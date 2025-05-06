//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "enclave.h"
#include "mprv.h"
#include "pmp.h"
#include "page.h"
#include "cpu.h"
#include "platform-hook.h"
#include "crypt.h"
#include <sbi/sbi_string.h>
#include <sbi/riscv_asm.h>
#include <sbi/riscv_locks.h>
#include <sbi/sbi_console.h>

#define ENCL_MAX  16
#define CACHE_MAX 4

int empty_cache_blocks = ENCLAVE_CACHE_SIZE/CACHE_BLOCK_SIZE;

struct enclave enclaves[ENCL_MAX];
struct enclave_cache cache[CACHE_MAX];
byte cache_valid[ENCLAVE_CACHE_SIZE/(CACHE_BLOCK_SIZE*8)];
int next_cache[ENCLAVE_CACHE_SIZE/CACHE_BLOCK_SIZE];//次のブロックの最初のオフセット
int used_cache = 0;
#define ENCLAVE_EXISTS(eid) (eid >= 0 && eid < ENCL_MAX && enclaves[eid].state >= 0)

static spinlock_t encl_lock = SPIN_LOCK_INITIALIZER;

extern void save_host_regs(void);
extern void restore_host_regs(void);
extern byte dev_public_key[PUBLIC_KEY_SIZE];

void sbi_printh(unsigned char* data, unsigned int len) {
    for (int i=0; i<len; i++) {
        sbi_printf("%02x", data[i]);
    }
    sbi_printf("\n");
}

uintptr_t base_cache_block(int num){
  return ENCLAVE_CACHE_BASE + num * CACHE_BLOCK_SIZE;
}

int set_cache(struct runtime_pa_params params, struct enclave_cache* cache){
  //enclaveをブロックごとにcache上にコピーする
  uintptr_t source = params.dram_base;//sourceを1ブロックずつ増やす
  int i = 0;
  int count = 0;
  int previous = 0;
  while(source < params.dram_base + params.dram_size){//コピー
    if((cache_valid[i/8]&(0x1 << i%8))==0){//i番目のblockがvalidかどうかを調べ、validなら書き込む
      sbi_memcpy((void*) base_cache_block(i), (void*) source, CACHE_BLOCK_SIZE);
      if(source == params.dram_base){//1番目ならfirst_block
        cache->first_block = i;
      }else{
        next_cache[previous] = i;//そうでないならnext_cacheに今の番号を入れる
      }
      if(source == params.runtime_base){
        cache->rt_block = i;
      }
      if(source == params.user_base){
        cache->eapp_block = i;
      }
      if(source == params.free_base){
        cache->free_block = i;
      }
      source += CACHE_BLOCK_SIZE;
      empty_cache_blocks--;
      cache_valid[i/8] = cache_valid[i/8] | (0x1 << i%8);
      count += 1;
      previous = i;
    }
    i++;
  }
  next_cache[previous] = -1;
  used_cache += 1;
  cache->block_num = count;
  return 1;
}

int copy_cache(struct runtime_pa_params* params, struct enclave_cache cache){
  uintptr_t freemem = params->dram_base;
  int copy_block = cache.first_block;
  while(copy_block != -1){
    sbi_memcpy((void*) freemem, (void*) base_cache_block(copy_block), CACHE_BLOCK_SIZE);
    if(copy_block == cache.rt_block){
      params->runtime_base = freemem;
    }
    if(copy_block == cache.eapp_block){
      params->user_base = freemem;
    }
    if(copy_block == cache.free_block){
      params->free_base = freemem;
    }
    copy_block = next_cache[copy_block];
    freemem += CACHE_BLOCK_SIZE;
  }
  return 1;
}

int lowest_cache(void){//最も優先度の低いcacheを返す
  int i;
  int ret = -1;
  for(i = 0; i < CACHE_MAX; i++){
    if(cache[i].state == VALID && cache[i].priority == used_cache-1){
      ret = i;
      break;
    }
  }
  return ret;
}

/****************************
 *
 * Enclave utility functions
 * Internal use by SBI calls
 *
 ****************************/

/* Internal function containing the core of the context switching
 * code to the enclave.
 *
 * Used by resume_enclave and run_enclave.
 *
 * Expects that eid has already been valided, and it is OK to run this enclave
*/
static inline void context_switch_to_enclave(struct sbi_trap_regs* regs,
                                                enclave_id eid,
                                                int load_parameters){
  /* save host context */
  swap_prev_state(&enclaves[eid].threads[0], regs, 1);
  swap_prev_mepc(&enclaves[eid].threads[0], regs, regs->mepc);
  swap_prev_mstatus(&enclaves[eid].threads[0], regs, regs->mstatus);

  uintptr_t interrupts = 0;
  csr_write(mideleg, interrupts);

  if(load_parameters) {
    // passing parameters for a first run
    regs->mepc = (uintptr_t) enclaves[eid].pa_params.dram_base - 4; // regs->mepc will be +4 before sbi_ecall_handler return
    regs->mstatus = (1 << MSTATUS_MPP_SHIFT);
    // $a1: (PA) DRAM base,
    regs->a1 = (uintptr_t) enclaves[eid].pa_params.dram_base;
    // $a2: (PA) DRAM size,
    regs->a2 = (uintptr_t) enclaves[eid].pa_params.dram_size;
    // $a3: (PA) kernel location,
    regs->a3 = (uintptr_t) enclaves[eid].pa_params.runtime_base;
    // $a4: (PA) user location,
    regs->a4 = (uintptr_t) enclaves[eid].pa_params.user_base;
    // $a5: (PA) freemem location,
    regs->a5 = (uintptr_t) enclaves[eid].pa_params.free_base;
    // $a6: (PA) utm base,
    regs->a6 = (uintptr_t) enclaves[eid].params.untrusted_ptr;
    // $a7: (size_t) utm size
    regs->a7 = (uintptr_t) enclaves[eid].params.untrusted_size;

    // enclave will only have physical addresses in the first run
    csr_write(satp, 0);
  }

  switch_vector_enclave();

  // set PMP
  osm_pmp_set(PMP_NO_PERM);
  int memid;
  for(memid=0; memid < ENCLAVE_REGIONS_MAX; memid++) {
    if(enclaves[eid].regions[memid].type != REGION_INVALID) {
      pmp_set_keystone(enclaves[eid].regions[memid].pmp_rid, PMP_ALL_PERM);
    }
  }

  // Setup any platform specific defenses
  platform_switch_to_enclave(&(enclaves[eid]));
  cpu_enter_enclave_context(eid);
}

static inline void context_switch_to_host(struct sbi_trap_regs *regs,
    enclave_id eid,
    int return_on_resume){

  // set PMP
  int memid;
  for(memid=0; memid < ENCLAVE_REGIONS_MAX; memid++) {
    if(enclaves[eid].regions[memid].type != REGION_INVALID) {
      pmp_set_keystone(enclaves[eid].regions[memid].pmp_rid, PMP_NO_PERM);
    }
  }
  osm_pmp_set(PMP_ALL_PERM);

  uintptr_t interrupts = MIP_SSIP | MIP_STIP | MIP_SEIP;
  csr_write(mideleg, interrupts);

  /* restore host context */
  swap_prev_state(&enclaves[eid].threads[0], regs, return_on_resume);
  swap_prev_mepc(&enclaves[eid].threads[0], regs, regs->mepc);
  swap_prev_mstatus(&enclaves[eid].threads[0], regs, regs->mstatus);

  switch_vector_host();

  uintptr_t pending = csr_read(mip);

  if (pending & MIP_MTIP) {
    csr_clear(mip, MIP_MTIP);
    csr_set(mip, MIP_STIP);
  }
  if (pending & MIP_MSIP) {
    csr_clear(mip, MIP_MSIP);
    csr_set(mip, MIP_SSIP);
  }
  if (pending & MIP_MEIP) {
    csr_clear(mip, MIP_MEIP);
    csr_set(mip, MIP_SEIP);
  }

  // Reconfigure platform specific defenses
  platform_switch_from_enclave(&(enclaves[eid]));

  cpu_exit_enclave_context();

  return;
}


// TODO: This function is externally used.
// refactoring needed
/*
 * Init all metadata as needed for keeping track of enclaves
 * Called once by the SM on startup
 */
void enclave_init_metadata(){
  enclave_id eid;
  int i=0;

  /* Assumes eids are incrementing values, which they are for now */
  for(eid=0; eid < ENCL_MAX; eid++){
    enclaves[eid].state = INVALID;

    // Clear out regions
    for(i=0; i < ENCLAVE_REGIONS_MAX; i++){
      enclaves[eid].regions[i].type = REGION_INVALID;
    }
    /* Fire all platform specific init for each enclave */
    platform_init_enclave(&(enclaves[eid]));
  }

  for(i = 0; i < CACHE_MAX; i++){
    cache[i].state = INVALID;
  }

}

static unsigned long clean_enclave_memory(uintptr_t utbase, uintptr_t utsize)
{

  // This function is quite temporary. See issue #38

  // Zero out the untrusted memory region, since it may be in
  // indeterminate state.
  sbi_memset((void*)utbase, 0, utsize);

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

static unsigned long encl_alloc_eid(enclave_id* _eid)
{
  enclave_id eid;

  spin_lock(&encl_lock);

  for(eid=0; eid<ENCL_MAX; eid++)
  {
    if(enclaves[eid].state == INVALID){
      break;
    }
  }
  if(eid != ENCL_MAX)
    enclaves[eid].state = ALLOCATED;

  spin_unlock(&encl_lock);

  if(eid != ENCL_MAX){
    *_eid = eid;
    return SBI_ERR_SM_ENCLAVE_SUCCESS;
  }
  else{
    return SBI_ERR_SM_ENCLAVE_NO_FREE_RESOURCE;
  }
}

static unsigned long encl_free_eid(enclave_id eid)
{
  spin_lock(&encl_lock);
  enclaves[eid].state = INVALID;
  spin_unlock(&encl_lock);
  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

int get_enclave_region_index(enclave_id eid, enum enclave_region_type type){
  size_t i;
  for(i = 0;i < ENCLAVE_REGIONS_MAX; i++){
    if(enclaves[eid].regions[i].type == type){
      return i;
    }
  }
  // No such region for this enclave
  return -1;
}

uintptr_t get_enclave_region_size(enclave_id eid, int memid)
{
  if (0 <= memid && memid < ENCLAVE_REGIONS_MAX)
    return pmp_region_get_size(enclaves[eid].regions[memid].pmp_rid);

  return 0;
}

uintptr_t get_enclave_region_base(enclave_id eid, int memid)
{
  if (0 <= memid && memid < ENCLAVE_REGIONS_MAX)
    return pmp_region_get_addr(enclaves[eid].regions[memid].pmp_rid);

  return 0;
}

// TODO: This function is externally used by sm-sbi.c.
// Change it to be internal (remove from the enclave.h and make static)
/* Internal function enforcing a copy source is from the untrusted world.
 * Does NOT do verification of dest, assumes caller knows what that is.
 * Dest should be inside the SM memory.
 */
unsigned long copy_enclave_create_args(uintptr_t src, struct keystone_sbi_create* dest){

  int region_overlap = copy_to_sm(dest, src, sizeof(struct keystone_sbi_create));

  if (region_overlap)
    return SBI_ERR_SM_ENCLAVE_REGION_OVERLAPS;
  else
    return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

/* copies data from enclave, source must be inside EPM */
static unsigned long copy_enclave_data(struct enclave* enclave,
                                          void* dest, uintptr_t source, size_t size) {

  int illegal = copy_to_sm(dest, source, size);

  if(illegal)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  else
    return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

/* copies data into enclave, destination must be inside EPM */
static unsigned long copy_enclave_report(struct enclave* enclave,
                                            uintptr_t dest, struct report* source) {

  int illegal = copy_from_sm(dest, source, sizeof(struct report));

  if(illegal)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  else
    return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

static int is_create_args_valid(struct keystone_sbi_create* args)
{
  uintptr_t epm_start, epm_end;

  /* printm("[create args info]: \r\n\tepm_addr: %llx\r\n\tepmsize: %llx\r\n\tutm_addr: %llx\r\n\tutmsize: %llx\r\n\truntime_addr: %llx\r\n\tuser_addr: %llx\r\n\tfree_addr: %llx\r\n", */
  /*        args->epm_region.paddr, */
  /*        args->epm_region.size, */
  /*        args->utm_region.paddr, */
  /*        args->utm_region.size, */
  /*        args->runtime_paddr, */
  /*        args->user_paddr, */
  /*        args->free_paddr); */

  // check if physical addresses are valid
  if (args->epm_region.size <= 0)
    return 0;

  // check if overflow
  if (args->epm_region.paddr >=
      args->epm_region.paddr + args->epm_region.size)
    return 0;
  if (args->utm_region.paddr >=
      args->utm_region.paddr + args->utm_region.size)
    return 0;

  epm_start = args->epm_region.paddr;
  epm_end = args->epm_region.paddr + args->epm_region.size;

  // check if physical addresses are in the range
  if (args->runtime_paddr < epm_start ||
      args->runtime_paddr >= epm_end)
    return 0;
  if (args->user_paddr < epm_start ||
      args->user_paddr >= epm_end)
    return 0;
  if (args->free_paddr < epm_start ||
      args->free_paddr > epm_end)
      // note: free_paddr == epm_end if there's no free memory
    return 0;

  // check the order of physical addresses
  if (args->runtime_paddr > args->user_paddr)
    return 0;
  if (args->user_paddr > args->free_paddr)
    return 0;

  return 1;
}

/*********************************
 *
 * Enclave SBI functions
 * These are exposed to S-mode via the sm-sbi interface
 *
 *********************************/


/* This handles creation of a new enclave, based on arguments provided
 * by the untrusted host.
 *
 * This may fail if: it cannot allocate PMP regions, EIDs, etc
 */
unsigned long create_enclave(unsigned long *eidptr, struct keystone_sbi_create create_args)
{
  /* EPM and UTM parameters */
  uintptr_t base = create_args.epm_region.paddr;
  size_t size = create_args.epm_region.size;
  uintptr_t utbase = create_args.utm_region.paddr;
  size_t utsize = create_args.utm_region.size;

  enclave_id eid;
  unsigned long ret;
  int region, shared_region;

  /* Runtime parameters */
  if(!is_create_args_valid(&create_args))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  /* set va params */
  struct runtime_va_params_t params = create_args.params;
  struct runtime_pa_params pa_params;
  pa_params.dram_base = base;
  pa_params.dram_size = size;
  pa_params.runtime_base = create_args.runtime_paddr;
  pa_params.user_base = create_args.user_paddr;
  pa_params.free_base = create_args.free_paddr;

  // allocate eid
  ret = SBI_ERR_SM_ENCLAVE_NO_FREE_RESOURCE;
  if (encl_alloc_eid(&eid) != SBI_ERR_SM_ENCLAVE_SUCCESS)
    goto error;

  // create a PMP region bound to the enclave
  ret = SBI_ERR_SM_ENCLAVE_PMP_FAILURE;
  if(pmp_region_init_atomic(base, size, PMP_PRI_ANY, &region, 0))
    goto free_encl_idx;

  // create PMP region for shared memory
  if(pmp_region_init_atomic(utbase, utsize, PMP_PRI_BOTTOM, &shared_region, 0))
    goto free_region;

  // set pmp registers for private region (not shared)
  if(pmp_set_global(region, PMP_NO_PERM))
    goto free_shared_region;

  // cleanup some memory regions for sanity See issue #38
  clean_enclave_memory(utbase, utsize);


  // initialize enclave metadata
  enclaves[eid].eid = eid;

  enclaves[eid].regions[0].pmp_rid = region;
  enclaves[eid].regions[0].type = REGION_EPM;
  enclaves[eid].regions[1].pmp_rid = shared_region;
  enclaves[eid].regions[1].type = REGION_UTM;
#if __riscv_xlen == 32
  enclaves[eid].encl_satp = ((base >> RISCV_PGSHIFT) | (SATP_MODE_SV32 << HGATP_MODE_SHIFT));
#else
  enclaves[eid].encl_satp = ((base >> RISCV_PGSHIFT) | (SATP_MODE_SV39 << HGATP_MODE_SHIFT));
#endif
  enclaves[eid].n_thread = 0;
  enclaves[eid].params = params;
  enclaves[eid].pa_params = pa_params;

  /* Init enclave state (regs etc) */
  clean_state(&enclaves[eid].threads[0]);

  /* Platform create happens as the last thing before hashing/etc since
     it may modify the enclave struct */
  ret = platform_create_enclave(&enclaves[eid]);
  if (ret)
    goto unset_region;

  /* Validate memory, prepare hash and signature for attestation */
  spin_lock(&encl_lock); // FIXME This should error for second enter.
 
  ret = validate_and_hash_enclave(&enclaves[eid]);
  /* The enclave is fresh if it has been validated and hashed but not run yet. */
  if (ret)
    goto unlock;

  enclaves[eid].state = FRESH;
  /* EIDs are unsigned int in size, copy via simple copy */
  *eidptr = eid;

  spin_unlock(&encl_lock);
  return SBI_ERR_SM_ENCLAVE_SUCCESS;

unlock:
  spin_unlock(&encl_lock);
// free_platform:
  platform_destroy_enclave(&enclaves[eid]);
unset_region:
  pmp_unset_global(region);
free_shared_region:
  pmp_region_free_atomic(shared_region);
free_region:
  pmp_region_free_atomic(region);
free_encl_idx:
  encl_free_eid(eid);
error:
  return ret;
}

unsigned long create_cache(unsigned long *eidptr, struct keystone_sbi_create create_args){

  //実際に実行されるenclaveを作成
  /* EPM and UTM parameters */
  uintptr_t base = create_args.epm_region.paddr;
  size_t size = create_args.epm_region.size;
  uintptr_t utbase = create_args.utm_region.paddr;
  size_t utsize = create_args.utm_region.size;

  enclave_id eid;
  unsigned long ret;
  int region, shared_region;

  /* Runtime parameters */
  if(!is_create_args_valid(&create_args))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  /* set va params */
  struct runtime_va_params_t params = create_args.params;
  struct runtime_pa_params pa_params;
  pa_params.dram_base = base;
  pa_params.dram_size = size;
  pa_params.runtime_base = create_args.runtime_paddr;
  pa_params.user_base = create_args.user_paddr;
  pa_params.free_base = create_args.free_paddr;

  sbi_printf("size = %ld", (pa_params.free_base - pa_params.dram_base));
  sbi_printf("base ,size = %ld, %ld\n", base, size);

  // allocate eid
  ret = SBI_ERR_SM_ENCLAVE_NO_FREE_RESOURCE;
  if (encl_alloc_eid(&eid) != SBI_ERR_SM_ENCLAVE_SUCCESS)
    goto error;

  // create a PMP region bound to the enclave
  ret = SBI_ERR_SM_ENCLAVE_PMP_FAILURE;
  if(pmp_region_init_atomic(base, size, PMP_PRI_ANY, &region, 0))
    goto free_encl_idx;

  // create PMP region for shared memory
  if(pmp_region_init_atomic(utbase, utsize, PMP_PRI_BOTTOM, &shared_region, 0))
    goto free_region;

  // set pmp registers for private region (not shared)
  if(pmp_set_global(region, PMP_NO_PERM))
    goto free_shared_region;

  // cleanup some memory regions for sanity See issue #38
  clean_enclave_memory(utbase, utsize);


  // initialize enclave metadata
  enclaves[eid].eid = eid;

  enclaves[eid].regions[0].pmp_rid = region;
  enclaves[eid].regions[0].type = REGION_EPM;
  enclaves[eid].regions[1].pmp_rid = shared_region;
  enclaves[eid].regions[1].type = REGION_UTM;
#if __riscv_xlen == 32
  enclaves[eid].encl_satp = ((base >> RISCV_PGSHIFT) | (SATP_MODE_SV32 << HGATP_MODE_SHIFT));
#else
  enclaves[eid].encl_satp = ((base >> RISCV_PGSHIFT) | (SATP_MODE_SV39 << HGATP_MODE_SHIFT));
#endif
  enclaves[eid].n_thread = 0;
  enclaves[eid].params = params;
  enclaves[eid].pa_params = pa_params;

  /* Init enclave state (regs etc) */
  clean_state(&enclaves[eid].threads[0]);

  /* Platform create happens as the last thing before hashing/etc since
     it may modify the enclave struct */
  ret = platform_create_enclave(&enclaves[eid]);
  if (ret)
    goto unset_region;

  /* Validate memory, prepare hash and signature for attestation */
  spin_lock(&encl_lock); // FIXME This should error for second enter.
 
  ret = validate_and_hash_enclave(&enclaves[eid]);
  /* The enclave is fresh if it has been validated and hashed but not run yet. */
  if (ret)
    goto unlock;

  enclaves[eid].state = FRESH;
  /* EIDs are unsigned int in size, copy via simple copy */
  *eidptr = eid;

  spin_unlock(&encl_lock);//ここまで

  if(size > ENCLAVE_CACHE_SIZE){//enclaveがcacheに収まり切らないならそのまま返す
    return SBI_ERR_SM_ENCLAVE_SUCCESS;
  }

  //certificate provider's public key
  /*if(!sm_verify(create_args.certificate, create_args.pub_key, 32, public_key)){
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT; //TODO make process when certification fail
  }*/
  int i;
  int cache_num = 0;

  int num;
  //容量が十分になるまでキャッシュを破棄
  while(empty_cache_blocks * CACHE_BLOCK_SIZE < size){
    num = lowest_cache();//priorityの最も低いcacheを検索
    destroy_cache(num);
  }

  for (i = 0; i < CACHE_MAX; i++) {  //どこを使うかを決定
    if (cache[i].state == INVALID || cache[i].priority == (CACHE_MAX - 1)) {
      cache_num = i;
      break;
    }
  }

  if(cache[cache_num].state==VALID){
    destroy_cache(cache_num);
  }

  for (i = 0; i < SIGN_SIZE; i++) {
    cache[cache_num].signature[i] = create_args.sign[i];
  }

  for(i = 0; i < ED_KEY_LENGTH; i++){
    cache[cache_num].pub_key[i] = create_args.pub_key[i];
  }

  for(i = 0; i < MDSIZE; i++){
    cache[cache_num].hash[i] = enclaves[eid].hash[i];
  }

  //他のキャッシュの優先度を下げる
  for (i = 0; i < CACHE_MAX; i++) {
    if (cache[i].state == VALID) {
      cache[i].priority += 1;
    }
  }

  // キャッシュを有効化
  cache[cache_num].state = VALID;
  cache[cache_num].priority = 0;

  //copy cache
  set_cache(pa_params, &cache[cache_num]);

  cache[cache_num].params = params;

  return SBI_ERR_SM_ENCLAVE_SUCCESS;

unlock:
  spin_unlock(&encl_lock);
// free_platform:
  platform_destroy_enclave(&enclaves[eid]);
unset_region:
  pmp_unset_global(region);
free_shared_region:
  pmp_region_free_atomic(shared_region);
free_region:
  pmp_region_free_atomic(region);
free_encl_idx:
  encl_free_eid(eid);
error:
  return ret;
}

unsigned long copy_cached_enclave(unsigned long* eidptr,
                                  struct keystone_sbi_create create_args){
  enclave_id eid = 0;
  unsigned long ret;
  int region, shared_region;

  int i;
  int cache_num = -1;

  for(int i = 0; i < CACHE_MAX; i++){
    if(check_enclave_cache(create_args.sign, create_args.pub_key, i)){
      cache_num = i;
    }
  }

  sbi_printf("base ,size = %ld, %ld\n", create_args.epm_region.paddr, create_args.epm_region.size);

  if(cache_num == -1){//ミス
    *eidptr = 100;//とりあえず取り得ない数値を返す
    return SBI_ERR_SM_ENCLAVE_SUCCESS;
  }


  //ヒットした場合
  /* EPM and UTM parameters */
  uintptr_t base = create_args.epm_region.paddr;
  size_t size = create_args.epm_region.size;
  uintptr_t utbase = create_args.utm_region.paddr;
  size_t utsize = create_args.utm_region.size;

  /* set va params */
  /*struct runtime_va_params_t params = create_args.params;
  params.runtime_entry = cache[cache_num].params.runtime_entry;
  params.user_entry = cache[cache_num].params.user_entry;*/

  struct runtime_pa_params pa_params;
  pa_params.dram_base = base;
  pa_params.dram_size = size;
  //データコピーの前にPMPエントリでメモリを保護
  // create a PMP region bound to the enclave
  ret = SBI_ERR_SM_ENCLAVE_PMP_FAILURE;
  if (pmp_region_init_atomic(base, size, PMP_PRI_ANY, &region, 0))
    goto free_encl_idx;

  // create PMP region for shared memory
  if (pmp_region_init_atomic(utbase, utsize, PMP_PRI_BOTTOM, &shared_region, 0))
    goto free_region;

  // set pmp registers for private region (not shared)
  if (pmp_set_global(region, PMP_NO_PERM)) goto free_shared_region;

  //バイナリのコピー
  copy_cache(&pa_params, cache[cache_num]);

  // allocate eid
  ret = SBI_ERR_SM_ENCLAVE_NO_FREE_RESOURCE;
  if (encl_alloc_eid(&eid) != SBI_ERR_SM_ENCLAVE_SUCCESS)
    goto error;

  // cleanup some memory regions for sanity See issue #38
  clean_enclave_memory(utbase, utsize);
  // initialize enclave metadata
  enclaves[eid].eid = eid;

  enclaves[eid].regions[0].pmp_rid = region;
  enclaves[eid].regions[0].type = REGION_EPM;
  enclaves[eid].regions[1].pmp_rid = shared_region;
  enclaves[eid].regions[1].type = REGION_UTM;
#if __riscv_xlen == 32
  enclaves[eid].encl_satp = ((base >> RISCV_PGSHIFT) | (SATP_MODE_SV32 << HGATP_MODE_SHIFT));
#else
  enclaves[eid].encl_satp = ((base >> RISCV_PGSHIFT) | (SATP_MODE_SV39 << HGATP_MODE_SHIFT));
#endif
  enclaves[eid].n_thread = 0;
  enclaves[eid].params = cache[cache_num].params;
  enclaves[eid].pa_params = pa_params;
  for(i = 0; i < MDSIZE; i++){
    enclaves[eid].hash[i]  = cache[cache_num].hash[i];
  }

  /* Init enclave state (regs etc) */
  clean_state(&enclaves[eid].threads[0]);

  /* Platform create happens as the last thing before hashing/etc since
     it may modify the enclave struct */
  ret = platform_create_enclave(&enclaves[eid]);
  if (ret)
    goto unset_region;

  //優先度制御
  for (i = 0; i < CACHE_MAX; i++) {
    if (cache[i].state == VALID &&
        cache[i].priority < cache[cache_num].priority) {
      cache[i].priority += 1;
    }
  }
  cache[cache_num].priority = 0;

  //終了
  enclaves[eid].state = FRESH;

  *eidptr = eid;
  return SBI_ERR_SM_ENCLAVE_SUCCESS;

//free_platform:
  platform_destroy_enclave(&enclaves[eid]);
unset_region:
  pmp_unset_global(region);
free_shared_region:
  pmp_region_free_atomic(shared_region);
free_region:
  pmp_region_free_atomic(region);
free_encl_idx:
  encl_free_eid(eid);
error:
  return ret;
}

int check_enclave_cache(byte *signature, byte *pub_key, int num){
  int i = 0;
  for (i = 0; i < SIGN_SIZE; i++) {  //検索
    if (signature[i] != cache[num].signature[i]) {
      return 0;
    }
  }
  for(i = 0; i < ED_KEY_LENGTH; i++){
    if (pub_key[i] != cache[num].pub_key[i]) {
      return 0;
    }
  }
  return 1;
}

/*
 * Fully destroys an enclave
 * Deallocates EID, clears epm, etc
 * Fails only if the enclave isn't running.
 */
unsigned long destroy_enclave(enclave_id eid)
{
  int destroyable;

  spin_lock(&encl_lock);
  destroyable = (ENCLAVE_EXISTS(eid)
                 && enclaves[eid].state <= STOPPED);
  /* update the enclave state first so that
   * no SM can run the enclave any longer */
  if(destroyable)
    enclaves[eid].state = DESTROYING;
  spin_unlock(&encl_lock);

  if(!destroyable)
    return SBI_ERR_SM_ENCLAVE_NOT_DESTROYABLE;


  // 0. Let the platform specifics do cleanup/modifications
  platform_destroy_enclave(&enclaves[eid]);


  // 1. clear all the data in the enclave pages
  // requires no lock (single runner)
  int i;
  void* base;
  size_t size;
  region_id rid;
  for(i = 0; i < ENCLAVE_REGIONS_MAX; i++){
    if(enclaves[eid].regions[i].type == REGION_INVALID ||
       enclaves[eid].regions[i].type == REGION_UTM)
      continue;
    //1.a Clear all pages
    rid = enclaves[eid].regions[i].pmp_rid;
    base = (void*) pmp_region_get_addr(rid);
    size = (size_t) pmp_region_get_size(rid);
    sbi_memset((void*) base, 0, size);

    //1.b free pmp region
    pmp_unset_global(rid);
    pmp_region_free_atomic(rid);
  }

  // 2. free pmp region for UTM
  rid = get_enclave_region_index(eid, REGION_UTM);
  if(rid != -1)
    pmp_region_free_atomic(enclaves[eid].regions[rid].pmp_rid);

  enclaves[eid].encl_satp = 0;
  enclaves[eid].n_thread = 0;
  enclaves[eid].params = (struct runtime_va_params_t) {0};
  enclaves[eid].pa_params = (struct runtime_pa_params) {0};
  for(i=0; i < ENCLAVE_REGIONS_MAX; i++){
    enclaves[eid].regions[i].type = REGION_INVALID;
  }

  // 3. release eid
  encl_free_eid(eid);

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long destroy_cache(int num){
  short int block = cache[num].first_block;
  int next;
  uintptr_t base;
  int i = 0;
  while(1){
    base = base_cache_block(block);
    sbi_memset((void*) base, 0, CACHE_BLOCK_SIZE);
    cache_valid[block/8] = cache_valid[block/8] & ~(0x1 << block%8);
    next = next_cache[block];
    next_cache[block] = 0;
    if(next < 0){
      break;
    }
    block = next;
  }

  empty_cache_blocks += cache[num].block_num;
  cache[num].state = INVALID;
  used_cache -= 1;

  cache[num].params = (struct runtime_va_params_t) {0};
  cache[num].rt_block = 0;
  cache[num].eapp_block = 0;
  cache[num].block_num = 0;
  cache[num].first_block = 0;
  for(i = 0; i < SIGN_SIZE;i++){
    cache[num].signature[i] = 0;
  }
  for(i = 0; i < ED_KEY_LENGTH; i++){
    cache[num].pub_key[i] = 0;
  }

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long reset_cache(){
  sbi_memset((void*) ENCLAVE_CACHE_BASE, 0, ENCLAVE_CACHE_SIZE);
  int i = 0;
  int j = 0;
  for(i = 0; i < ENCLAVE_CACHE_SIZE/(CACHE_BLOCK_SIZE*8); i++){
    cache_valid[i] = 0;
  }
  empty_cache_blocks = ENCLAVE_CACHE_SIZE/CACHE_BLOCK_SIZE;
  used_cache = 0;

  for(i = 0; i < CACHE_MAX; i++){
    cache[i].params = (struct runtime_va_params_t) {0};
    cache[i].rt_block = 0;
    cache[i].eapp_block = 0;
    cache[i].block_num = 0;
    cache[i].first_block = 0;
    for(j = 0; j < SIGN_SIZE;j++){
      cache[i].signature[j] = 0;
    }
    for(j = 0; j < ED_KEY_LENGTH; j++){
      cache[i].pub_key[j] = 0;
    }
    cache[i].priority = 0;
  }
  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long run_enclave(struct sbi_trap_regs *regs, enclave_id eid)
{
  int runable;

  spin_lock(&encl_lock);
  runable = (ENCLAVE_EXISTS(eid)
            && enclaves[eid].state == FRESH);
  if(runable) {
    enclaves[eid].state = RUNNING;
    enclaves[eid].n_thread++;
  }
  spin_unlock(&encl_lock);

  if(!runable) {
    return SBI_ERR_SM_ENCLAVE_NOT_FRESH;
  }

  // Enclave is OK to run, context switch to it
  context_switch_to_enclave(regs, eid, 1);

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long exit_enclave(struct sbi_trap_regs *regs, enclave_id eid)
{
  int exitable;

  spin_lock(&encl_lock);
  exitable = enclaves[eid].state == RUNNING;
  if (exitable) {
    enclaves[eid].n_thread--;
    if(enclaves[eid].n_thread == 0)
      enclaves[eid].state = STOPPED;
  }
  spin_unlock(&encl_lock);

  if(!exitable)
    return SBI_ERR_SM_ENCLAVE_NOT_RUNNING;

  context_switch_to_host(regs, eid, 0);

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long stop_enclave(struct sbi_trap_regs *regs, uint64_t request, enclave_id eid)
{
  int stoppable;

  spin_lock(&encl_lock);
  stoppable = enclaves[eid].state == RUNNING;
  if (stoppable) {
    enclaves[eid].n_thread--;
    if(enclaves[eid].n_thread == 0)
      enclaves[eid].state = STOPPED;
  }
  spin_unlock(&encl_lock);

  if(!stoppable)
    return SBI_ERR_SM_ENCLAVE_NOT_RUNNING;

  context_switch_to_host(regs, eid, request == STOP_EDGE_CALL_HOST);

  switch(request) {
    case(STOP_TIMER_INTERRUPT):
      return SBI_ERR_SM_ENCLAVE_INTERRUPTED;
    case(STOP_EDGE_CALL_HOST):
      return SBI_ERR_SM_ENCLAVE_EDGE_CALL_HOST;
    default:
      return SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR;
  }
}

unsigned long resume_enclave(struct sbi_trap_regs *regs, enclave_id eid)
{
  int resumable;

  spin_lock(&encl_lock);
  resumable = (ENCLAVE_EXISTS(eid)
               && (enclaves[eid].state == RUNNING || enclaves[eid].state == STOPPED)
               && enclaves[eid].n_thread < MAX_ENCL_THREADS);

  if(!resumable) {
    spin_unlock(&encl_lock);
    return SBI_ERR_SM_ENCLAVE_NOT_RESUMABLE;
  } else {
    enclaves[eid].n_thread++;
    enclaves[eid].state = RUNNING;
  }
  spin_unlock(&encl_lock);

  // Enclave is OK to resume, context switch to it
  context_switch_to_enclave(regs, eid, 0);

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long attest_enclave(uintptr_t report_ptr, uintptr_t data, uintptr_t size, enclave_id eid)
{
  int attestable;
  struct report report;
  int ret;

  if (size > ATTEST_DATA_MAXLEN)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  spin_lock(&encl_lock);
  attestable = (ENCLAVE_EXISTS(eid)
                && (enclaves[eid].state >= FRESH));

  if(!attestable) {
    ret = SBI_ERR_SM_ENCLAVE_NOT_INITIALIZED;
    goto err_unlock;
  }

  /* copy data to be signed */
  ret = copy_enclave_data(&enclaves[eid], report.enclave.data,
      data, size);
  report.enclave.data_len = size;

  if (ret) {
    ret = SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;
    goto err_unlock;
  }

  spin_unlock(&encl_lock); // Don't need to wait while signing, which might take some time

  sbi_memcpy(report.dev_public_key, dev_public_key, PUBLIC_KEY_SIZE);
  sbi_memcpy(report.sm.hash, sm_hash, MDSIZE);
  sbi_memcpy(report.sm.public_key, sm_public_key, PUBLIC_KEY_SIZE);
  sbi_memcpy(report.sm.signature, sm_signature, SIGNATURE_SIZE);
  sbi_memcpy(report.enclave.hash, enclaves[eid].hash, MDSIZE);
  sm_sign(report.enclave.signature,
      &report.enclave,
      sizeof(struct enclave_report)
      - SIGNATURE_SIZE
      - ATTEST_DATA_MAXLEN + size);

  spin_lock(&encl_lock);

  /* copy report to the enclave */
  ret = copy_enclave_report(&enclaves[eid],
      report_ptr,
      &report);

  if (ret) {
    ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
    goto err_unlock;
  }

  ret = SBI_ERR_SM_ENCLAVE_SUCCESS;

err_unlock:
  spin_unlock(&encl_lock);
  return ret;
}

unsigned long get_sealing_key(uintptr_t sealing_key, uintptr_t key_ident,
                                 size_t key_ident_size, enclave_id eid)
{
  struct sealing_key *key_struct = (struct sealing_key *)sealing_key;
  int ret;

  /* derive key */
  ret = sm_derive_sealing_key((unsigned char *)key_struct->key,
                              (const unsigned char *)key_ident, key_ident_size,
                              (const unsigned char *)enclaves[eid].hash);
  if (ret)
    return SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR;

  /* sign derived key */
  sm_sign((void *)key_struct->signature, (void *)key_struct->key,
          SEALING_KEY_SIZE);

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}
