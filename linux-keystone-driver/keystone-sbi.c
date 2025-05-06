#include "keystone-sbi.h"

struct sbiret sbi_sm_create_enclave(struct keystone_sbi_create_t* args) {
  return sbi_ecall(KEYSTONE_SBI_EXT_ID,
      SBI_SM_CREATE_ENCLAVE,
      (unsigned long) args, 0, 0, 0, 0, 0);
}

struct sbiret sbi_sm_create_cache(struct keystone_sbi_create_t* args){
  return sbi_ecall(KEYSTONE_SBI_EXT_ID,
      SBI_SM_CREATE_CACHE,
      (unsigned long) args, 0, 0, 0, 0, 0);
}

struct sbiret sbi_sm_run_enclave(unsigned long eid) {
  return sbi_ecall(KEYSTONE_SBI_EXT_ID,
      SBI_SM_RUN_ENCLAVE,
      eid, 0, 0, 0, 0, 0);
}

struct sbiret sbi_sm_destroy_enclave(unsigned long eid) {
  return sbi_ecall(KEYSTONE_SBI_EXT_ID,
      SBI_SM_DESTROY_ENCLAVE,
      eid, 0, 0, 0, 0, 0);
}

struct sbiret sbi_sm_reset_cache(){
  return sbi_ecall(KEYSTONE_SBI_EXT_ID,
      SBI_SM_RESET_CACHE,
      0, 0, 0, 0, 0, 0);
}

struct sbiret sbi_sm_resume_enclave(unsigned long eid) {
  return sbi_ecall(KEYSTONE_SBI_EXT_ID,
      SBI_SM_RESUME_ENCLAVE,
      eid, 0, 0, 0, 0, 0);
}

struct sbiret sbi_sm_copy_cached_enclave(struct keystone_sbi_create_t* args) {
  return sbi_ecall(KEYSTONE_SBI_EXT_ID,
      SBI_SM_COPY_CACHED_ENCLAVE,
      (unsigned long) args, 0, 0, 0, 0, 0);
}