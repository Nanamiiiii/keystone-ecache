//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#ifndef sm_h
#define sm_h

#include <sbi/sbi_types.h>
#include "pmp.h"
#include "sm-sbi.h"
#include <sbi/riscv_encoding.h>
#include <sbi/sbi_console.h>

#define SMM_BASE  0x80000000
#define SMM_SIZE  0x200000
#define ENCLAVE_CACHE_BASE 0xf0000000
#define ENCLAVE_CACHE_SIZE 0x08000000
#define CACHE_BLOCK_SIZE_SHIFT 12
#define CACHE_BLOCK_SIZE (0x1 << CACHE_BLOCK_SIZE_SHIFT)

/* 0-1999 are not used (deprecated) */
#define FID_RANGE_DEPRECATED      1999
/* 2000-2999 are called by host */
#define SBI_SM_CREATE_ENCLAVE     2001
#define SBI_SM_DESTROY_ENCLAVE    2002
#define SBI_SM_RUN_ENCLAVE        2003
#define SBI_SM_RESUME_ENCLAVE     2005
#define SBI_SM_COPY_CACHED_ENCLAVE 2006
#define SBI_SM_CREATE_CACHE 2007
#define SBI_SM_RESET_CACHE 2008
#define FID_RANGE_HOST            2999
/* 3000-3999 are called by enclave */
#define SBI_SM_RANDOM             3001
#define SBI_SM_ATTEST_ENCLAVE     3002
#define SBI_SM_GET_SEALING_KEY    3003
#define SBI_SM_STOP_ENCLAVE       3004
#define SBI_SM_EXIT_ENCLAVE       3006
#define FID_RANGE_ENCLAVE         3999
/* 4000-4999 are experimental */
#define SBI_SM_CALL_PLUGIN        4000
#define FID_RANGE_CUSTOM          4999

/* error codes */
#define SBI_ERR_SM_ENCLAVE_SUCCESS                     0
#define SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR               100000
#define SBI_ERR_SM_ENCLAVE_INVALID_ID                  100001
#define SBI_ERR_SM_ENCLAVE_INTERRUPTED                 100002
#define SBI_ERR_SM_ENCLAVE_PMP_FAILURE                 100003
#define SBI_ERR_SM_ENCLAVE_NOT_RUNNABLE                100004
#define SBI_ERR_SM_ENCLAVE_NOT_DESTROYABLE             100005
#define SBI_ERR_SM_ENCLAVE_REGION_OVERLAPS             100006
#define SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE              100007
#define SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT            100008
#define SBI_ERR_SM_ENCLAVE_NOT_RUNNING                 100009
#define SBI_ERR_SM_ENCLAVE_NOT_RESUMABLE               100010
#define SBI_ERR_SM_ENCLAVE_EDGE_CALL_HOST              100011
#define SBI_ERR_SM_ENCLAVE_NOT_INITIALIZED             100012
#define SBI_ERR_SM_ENCLAVE_NO_FREE_RESOURCE            100013
#define SBI_ERR_SM_ENCLAVE_SBI_PROHIBITED              100014
#define SBI_ERR_SM_ENCLAVE_ILLEGAL_PTE                 100015
#define SBI_ERR_SM_ENCLAVE_NOT_FRESH                   100016
#define SBI_ERR_SM_DEPRECATED                          100099
#define SBI_ERR_SM_NOT_IMPLEMENTED                     100100

#define SBI_ERR_SM_PMP_SUCCESS                         0
#define SBI_ERR_SM_PMP_REGION_SIZE_INVALID             100020
#define SBI_ERR_SM_PMP_REGION_NOT_PAGE_GRANULARITY     100021
#define SBI_ERR_SM_PMP_REGION_NOT_ALIGNED              100022
#define SBI_ERR_SM_PMP_REGION_MAX_REACHED              100023
#define SBI_ERR_SM_PMP_REGION_INVALID                  100024
#define SBI_ERR_SM_PMP_REGION_OVERLAP                  100025
#define SBI_ERR_SM_PMP_REGION_IMPOSSIBLE_TOR           100026

//for Enclave cache
#define SIGN_SIZE 64
#define CERT_SIZE 64
#define ED_KEY_LENGTH 32

typedef unsigned char byte;

void sm_init(bool cold_boot);

/* platform specific functions */
#define ATTESTATION_KEY_LENGTH  64
void sm_retrieve_pubkey(void* dest);
void sm_sign(void* sign, const void* data, size_t len);
int sm_derive_sealing_key(unsigned char *key,
                          const unsigned char *key_ident,
                          size_t key_ident_size,
                          const unsigned char *enclave_hash);
int sm_verify(void* certificate, void* message, size_t len, const unsigned char* public_key);

/* creation parameters */
struct keystone_sbi_pregion
{
  uintptr_t paddr;
  size_t size;
};
struct runtime_va_params_t
{
  uintptr_t runtime_entry;
  uintptr_t user_entry;
  uintptr_t untrusted_ptr;
  uintptr_t untrusted_size;
};

struct runtime_pa_params
{
  uintptr_t dram_base;
  uintptr_t dram_size;
  uintptr_t runtime_base;
  uintptr_t user_base;
  uintptr_t free_base;
};

struct keystone_sbi_create
{
  struct keystone_sbi_pregion epm_region;
  struct keystone_sbi_pregion utm_region;

  uintptr_t runtime_paddr;
  uintptr_t user_paddr;
  uintptr_t free_paddr;

  struct runtime_va_params_t params;

  //for cache
  byte sign[SIGN_SIZE];
  byte pub_key[ED_KEY_LENGTH];
  byte certificate[CERT_SIZE];
  
  unsigned int* eid_pptr; // TODO: remove?


};

int osm_pmp_set(uint8_t perm);

//public key for test
static const unsigned char public_key[] = {
  0x0f, 0xaa, 0xd4, 0xff, 0x01, 0x17, 0x85, 0x83, 0xba, 0xa5, 0x88, 0x96,
  0x6f, 0x7c, 0x1f, 0xf3, 0x25, 0x64, 0xdd, 0x17, 0xd7, 0xdc, 0x2b, 0x46,
  0xcb, 0x50, 0xa8, 0x4a, 0x69, 0x27, 0x0b, 0x4c
};

static const unsigned char certificate[] = {
  0x1d, 0xe1, 0x32, 0xb8, 0x03, 0x28, 0xd2, 0x0a,
  0xdc, 0x88, 0x56, 0x65, 0x25, 0xf5, 0x71, 0xe4,
  0x72, 0xf5, 0x4b, 0x11, 0x94, 0x80, 0x76, 0xee,
  0x51, 0x0c, 0x11, 0xb2, 0x3e, 0x1a, 0x64, 0xb6,
  0xd3, 0xc7, 0xb7, 0x00, 0x75, 0x0a, 0xf7, 0x67,
  0xfb, 0xe4, 0x6e, 0xc2, 0x87, 0x2e, 0x68, 0xe1,
  0xb5, 0xd1, 0x7c, 0x17, 0xad, 0x7e, 0x9f, 0x4c,
  0x5e, 0xe8, 0xd0, 0x08, 0x48, 0x36, 0xef, 0x08
};

static const unsigned char priv_key[] = {
  0x40, 0xa0, 0x99, 0x47, 0x8c, 0xce, 0xfa, 0x3a, 0x06, 0x63, 0xab, 0xc9,
  0x5e, 0x7a, 0x1e, 0xc9, 0x54, 0xb4, 0xf5, 0xf6, 0x45, 0xba, 0xd8, 0x04,
  0xdb, 0x13, 0xe7, 0xd7, 0x82, 0x6c, 0x70, 0x73, 0x57, 0x6a, 0x9a, 0xb6,
  0x21, 0x60, 0xd9, 0xd1, 0xc6, 0xae, 0xdc, 0x29, 0x85, 0x2f, 0xb9, 0x60,
  0xee, 0x51, 0x32, 0x83, 0x5a, 0x16, 0x89, 0xec, 0x06, 0xa8, 0x72, 0x34,
  0x51, 0xaa, 0x0e, 0x4a
};

#endif
