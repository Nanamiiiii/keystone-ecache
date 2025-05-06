//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#ifndef _KEYSTONE_USER_H_
#define _KEYSTONE_USER_H_

#include <linux/types.h>
#include <linux/ioctl.h>
// Linux generic TEE subsystem magic defined in <linux/tee.h>
#define KEYSTONE_IOC_MAGIC  0xa4

// ioctl definition
#define KEYSTONE_IOC_CREATE_ENCLAVE \
  _IOR(KEYSTONE_IOC_MAGIC, 0x00, struct keystone_ioctl_create_enclave)
#define KEYSTONE_IOC_DESTROY_ENCLAVE \
  _IOW(KEYSTONE_IOC_MAGIC, 0x01, struct keystone_ioctl_create_enclave)
#define KEYSTONE_IOC_RUN_ENCLAVE \
  _IOR(KEYSTONE_IOC_MAGIC, 0x04, struct keystone_ioctl_run_enclave)
#define KEYSTONE_IOC_RESUME_ENCLAVE \
  _IOR(KEYSTONE_IOC_MAGIC, 0x05, struct keystone_ioctl_run_enclave)
#define KEYSTONE_IOC_FINALIZE_ENCLAVE \
  _IOR(KEYSTONE_IOC_MAGIC, 0x06, struct keystone_ioctl_create_enclave)
#define KEYSTONE_IOC_UTM_INIT \
  _IOR(KEYSTONE_IOC_MAGIC, 0x07, struct keystone_ioctl_create_enclave)
#define KEYSTONE_IOC_COPY_CACHED_ENCLAVE \
  _IOR(KEYSTONE_IOC_MAGIC, 0x08, struct keystone_ioctl_create_enclave)
#define KEYSTONE_IOC_CREATE_CACHE \
  _IOR(KEYSTONE_IOC_MAGIC, 0x09, struct keystone_ioctl_create_enclave)
#define KEYSTONE_IOC_FINALIZE_CACHE \
  _IOR(KEYSTONE_IOC_MAGIC, 0x0a, struct keystone_ioctl_create_enclave)
#define KEYSTONE_IOC_RESET_CACHE \
  _IOR(KEYSTONE_IOC_MAGIC, 0x0b, int) 
#define KEYSTONE_FREE_EID \
  _IOR(KEYSTONE_IOC_MAGIC, 0x0c, struct keystone_ioctl_create_enclave)

#define RT_NOEXEC 0
#define USER_NOEXEC 1
#define RT_FULL 2
#define USER_FULL 3
#define UTM_FULL 4

//for cache
#define SIGN_SIZE 64
#define CERT_SIZE 64
#define ED_KEY_LENGTH 32

struct runtime_params_t {
  uintptr_t runtime_entry;
  uintptr_t user_entry;
  uintptr_t untrusted_ptr;
  uintptr_t  untrusted_size;
};

struct keystone_ioctl_create_enclave {
  uintptr_t eid;

  //Min pages required
  uintptr_t min_pages;

  // virtual addresses
  uintptr_t runtime_vaddr;
  uintptr_t user_vaddr;

  uintptr_t pt_ptr;
  uintptr_t utm_free_ptr;

  //Used for hash
  uintptr_t epm_paddr;
  uintptr_t utm_paddr;
  uintptr_t runtime_paddr;
  uintptr_t user_paddr;
  uintptr_t free_paddr;

  uintptr_t epm_size;
  uintptr_t utm_size;

  // Runtime Parameters
  struct runtime_params_t params;

  //cache
  unsigned char sign[SIGN_SIZE];
  unsigned char pub_key[ED_KEY_LENGTH];
  unsigned char certificate[CERT_SIZE];
};

struct keystone_ioctl_run_enclave {
  uintptr_t eid;
  uintptr_t error;
  uintptr_t value;
};

#endif
