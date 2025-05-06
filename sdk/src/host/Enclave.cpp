//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "Enclave.hpp"
#include <math.h>
#include <sys/mman.h>
#include <sys/stat.h>
extern "C" {
#include "./keystone_user.h"
#include "common/sha3.h"
}
#include "ElfFile.hpp"
#include "hash_util.hpp"
#include <iostream>
#include <stdio.h>
#include <unistd.h>
#include <linux/limits.h>
#include <fstream>
#include <string>

//get unsigned char array from hex array
void BytesFromHexString(unsigned char *data, const char *string) {
    int len = (int)strlen(string);
    for (int i=0; i<len; i+=2) {
        unsigned int x;
        sscanf((char *)(string + i), "%02x", &x);
        data[i/2] = x;
    }
}

namespace Keystone {

Enclave::Enclave() {
}

Enclave::~Enclave() {
  destroy();
}

uint64_t
calculate_required_pages(ElfFile** elfFiles, size_t numElfFiles) {
  uint64_t req_pages = 0;

  for (int i = 0; i < numElfFiles; i++) {
    ElfFile* elfFile = elfFiles[i];
    req_pages += ceil(elfFile->getFileSize() / PAGE_SIZE);
  }
  /* FIXME: calculate the required number of pages for the page table.
   * We actually don't know how many page tables the enclave might need,
   * because the SDK never knows how its memory will be aligned.
   * Ideally, this should be managed by the driver.
   * For now, we naively allocate enough pages so that we can temporarily get
   * away from this problem.
   * 15 pages will be more than sufficient to cover several hundreds of
   * megabytes of enclave/runtime. */
  /* FIXME Part 2: now that loader does loading, .bss sections also eat up
   * space. Eapp dev must make FREEMEM big enough to fit this!!
   * Possible fix -- re-add exact .bss calculations?
   */

  /* Add one page each for bss segments of runtime and eapp */ 
  // TODO: add space for stack?
  req_pages += 16;
  return req_pages;
}

bool
Enclave::prepareEnclaveMemory(size_t requiredPages, uintptr_t alternatePhysAddr) {
  // FIXME: this will be deprecated with complete freemem support.
  // We just add freemem size for now.
  uint64_t minPages;
  minPages = ROUND_UP(params.getFreeMemSize(), PAGE_BITS) / PAGE_SIZE; 
  minPages += requiredPages;

  if (params.isSimulated()) {
    pMemory->init(0, 0, minPages);
    return true;
  }

  /* Call Enclave Driver */
  if (pDevice->create(minPages) != Error::Success) {
    return false;
  }

  /* We switch out the phys addr as needed */
  uintptr_t physAddr;
  if (alternatePhysAddr) {
    physAddr = alternatePhysAddr;
  } else {
    physAddr = pDevice->getPhysAddr();
  }

  pMemory->init(pDevice, physAddr, minPages);
  return true;
}

uintptr_t
Enclave::copyFile(uintptr_t filePtr, size_t fileSize) {
	uintptr_t startOffset = pMemory->getCurrentOffset(); 
  size_t bytesRemaining = fileSize; 
	
	uintptr_t currOffset;
	while (bytesRemaining > 0) {
		currOffset = pMemory->getCurrentOffset(); 
    pMemory->incrementEPMFreeList();

		size_t bytesToWrite = (bytesRemaining > PAGE_SIZE) ? PAGE_SIZE : bytesRemaining;
		size_t bytesWritten = fileSize - bytesRemaining;

    if (bytesToWrite < PAGE_SIZE) {
      char page[PAGE_SIZE];
      memset(page, 0, PAGE_SIZE);
      memcpy(page, (const void*) (filePtr + bytesWritten), (size_t)(bytesToWrite));
      pMemory->writeMem((uintptr_t) page, currOffset, PAGE_SIZE);
    } else {
		  pMemory->writeMem(filePtr + bytesWritten, currOffset, bytesToWrite);
    }
		bytesRemaining -= bytesToWrite;
	}
	return startOffset;
}

static void measureElfFile(hash_ctx_t* hash_ctx, ElfFile* file) {
  uintptr_t fptr = (uintptr_t) file->getPtr();
  uintptr_t fend = fptr + (uintptr_t) file->getFileSize();

  for (; fptr < fend; fptr += PAGE_SIZE) {
    if (fend - fptr < PAGE_SIZE) {
      char page[PAGE_SIZE];
      memset(page, 0, PAGE_SIZE);
      memcpy(page, (const void*) fptr, (size_t)(fend-fptr));
      hash_extend_page(hash_ctx, (void*) page);
    } else {
      hash_extend_page(hash_ctx, (void*) fptr);
    }
  }
}

Error
Enclave::measure(char* hash, const char* eapppath, const char* runtimepath, const char* loaderpath) {
  hash_ctx_t hash_ctx;
  hash_init(&hash_ctx);

  ElfFile* loader = new ElfFile(loaderpath);
  ElfFile* runtime = new ElfFile(runtimepath);
  ElfFile* eapp = new ElfFile(eapppath);

  uintptr_t sizes[3] = { PAGE_UP(loader->getFileSize()), PAGE_UP(runtime->getFileSize()),
                          PAGE_UP(eapp->getFileSize()) };
  hash_extend(&hash_ctx, (void*) sizes, sizeof(sizes));

  measureElfFile(&hash_ctx, loader);
  delete loader;
  measureElfFile(&hash_ctx, runtime);
  delete runtime;
  measureElfFile(&hash_ctx, eapp);
  delete eapp;

  hash_finalize(hash, &hash_ctx);

  return Error::Success;
}

Error
Enclave::init(const char* eapppath, const char* runtimepath, const char* loaderpath, Params _params) {
  return this->init(eapppath, runtimepath, loaderpath, _params, (uintptr_t)0);
}

Error
Enclave::init(
    const char* eapppath, const char* runtimepath, const char* loaderpath, Params _params,
    uintptr_t alternatePhysAddr) {
  params = _params;

  if (params.isSimulated()) {
    pMemory = new SimulatedEnclaveMemory();
    pDevice = new MockKeystoneDevice();
    return Error::DeviceInitFailure;
  } else {
    pMemory = new PhysicalEnclaveMemory();
    pDevice = new KeystoneDevice();
  }

  ElfFile* enclaveFile = new ElfFile(eapppath);
  ElfFile* runtimeFile = new ElfFile(runtimepath);
  ElfFile* loaderFile = new ElfFile(loaderpath);

  if (!pDevice->initDevice(params)) {
    destroy();
    return Error::DeviceInitFailure;
  }

  ElfFile* elfFiles[3] = {enclaveFile, runtimeFile, loaderFile};
  size_t requiredPages = calculate_required_pages(elfFiles, 3);

  if (!prepareEnclaveMemory(requiredPages, alternatePhysAddr)) {
    destroy();
    return Error::DeviceError;
  }

  uintptr_t utm_free;
  utm_free = pMemory->allocUtm(params.getUntrustedSize());

  if (!utm_free) {
    ERROR("failed to init untrusted memory - ioctl() failed");
    destroy();
    return Error::DeviceError;
  }
	
  struct runtime_params_t runtimeParams;
  runtimeParams.untrusted_ptr =
      reinterpret_cast<uintptr_t>(utm_free);
  runtimeParams.untrusted_size =
      reinterpret_cast<uintptr_t>(params.getUntrustedSize());

#ifdef ENABLE_ENCLAVE_CACHE
  //get signature, public key, certificate(cacheを使わないときはここから閉じる)
  std::ifstream signFile("sign.txt");
  char str_sign[SIGN_SIZE+1];
  unsigned char hex_sign[SIGN_SIZE/2];
  
  if(signFile.fail()){
    std::cerr << "Failed to open file1." << std::endl;
    return Error::FileNotExist;
  }

  signFile.getline(str_sign, SIGN_SIZE+1);
  BytesFromHexString(hex_sign, str_sign);

  std::ifstream keyFile("pubkey.txt");

  char str_pub_key[ED_KEY_LENGTH+1];
  unsigned char hex_pub_key[ED_KEY_LENGTH/2];
  
  if(keyFile.fail()){
    std::cerr << "Failed to open file2." << std::endl;
    return Error::FileNotExist;
  }

  keyFile.getline(str_pub_key, ED_KEY_LENGTH+1);
  BytesFromHexString(hex_pub_key, str_pub_key);

  std::ifstream certFile("certificate.txt");

  char str_cert[CERT_SIZE+1];
  unsigned char hex_cert[CERT_SIZE/2];
  
  if(certFile.fail()){
    std::cerr << "Failed to open file3." << std::endl;
    return Error::FileNotExist;
  }

  certFile.getline(str_cert, SIGN_SIZE+1);
  BytesFromHexString(hex_cert, str_cert);

  if(pDevice->copyCachedEnclave(runtimeParams, hex_sign, hex_pub_key, hex_cert)){
    //cacheヒット時はmapUntrustedだけやる
    if (!mapUntrusted(params.getUntrustedSize())) {
          ERROR(
          "failed to finalize enclave - cannot obtain the untrusted buffer "
          "pointer \n");
          destroy();
          return Error::DeviceMemoryMapError;
      }
    std::cout << "hit" << std::endl;
    delete enclaveFile;
    delete runtimeFile;
    delete loaderFile;
    return Error::Success;
  }else{//ミス時は通常通りに作成
    std::cout << "miss" << std::endl;
    copyFile((uintptr_t) loaderFile->getPtr(), loaderFile->getFileSize());

    pMemory->startRuntimeMem();
    runtimeElfAddr = copyFile((uintptr_t) runtimeFile->getPtr(), runtimeFile->getFileSize()); // TODO: figure out if we need runtimeELFAddr

    pMemory->startEappMem();
    enclaveElfAddr = copyFile((uintptr_t) enclaveFile->getPtr(), enclaveFile->getFileSize());  // TODO: figure out if we need enclaveElfAddr

    pMemory->startFreeMem();

    //cache用のfinalize, 獲得したeidの開放やcache metadataの作成、mmapの解除を行う
    if (pDevice->cacheFinalize(
          pMemory->getRuntimePhysAddr(), pMemory->getEappPhysAddr(),
          pMemory->getFreePhysAddr(), runtimeParams, hex_sign, hex_pub_key, hex_cert) != Error::Success) {
      return Error::DeviceError;
    }

    if (!mapUntrusted(params.getUntrustedSize())) {
      ERROR(
      "failed to finalize enclave - cannot obtain the untrusted buffer "
      "pointer \n");
      destroy();
      return Error::DeviceMemoryMapError;
    }

    // ELF files are no longer needed 
    delete enclaveFile;
    delete runtimeFile;
    delete loaderFile;
    return Error::Success;
  }
  //enclaveキャッシュはここまで
#endif

  /* Copy loader into beginning of enclave memory */
  copyFile((uintptr_t) loaderFile->getPtr(), loaderFile->getFileSize());

  pMemory->startRuntimeMem();
  runtimeElfAddr = copyFile((uintptr_t) runtimeFile->getPtr(), runtimeFile->getFileSize()); // TODO: figure out if we need runtimeELFAddr

  pMemory->startEappMem();
  enclaveElfAddr = copyFile((uintptr_t) enclaveFile->getPtr(), enclaveFile->getFileSize());  // TODO: figure out if we need enclaveElfAddr

  pMemory->startFreeMem();

  if (pDevice->finalize(
          pMemory->getRuntimePhysAddr(), pMemory->getEappPhysAddr(),
          pMemory->getFreePhysAddr(), runtimeParams) != Error::Success) {
    destroy();
    return Error::DeviceError;
  }
  if (!mapUntrusted(params.getUntrustedSize())) {
    ERROR(
        "failed to finalize enclave - cannot obtain the untrusted buffer "
        "pointer \n");
    destroy();
    return Error::DeviceMemoryMapError;
  }

  /* ELF files are no longer needed */
  delete enclaveFile;
  delete runtimeFile;
  delete loaderFile;
  return Error::Success;
}

bool
Enclave::mapUntrusted(size_t size) {
  if (size == 0) {
    return true;
  }

  shared_buffer = pDevice->map(0, size);

  if (shared_buffer == NULL) {
    return false;
  }

  shared_buffer_size = size;

  return true;
}

Error
Enclave::destroy() {
  return pDevice->destroy();
}

Error
Enclave::resetcache(){
  return pDevice->resetcache();
}

Error
Enclave::run(uintptr_t* retval) {
  if (params.isSimulated()) {
    return Error::Success;
  }

  Error ret = pDevice->run(retval);
  while (ret == Error::EdgeCallHost || ret == Error::EnclaveInterrupted) {
    /* enclave is stopped in the middle. */
    if (ret == Error::EdgeCallHost && oFuncDispatch != NULL) {
      oFuncDispatch(getSharedBuffer());
    }
    ret = pDevice->resume(retval);
  }

  if (ret != Error::Success) {
    ERROR("failed to run enclave - ioctl() failed");
    destroy();
    return Error::DeviceError;
  }

  return Error::Success;
}

void*
Enclave::getSharedBuffer() {
  return shared_buffer;
}

size_t
Enclave::getSharedBufferSize() {
  return shared_buffer_size;
}

Memory*
Enclave::getMemory() {
  return pMemory;
}

Error
Enclave::registerOcallDispatch(OcallFunc func) {
  oFuncDispatch = func;
  return Error::Success;
}

}  // namespace Keystone
