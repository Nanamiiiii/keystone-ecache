//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include <iostream>
#include "edge/edge_call.h"
#include "host/keystone.h"

using namespace Keystone;

int
main(int argc, char** argv) {
  Enclave enclave;
  Params params;

  clock_t start;
  clock_t end;

  params.setFreeMemSize(512 * 1024);
  params.setUntrustedMem(DEFAULT_UNTRUSTED_PTR, 256 * 1024);

  start = clock();
  enclave.init(argv[1], argv[2], argv[3], params);
  end = clock();

  enclave.registerOcallDispatch(incoming_call_dispatch);
  edge_call_init_internals(
      (uintptr_t)enclave.getSharedBuffer(), enclave.getSharedBufferSize());

  enclave.run();
  std::cout<< (double)(end-start)/ CLOCKS_PER_SEC << std::endl;

  return 0;
}
