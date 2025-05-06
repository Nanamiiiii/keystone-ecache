#include <iostream>
#include <stdio.h>
#include "edge/edge_call.h"
#include "host/keystone.h"

using namespace Keystone;

int
main(int argc, char** argv) {
  Enclave enclave;
  Params params;

  params.setFreeMemSize(256 * 1024);
  params.setUntrustedMem(DEFAULT_UNTRUSTED_PTR, 256 * 1024);

  clock_t start = clock();
  enclave.init(argv[1], argv[2], argv[3], params);
  clock_t end =clock();
  enclave.registerOcallDispatch(incoming_call_dispatch);
  edge_call_init_internals(
      (uintptr_t)enclave.getSharedBuffer(), enclave.getSharedBufferSize());
  enclave.run();
  std::cout << "time = " << (double)(end-start) / CLOCKS_PER_SEC << "sec." << std::endl;

  return 0;
}