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
  enclave.run();
  enclave.resetcache();
  return 0;
}