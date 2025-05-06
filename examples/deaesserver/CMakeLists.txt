set(eapp_bin deaesserver)
set(eapp_src eapp/deaesserver.c)
set(host_bin deaesserver-runner)
set(host_src host/host.cpp)
set(package_name "deaesserver.ke")
set(package_script "./deaesserver-runner deaesserver eyrie-rt loader.bin")

if(RISCV32)
  set(eyrie_plugins "freemem io_syscall linux_syscall env_setup rv32")
else()
  set(eyrie_plugins "freemem io_syscall linux_syscall env_setup")
endif()

set(enclave_cache_cert certificate.txt)
set(enclave_cache_pubkey pubkey.txt)
set(enclave_cache_sig sign.txt)

# eapp

add_executable(${eapp_bin} ${eapp_src} ${AES_LIBRARY_SRC} ${AES_LIBRARY_INCLUDE})
target_link_libraries(${eapp_bin} "-static" ${KEYSTONE_LIB_EAPP} ${KEYSTONE_LIB_EDGE})

# host

add_executable(${host_bin} ${host_src})
target_link_libraries(${host_bin} ${KEYSTONE_LIB_HOST} ${KEYSTONE_LIB_EDGE} "-static")

# add target for Eyrie runtime (see keystone.cmake)

set(eyrie_files_to_copy .options_log eyrie-rt loader.bin)
add_eyrie_runtime(${eapp_bin}-eyrie
  ${eyrie_plugins}
  ${eyrie_files_to_copy})

# add target for packaging (see keystone.cmake)

add_keystone_package(${eapp_bin}-package
  ${package_name}
  ${package_script}
  ${eyrie_files_to_copy} ${eapp_bin} ${host_bin} ${enclave_cache_cert} ${enclave_cache_pubkey} ${enclave_cache_sig})

add_dependencies(${eapp_bin}-package ${eapp_bin}-eyrie)

# add package to the top-level target
add_dependencies(examples ${eapp_bin}-package)
