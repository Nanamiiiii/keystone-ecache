set(eapp_bin signserver2)
set(eapp_src eapp/signserver2.c)
set(host_bin signserver2-runner)
set(host_src host/host.cpp)
set(package_name "signserver2.ke")
set(package_script "./signserver2-runner signserver2 eyrie-rt loader.bin")
set(AES_LIBRARIES "/home/umetaku/keystone/tiny-AES-c/libaes64.a")
set(AES_INCLUDE_DIR "/home/umetaku/keystone/tiny-AES-c")

if(RISCV32)
  set(eyrie_plugins "freemem io_syscall linux_syscall env_setup rv32")
else()
  set(eyrie_plugins "freemem io_syscall linux_syscall env_setup")
endif()

# eapp

include_directories(${AES_INCLUDE_DIR})
add_executable(${eapp_bin} ${eapp_src})
target_link_options(${eapp_bin} PRIVATE -Wl,--gc-sections)
target_compile_options(${eapp_bin} PRIVATE -ffunction-sections -fdata-sections)
target_link_libraries(${eapp_bin} "-static" 
  ${KEYSTONE_LIB_EAPP} ${KEYSTONE_LIB_EDGE} ${KEYSTONE_LIB_VERIFIER}
  ${AES_LIBRARIES}
)

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
  ${eyrie_files_to_copy} ${eapp_bin} ${host_bin})

add_dependencies(${eapp_bin}-package ${eapp_bin}-eyrie)

# add package to the top-level target
add_dependencies(examples ${eapp_bin}-package)
