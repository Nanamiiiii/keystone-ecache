set(eapp_bin aes)
set(eapp_src eapp/aes.c)
set(host_bin aes-runner)
set(host_src host/host.cpp)
set(package_name "aes.ke")
set(package_script "./aes-runner aes eyrie-rt loader.bin")

if(RISCV32)
  set(eyrie_plugins "freemem io_syscall linux_syscall env_setup rv32")
else()
  set(eyrie_plugins "freemem io_syscall linux_syscall env_setup")
endif()

# tiny aes library
set(AES_LIBRARY_SRC ../tiny-AES-c/aes.c)
set(AES_LIBRARY_INCLUDE ../tiny-AES-c)

# eapp

add_executable(${eapp_bin} ${eapp_src} ${AES_LIBRARY_SRC})
target_include_directories(${eapp_bin} PRIVATE ${AES_LIBRARY_INCLUDE})
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
  ${eyrie_files_to_copy} ${eapp_bin} ${host_bin})

add_dependencies(${eapp_bin}-package ${eapp_bin}-eyrie)

# add package to the top-level target
add_dependencies(examples ${eapp_bin}-package)
