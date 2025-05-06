# tiny aes library
set(AES_LIBRARY_SRC ../tiny-AES-c/aes.c)
set(AES_LIBRARY_INCLUDE ../tiny-AES-c)

add_executable(signclient signclient.cpp)
add_executable(aesclient aesclient.cpp ${AES_LIBRARY_SRC})
target_include_directories(aesclient PRIVATE ${AES_LIBRARY_INCLUDE})
add_executable(client client.cpp)
add_executable(server server.cpp)
add_dependencies(examples signclient aesclient client server)