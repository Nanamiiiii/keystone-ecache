#include <iostream>
#include <stdio.h>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include "edge/edge_call.h"
#include "host/keystone.h"

using namespace Keystone;

#define PORT 60000
#define BUFFER_SIZE 256

#define  OCALL_PRINT_BUFFER 1
#define  OCALL_PRINT_VALUE 2
#define  OCALL_SEND_REPLY  3
#define OCALL_GET_STRING 4
#define OCALL_WAIT_FOR_MESSAGE 5

static char socket_buffer[BUFFER_SIZE] = {0};

static void print_buffer_wrapper(void* buffer);
static unsigned long print_buffer(char* str);
static void print_value_wrapper(void* buffer);
static void print_value(unsigned long val);
static void send_reply_wrapper(void* buffer);
static void get_host_string_wrapper(void* buffer);
static const char* get_host_string();
static void wait_for_message_wrapper(void* buffer);
static char* recv_buf(int* len);
static void send_buf(char* sendbuf, int len);
static void server_init(void);

int server_fd, client_socket;
struct sockaddr_in address;
static socklen_t clientaddr_size;
int opt = 1;
int addrlen = sizeof(address);

void
edge_init(Keystone::Enclave* enclave)
{
  enclave->registerOcallDispatch(incoming_call_dispatch);
  register_call(OCALL_PRINT_BUFFER, print_buffer_wrapper);
  register_call(OCALL_PRINT_VALUE, print_value_wrapper);
  register_call(OCALL_SEND_REPLY, send_reply_wrapper);
  register_call(OCALL_GET_STRING, get_host_string_wrapper);
  register_call(OCALL_WAIT_FOR_MESSAGE, wait_for_message_wrapper);

    edge_call_init_internals((uintptr_t)enclave->getSharedBuffer(),
			     enclave->getSharedBufferSize());
}

void
print_buffer_wrapper(void* buffer)
{
    struct edge_call* edge_call = (struct edge_call*)buffer;
    uintptr_t call_args;
    unsigned long ret_val;
    size_t arg_len;
    if (edge_call_args_ptr(edge_call, &call_args, &arg_len) != 0) {
        edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
        return;
    }

    ret_val = print_buffer((char*)call_args);

    uintptr_t data_section = edge_call_data_ptr();
    memcpy((void*)data_section, &ret_val, sizeof(unsigned long));
    if (edge_call_setup_ret(edge_call,
			    (void*)data_section, sizeof(unsigned long))) {
        edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
        } else {
        edge_call->return_data.call_status = CALL_STATUS_OK;
    }

    return;
}

unsigned long
print_buffer(char* str) {
  printf("Enclave said: %s", str);
  fflush(stdout);
  return strlen(str);
}

void
print_value_wrapper(void* buffer) {
  /* For now we assume the call struct is at the front of the shared
   * buffer. This will have to change to allow nested calls. */
  struct edge_call* edge_call = (struct edge_call*)buffer;

  uintptr_t call_args;
  unsigned long ret_val;
  size_t args_len;
  if (edge_call_args_ptr(edge_call, &call_args, &args_len) != 0) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
    return;
  }

  print_value(*(unsigned long*)call_args);

  edge_call->return_data.call_status = CALL_STATUS_OK;
  return;
}

void
print_value(unsigned long val) {
  printf("Enclave said value: %u\n", val);
  return;
}

void
send_reply_wrapper(void* buffer)
{
    struct edge_call* edge_call = (struct edge_call*)buffer;

    uintptr_t call_args;
    unsigned long ret_val;
    size_t args_len;
    if (edge_call_args_ptr(edge_call, &call_args, &args_len) != 0) {
	  edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
	  return;
    }

    send_buf((char*)call_args, edge_call->call_arg_size);
    edge_call->return_data.call_status = CALL_STATUS_OK;

    return;
}

void
send_buf(char* sendbuf, int len)
{
    address.sin_port = ntohs(PORT);
    ssize_t send_status;
    send_status = send(client_socket, sendbuf, len, 0);
    if (send_status < 0) {
	perror("send error");
	exit(-1);
    }
}

void
get_host_string_wrapper(void* buffer) {
  /* For now we assume the call struct is at the front of the shared
   * buffer. This will have to change to allow nested calls. */
  struct edge_call* edge_call = (struct edge_call*)buffer;

  uintptr_t call_args;
  unsigned long ret_val;
  size_t args_len;
  if (edge_call_args_ptr(edge_call, &call_args, &args_len) != 0) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
    return;
  }

  const char* host_str = get_host_string();
  size_t host_str_len  = strlen(host_str) + 1;

  // This handles wrapping the data into an edge_data_t and storing it
  // in the shared region.
  if (edge_call_setup_wrapped_ret(edge_call, (void*)host_str, host_str_len)) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
  } else {
    edge_call->return_data.call_status = CALL_STATUS_OK;
  }

  return;
}

const char* get_host_string(){
  return socket_buffer;
}

void
wait_for_message_wrapper(void* buffer)
{
    struct edge_call* edge_call = (struct edge_call*)buffer;

    uintptr_t call_args;
    unsigned long ret_val;
    size_t args_len;
    if (edge_call_args_ptr(edge_call, &call_args, &args_len) != 0) {
	edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
	return;
    }

    int len;
    void* dbuf = (void*)recv_buf(&len);

    if (edge_call_setup_wrapped_ret(edge_call, dbuf, len)) {
	edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
    } else{
	edge_call->return_data.call_status = CALL_STATUS_OK;
    }

    return;
}

char*
recv_buf(int* len)
{
    static char recvbuf[64];

    int recv_status;
    clientaddr_size = sizeof(address);
    recv_status = recvfrom(server_fd, recvbuf, sizeof(recvbuf),
			   0, (struct sockaddr *)&address, &clientaddr_size);
    if (recv_status < 0) {
	*len = 0;
    } else {
	printf("from %s:%d, %s\n", inet_ntoa(address.sin_addr), ntohs(address.sin_port), recvbuf);
	*len = clientaddr_size;
    }

    return recvbuf;
}

void server_init(void) {

    // サーバーソケットの作成
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // ソケットオプションの設定
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // アドレスとポートの設定
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // ソケットをポートにバインド
    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // 接続待ち状態に設定
    if (listen(server_fd, 3) < 0) {
        perror("listen failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
}

int
main(int argc, char** argv) {

  server_init();  

  while (true) {
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    if ((client_socket = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen)) < 0) {
        perror("accept failed");
        continue;
    }

    int valread = read(client_socket, socket_buffer, BUFFER_SIZE);

    //std::cout << "Connection established with client." << std::endl;

    Enclave enclave;
    Params params;
    params.setUntrustedMem(DEFAULT_UNTRUSTED_PTR, 256 * 1024); 
    params.setFreeMemSize(256 * 1024);
    enclave.init(argv[1], argv[2], argv[3], params);
    edge_init(&enclave);
    enclave.run();

    memset(socket_buffer, 0, BUFFER_SIZE);
    close(client_socket);
  }

  close(server_fd);

  return 0;
}