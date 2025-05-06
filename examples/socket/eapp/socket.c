#include "edge/edge_call.h"
#include "app/eapp_utils.h"
#include "app/string.h"
#include "app/syscall.h"

#define BUFFER_SIZE 256

#define  OCALL_PRINT_BUFFER 1
#define  OCALL_PRINT_VALUE 2
#define  OCALL_SEND_REPLY  3
#define OCALL_GET_STRING 4
#define OCALL_WAIT_FOR_MESSAGE 5

void ocall_print_value(unsigned long val){

  unsigned long val_ = val;
  ocall(OCALL_PRINT_VALUE, &val_, sizeof(unsigned long), 0, 0);

  return;
}

unsigned long ocall_print_buffer(char* data, size_t data_len){

  unsigned long retval;
  ocall(OCALL_PRINT_BUFFER, data, data_len, &retval ,sizeof(unsigned long));

  return retval;
}

void ocall_send_reply(char* data, size_t data_len){
    ocall(OCALL_SEND_REPLY, data, data_len, 0, 0);
    return;
}

void ocall_get_string(struct edge_data* retdata){
  ocall(OCALL_GET_STRING, NULL, 0, retdata, sizeof(struct edge_data));
  return;
}

void
ocall_wait_for_message(struct edge_data *msg)
{
    ocall(OCALL_WAIT_FOR_MESSAGE, NULL, 0, msg, sizeof(struct edge_data));
}


int main() {
  struct edge_data input;
  //ocall_wait_for_message(&input);
  ocall_get_string(&input);
  char host_str[BUFFER_SIZE];
  copy_from_shared(host_str, input.offset, input.size);

  int length = strlen(host_str);
  int i = 0;
  ocall_send_reply(host_str, length+1);
  return 0;
}