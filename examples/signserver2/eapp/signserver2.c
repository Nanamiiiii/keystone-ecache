#include "edge/edge_call.h"
#include "app/eapp_utils.h"
#include "app/string.h"
#include "app/syscall.h"
#include "verifier/ed25519/ed25519.h"
#include "key.h"
#include "aes.h"

static const uint8_t key[] ={ 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                      						0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };
static const uint8_t iv[]  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

#define BUFFER_SIZE 2048

#define  OCALL_PRINT_BUFFER 1
#define  OCALL_PRINT_VALUE 2
#define  OCALL_SEND_REPLY  3
#define OCALL_GET_STRING 4
#define OCALL_GET_KEYNUM 5
#define OCALL_WAIT_FOR_MESSAGE 6

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

void ocall_get_key_number(struct edge_data* retdata){
  ocall(OCALL_GET_KEYNUM, NULL, 0, retdata, sizeof(struct edge_data));
}

void
ocall_wait_for_message(struct edge_data *msg)
{
    ocall(OCALL_WAIT_FOR_MESSAGE, NULL, 0, msg, sizeof(struct edge_data));
}


int main() {
  static struct edge_data input1, input2;
  static struct AES_ctx ctx;
  //ocall_wait_for_message(&input);
  ocall_get_key_number(&input1);
  int key_num;
  copy_from_shared(&key_num, input1.offset, input1.size);

  ocall_get_string(&input2);
  static char host_str[BUFFER_SIZE];
  copy_from_shared(host_str, input2.offset, input2.size);

  static unsigned char secret_key[SECRET_KEY_LEN];
  memcpy(secret_key, key_pairs[key_num].secret_key, SECRET_KEY_LEN);

  AES_init_ctx_iv(&ctx, key, iv);
  AES_CBC_decrypt_buffer(&ctx, (uint8_t*)secret_key, SECRET_KEY_LEN);

  static unsigned char signature[32];
  ed25519_sign(signature, host_str, strlen(host_str), 
                secret_key, key_pairs[key_num].public_key);

  int length = strlen(host_str);
  int i = 0;
  ocall_send_reply(signature, 32);
  
  return 0;
}