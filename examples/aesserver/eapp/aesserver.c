#include "edge/edge_call.h"
#include "app/eapp_utils.h"
#include "app/string.h"
#include "app/syscall.h"
#include "stdio.h"
#include "time.h"
#include "aes.h"
#include <ctype.h>

#define BUFFER_SIZE 256

#define  OCALL_PRINT_BUFFER 1
#define  OCALL_PRINT_VALUE 2
#define  OCALL_SEND_REPLY  3
#define OCALL_GET_STRING 4
#define OCALL_WAIT_FOR_MESSAGE 5

#define AES_KEY_LENGTH 32
#define AES_IV_LENGTH 16

static const unsigned char _sanctum_dev_secret_key[] = {
    0x40, 0xa0, 0x99, 0x47, 0x8c, 0xce, 0xfa, 0x3a, 0x06, 0x63, 0xab,
    0xc9, 0x5e, 0x7a, 0x1e, 0xc9, 0x54, 0xb4, 0xf5, 0xf6, 0x45, 0xba,
    0xd8, 0x04, 0xdb, 0x13, 0xe7, 0xd7, 0x82, 0x6c, 0x70, 0x73, 0x57,
    0x6a, 0x9a, 0xb6, 0x21, 0x60, 0xd9, 0xd1, 0xc6, 0xae, 0xdc, 0x29,
    0x85, 0x2f, 0xb9, 0x60, 0xee, 0x51, 0x32, 0x83, 0x5a, 0x16, 0x89,
    0xec, 0x06, 0xa8, 0x72, 0x34, 0x51, 0xaa, 0x0e, 0x4a};

static const uint8_t key[] ={ 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                      						0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };
static const uint8_t iv[]  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

static void ocall_print_value(unsigned long val){

  unsigned long val_ = val;
  ocall(OCALL_PRINT_VALUE, &val_, sizeof(unsigned long), 0, 0);

  return;
}

static unsigned long ocall_print_buffer(char* data, size_t data_len){

  unsigned long retval;
  ocall(OCALL_PRINT_BUFFER, data, data_len, &retval ,sizeof(unsigned long));

  return retval;
}

static void ocall_send_reply(char* data, size_t data_len){
    ocall(OCALL_SEND_REPLY, data, data_len, 0, 0);
    return;
}

static void ocall_get_string(struct edge_data* retdata){
  ocall(OCALL_GET_STRING, NULL, 0, retdata, sizeof(struct edge_data));
  return;
}

static void
ocall_wait_for_message(struct edge_data *msg)
{
    ocall(OCALL_WAIT_FOR_MESSAGE, NULL, 0, msg, sizeof(struct edge_data));
}

int main() {
  clock_t start,end;
  struct edge_data input;

  ocall_get_string(&input);
  struct AES_ctx ctx;
  static char text[BUFFER_SIZE];
  copy_from_shared(text, input.offset, input.size);
  start = clock();
	AES_init_ctx_iv(&ctx, key, iv);
	AES_CBC_encrypt_buffer(&ctx, (uint8_t*)_sanctum_dev_secret_key, BUFFER_SIZE);
  AES_init_ctx_iv(&ctx, key, iv);
  AES_CBC_decrypt_buffer(&ctx, (uint8_t*)_sanctum_dev_secret_key, BUFFER_SIZE);
  end =clock();
  int text_len = strlen(text);
  ocall_send_reply(text, text_len);
  
  printf("time = %lf\n", ((double)(end-start)/CLOCKS_PER_SEC));
  return 0;
}