#include <iostream>
#include <stdio.h>
#include <cstring>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "aes.h"

static const uint8_t key[] ={ 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                      						0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };
static const uint8_t iv[]  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

#define SERVER_IP "127.0.0.1"  // サーバーのIPアドレス（ローカルホスト）
#define PORT 60000             // サーバーのポート番号
#define BUFFER_SIZE 256       // バッファサイズ

int main() {
	int sock = 0;
	struct sockaddr_in serv_addr;
	char buffer[BUFFER_SIZE] = {0};
	struct timespec start, end;

	// ソケットの作成
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
			std::cerr << "Socket creation error" << std::endl;
			return -1;
	}

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(PORT);

	// IPアドレスの変換と設定
	if (inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0) {
			std::cerr << "Invalid address/ Address not supported" << std::endl;
			return -1;
	}

	// サーバーに接続
	if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
			std::cerr << "Connection failed" << std::endl;
			return -1;
	}

	std::cout << "Connected to the server." << std::endl;
		// 標準入力からメッセージを読み取る
		std::string message;
		std::cout << "> ";
		std::getline(std::cin, message);
		clock_gettime(CLOCK_MONOTONIC, &start);
		// サーバーにメッセージを送信
		send(sock, message.c_str(), message.length(), 0);

		// サーバーからの応答を受信
		int valread = read(sock, buffer, BUFFER_SIZE);
		std::cout << valread;
		if (valread > 0) {
				buffer[valread] = '\0';
				std::cout << "Echo from server: " << buffer << std::endl;
		}
		clock_gettime(CLOCK_MONOTONIC, &end);
	double time = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;

	std::cout << "return" << time << std::endl;
		// バッファをクリア
		memset(buffer, 0, BUFFER_SIZE);


	// ソケットを閉じる
	close(sock);
	std::cout << "Disconnected from server." << std::endl;
	return 0;
}