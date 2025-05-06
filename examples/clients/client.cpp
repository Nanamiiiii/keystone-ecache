#include <iostream>
#include <stdio.h>
#include <cstring>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

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