#include <iostream>
#include <fstream>
#include <stdio.h>
#include <cstring>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#define SERVER_IP "127.0.0.1"  // サーバーのIPアドレス（ローカルホスト）
#define PORT 60000             // サーバーのポート番号
#define BUFFER_SIZE 4096       // バッファサイズ

void printh(unsigned char* data, unsigned int len) {
    for (int i=0; i<len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

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

	std::string input;
  std::cout << "key_number";
	std::getline(std::cin, input);
	
	send(sock, input.c_str(), input.size(), 0);
	// メッセージ送信
	
	input.clear();
	
	std::ifstream file("input.txt");
	if (!file.is_open()) {
    std::cerr << "Failed to open file." << std::endl;
    return 1;
  }
  std::string line;
  // ファイルの内容をすべて結合して読み取る
  while (std::getline(file, line)) {
    input += line;
  }
	file.close(); // ファイルを閉じる
	std::cout << "client" << input.size() << std::endl;

	clock_gettime(CLOCK_MONOTONIC, &start);
  // データサイズを文字列で送信
  std::string data_size_str = std::to_string(input.size());
  send(sock, data_size_str.c_str(), data_size_str.size(), 0);

	size_t total_sent = 0;
  while (total_sent < input.size()) {
    size_t chunk_size = std::min(static_cast<size_t>(BUFFER_SIZE), input.size() - total_sent);
    int sent = send(sock, input.c_str() + total_sent, chunk_size, 0);
    if (sent < 0) {
      std::cerr << "Error sending data" << std::endl;
      break;
    }
    total_sent += sent;
  }

	// サーバーからの応答を受信
	int valread = read(sock, buffer, BUFFER_SIZE);
	std::cout << valread;
	if (valread > 0) {
			buffer[valread] = '\0';
			std::cout << "Echo from server: ";
			printh((unsigned char*)buffer, 32);
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