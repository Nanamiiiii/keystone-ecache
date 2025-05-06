#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>

#define PORT 8080
#define BUFFER_SIZE 1024

int server_fd;
struct sockaddr_in address;
int opt = 1;
int addrlen = sizeof(address);

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

void handleClient(int client_socket) {
    char buffer[BUFFER_SIZE] = {0};

        int valread = read(client_socket, buffer, BUFFER_SIZE);

        std::string message(buffer, valread);

        std::cout << "Received: " << buffer << std::endl;

        int message_length = message.size();
        std::string response = std::to_string(message_length);
        send(client_socket, response.c_str(), response.size(), 0);
        std::cout << "lengthss: " << message_length << std::endl;

        // バッファをクリア
        memset(buffer, 0, BUFFER_SIZE);

    close(client_socket);
}

int main() {
    // SIGCHLDシグナルを無視（子プロセスのゾンビ化を防止）
    signal(SIGCHLD, SIG_IGN);

    server_init();

    std::cout << "Echo server is listening on port " << PORT << "..." << std::endl;

    while (true) {
        // クライアントからの接続を受け入れ
        int client_socket;
        if ((client_socket = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen)) < 0) {
            perror("accept failed");
            continue;
        }

        std::cout << "Connection established with client." << std::endl;

        // 新しいプロセスを作成してクライアント処理を行う
        pid_t pid = fork();
        if (pid == 0) {
            // 子プロセスでクライアント処理
            close(server_fd);  // 子プロセスはサーバーソケットを閉じる
            handleClient(client_socket);
            exit(0);  // 子プロセス終了
        } else if (pid > 0) {
            // 親プロセス
            close(client_socket);  // 親プロセスはクライアントソケットを閉じる
        } else {
            perror("fork failed");
            close(client_socket);
        }
    }

    close(server_fd);
    return 0;
}