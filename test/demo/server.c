#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>

void handle_client(SOCKET clientSocket) {
    char buffer[16];
    int bofSize = 128;
    int bytesRead;

    // Handle the client request
    while ((bytesRead = recv(clientSocket, buffer, bofSize, 0)) > 0) {
        // Process the received data as needed
        printf("Received from client: %.*s\n", bytesRead, buffer);

        // Respond to the client (optional)
        char* response = buffer;
        send(clientSocket, response, bytesRead, 0);
    }
}

int main() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        exit(1);
    }

    SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == INVALID_SOCKET) {
        perror("Socket creation failed");
        exit(1);
    }

    struct sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = INADDR_ANY;
    serverAddress.sin_port = htons(8080);

    if (bind(serverSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) == SOCKET_ERROR) {
        perror("Bind failed");
        exit(1);
    }

    if (listen(serverSocket, 5) == SOCKET_ERROR) {
        perror("Listen failed");
        exit(1);
    }

    printf("Server is waiting for incoming connections...\n");

    while (1) {
        SOCKET clientSocket;
        struct sockaddr_in clientAddress;
        int clientAddressLength = sizeof(clientAddress);

        clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddress, &clientAddressLength);
        if (clientSocket == INVALID_SOCKET) {
            perror("Accept failed");
            continue;
        }

        printf("Client connected\n");

        handle_client(clientSocket);
        printf("[child] handle client successfully!\n");
        closesocket(clientSocket);
    }

    closesocket(serverSocket);
    WSACleanup();
    return 0;
}




/*#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>



void handle_client(int clientSocket) {
    char buffer[16];
    int bofSize = 128;
    int bytesRead;

    // Handle the client request
    while ((bytesRead = recv(clientSocket, buffer, bofSize, 0)) > 0) {
        // Process the received data as needed
        printf("Received from client: %.*s\n", bytesRead, buffer);

        // Respond to the client (optional)
        char* response = buffer;
        send(clientSocket, response, strlen(response), 0);
    }
    
}

int main() {
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == -1) {
        perror("Socket creation failed");
        exit(1);
    }

    struct sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = INADDR_ANY;
    serverAddress.sin_port = htons(8080);

    if (bind(serverSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) == -1) {
        perror("Bind failed");
        exit(1);
    }


    if (listen(serverSocket, 5) == -1) {
        perror("Listen failed");
        exit(1);
    }

    printf("Server is waiting for incoming connections...\n");

    while (1) {
        int clientSocket;
        struct sockaddr_in clientAddress;
        socklen_t clientAddressLength = sizeof(clientAddress);

        clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddress, &clientAddressLength);
        if (clientSocket == -1) {
            perror("Accept failed");
            continue;
        }

        printf("Client connected\n");

        handle_client(clientSocket);
        printf("[child] handle client successfully!\n");
        close(clientSocket);


        // Create a new process to handle the client request
        pid_t child_pid = fork();

        if (child_pid == 0) {
            // In the child process, handle the client request
            handle_client(clientSocket);
            printf("[child] handle client successfully!\n");
            close(clientSocket);
            exit(0);
        } else if (child_pid > 0) {
            // In the parent process, close the client socket
            close(clientSocket);
        } else {
            perror("Fork failed");
            exit(1);
        }
    }

    close(serverSocket);
    return 0;
}
*/