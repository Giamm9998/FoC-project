#include <arpa/inet.h>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define PORT 8081
#define ADDRESS "127.0.0.1"

using namespace std;

void greet_user() {
    // Thanks to https://fsymbols.com/generators/carty/
    puts("\
░█████╗░██╗░░░░░░█████╗░██╗░░░██╗██████╗░    ░██████╗████████╗░█████╗░██████╗░░█████╗░░██████╗░███████╗\n\
██╔══██╗██║░░░░░██╔══██╗██║░░░██║██╔══██╗    ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗██╔══██╗██╔════╝░██╔════╝\n\
██║░░╚═╝██║░░░░░██║░░██║██║░░░██║██║░░██║    ╚█████╗░░░░██║░░░██║░░██║██████╔╝███████║██║░░██╗░█████╗░░\n\
██║░░██╗██║░░░░░██║░░██║██║░░░██║██║░░██║    ░╚═══██╗░░░██║░░░██║░░██║██╔══██╗██╔══██║██║░░╚██╗██╔══╝░░\n\
╚█████╔╝███████╗╚█████╔╝╚██████╔╝██████╔╝    ██████╔╝░░░██║░░░╚█████╔╝██║░░██║██║░░██║╚██████╔╝███████╗\n\
░╚════╝░╚══════╝░╚════╝░░╚═════╝░╚═════╝░    ╚═════╝░░░░╚═╝░░░░╚════╝░╚═╝░░╚═╝╚═╝░░╚═╝░╚═════╝░╚══════╝\n");
}

void interact(int server_fd) {
    string input;
    char buffer[1024] = {0};
    cout << "What do you want to send to the server? ";
    cin >> input;
    write(server_fd, input.c_str(), input.length());
    read(server_fd, buffer, sizeof(buffer));
    cout << "From server: " << buffer << endl;
}

int main(int argc, char const *argv[]) {
    int sock = 0, valread;
    struct sockaddr_in serv_addr;

    // Create the socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Set socket address and port
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // Convert IPv4 and IPv6 addresses from text to binary
    // form
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        perror("Cannot convert address");
        exit(EXIT_FAILURE);
    }

    // Connect to the server
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Cannot connect to server");
        exit(EXIT_FAILURE);
    }

    greet_user();

    // Start interacting with the server
    interact(sock);

    // Close socket when we are done
    close(sock);
}
