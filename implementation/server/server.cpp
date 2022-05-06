#include <csignal>
#include <iostream>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <wait.h>
#define PORT 8081

using namespace std;

pid_t server = -1;

/* Handler for SIGINT. Gracefully shuts down the server by:
 *     - waiting for every child to terminate (we assume that child processes
 *       will eventually terminate)
 */
void sigint_handler(int signum) {
    if (server == getpid()) {
        cout << "Gracefully shutting down server..." << endl;

        while (wait(NULL) > 0)
            ;
        cout << " Bye!" << endl;

        exit(EXIT_SUCCESS);
    }
}

void serve_client(int client_fd) {
    char test[] = "Hello from server!";
    char buffer[1024] = {0};
    write(client_fd, test, sizeof(test));
    read(client_fd, buffer, sizeof(buffer));
    cout << "From client: " << buffer << endl;
}

int main() {
    int sock, new_client, enable_sockopt = 1;
    struct sockaddr_in address;
    socklen_t addr_len = sizeof(address);
    pid_t res;

    server = getpid();

    // Register signal handler to gracefully close on SIGINT
    signal(SIGINT, sigint_handler);

    // Create socket file descriptor
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable_sockopt,
                   sizeof(int)) < 0) {
        perror("setsockopt failed");
        exit(EXIT_FAILURE);
    }

    // Set socket address and port
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Attach socket to specified port
    if (bind(sock, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    // Start listening on it
    if (listen(sock, 0) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    // Accept loop: each time a new client connects start a new process for that
    // client. The child process will handle all interactions with the client.
    while ((new_client =
                accept(sock, (struct sockaddr *)&address, &addr_len)) >= 0) {
        if ((res = fork()) == -1) {
            perror("fork");
            exit(EXIT_FAILURE);
        } else if (res == 0) {
            serve_client(new_client);
            // Close the file descriptor after we are done with it
            close(new_client);
            exit(EXIT_SUCCESS);
        };

        // The parent closes the fd immediately
        close(new_client);
    }
    perror("accept");
    exit(EXIT_FAILURE);
}
