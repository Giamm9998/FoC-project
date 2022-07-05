#include "../common/types.h"
#include "../common/utils.h"
#include "authentication.h"
#include <csignal>
#include <iostream>
#include <netinet/in.h>
#include <openssl/bio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <wait.h>

#define PORT 8080

using namespace std;

pid_t server = -1;
unsigned char *shared_key;

/* Handler for SIGINT. Gracefully shuts down the server by:
 *     - waiting for every child to terminate (we assume that child processes
 *       will eventually terminate)
 */
void sigint_handler(int signum) {
    if (server == getpid()) {
        cout << "Waiting for every child process to terminate... " << endl;

        while (wait(NULL) > 0)
            ;
        cout << "Bye!" << endl;

        exit(EXIT_SUCCESS);
    }
}

/* Server loop for the client to send requests to the server */
void serve_client(int client_fd) {
    int key_len;

    key_len = get_symmetric_key_length();

    try {
        auto [username, shared_key] = authenticate(client_fd, key_len);
    } catch (char const *ex) {
        cerr << "Authentication of the client failed";
#ifdef DEBUG
        cerr << " with \"" << ex << '"' << endl << "Exiting...";
#endif
        cerr << endl;
        close(client_fd);
        exit(EXIT_FAILURE);
    }
#ifdef DEBUG
    print_shared_key(shared_key, key_len);
#endif

    // Server loop
    for (;;) {
        exit(0);
    }
}

int main() {
    int sock, new_client;
    struct sockaddr_in address;
    socklen_t addr_len = sizeof(address);
    pid_t res;

    server = getpid();

    // Register signal handler to gracefully close on SIGINT
    signal(SIGINT, sigint_handler);

    // Create socket file descriptor
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

#ifdef DEBUG
    int enable_sockopt = 1;
    // Set SO_REUSEADDR flag, so that the same port can be re-used right away
    // without waiting the TIME_WAIT time. This is used to avoid errors during
    // debug time due to the default TCP behavior.
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable_sockopt,
                   sizeof(int)) < 0) {
        perror("Setting socket options failed");
        exit(EXIT_FAILURE);
    }
#endif

    // Set socket address and port
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Attach socket to specified port
    if (bind(sock, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Socket binding failed");
        exit(EXIT_FAILURE);
    }

    // Start listening on it
    if (listen(sock, 0) < 0) {
        perror("Socket listen failed");
        exit(EXIT_FAILURE);
    }

#ifdef DEBUG
    // When in debug mode, don't spawn child processes. Instead, use the main
    // process to serve the client request. Should make debugging easier.
    if ((new_client = accept(sock, (struct sockaddr *)&address, &addr_len)) >=
        0) {
        serve_client(new_client);
        // Close the file descriptor after we are done with it
        close(new_client);
        exit(EXIT_SUCCESS);
    } else {
        perror("Accept failed");
        exit(EXIT_FAILURE);
    }
#else
    // Accept loop: each time a new client connects start a new process for that
    // client. The child process will handle all interactions with the client.
    while ((new_client =
                accept(sock, (struct sockaddr *)&address, &addr_len)) >= 0) {
        if ((res = fork()) == -1) {
            perror("Fork failed");
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
    perror("Accept failed");
    exit(EXIT_FAILURE);
#endif
}
