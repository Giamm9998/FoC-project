#include "../common/common.h"
#include "authentication.h"
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

int sock;
unsigned char *shared_key;

void greet_user() {
    // Thanks to https://fsymbols.com/generators/carty/
    cout << "\
░█████╗░██╗░░░░░░█████╗░██╗░░░██╗██████╗░    ░██████╗████████╗░█████╗░██████╗░░█████╗░░██████╗░███████╗\n\
██╔══██╗██║░░░░░██╔══██╗██║░░░██║██╔══██╗    ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗██╔══██╗██╔════╝░██╔════╝\n\
██║░░╚═╝██║░░░░░██║░░██║██║░░░██║██║░░██║    ╚█████╗░░░░██║░░░██║░░██║██████╔╝███████║██║░░██╗░█████╗░░\n\
██║░░██╗██║░░░░░██║░░██║██║░░░██║██║░░██║    ░╚═══██╗░░░██║░░░██║░░██║██╔══██╗██╔══██║██║░░╚██╗██╔══╝░░\n\
╚█████╔╝███████╗╚█████╔╝╚██████╔╝██████╔╝    ██████╔╝░░░██║░░░╚█████╔╝██║░░██║██║░░██║╚██████╔╝███████╗\n\
░╚════╝░╚══════╝░╚════╝░░╚═════╝░╚═════╝░    ╚═════╝░░░░╚═╝░░░░╚════╝░╚═╝░░╚═╝╚═╝░░╚═╝░╚═════╝░╚══════╝"
         << endl
         << endl;
}

void print_menu() {
    cout << "Actions:" << endl;
    cout << "    list - List your files" << endl;
    cout << "    upload - Upload a new file" << endl;
    cout << "    rename - Rename a file" << endl;
    cout << "    delete - Delete a file" << endl;
    cout << "    exit - Terminate current session" << endl;
    cout << "> ";
}

/* Loop for the user to interact with the server. */
void interact() {
    unsigned char *key;
    string action;
    int key_len;

    key_len = get_symmetric_key_length();

    // First of all, the user must run the authentication protocol with the
    // other party (hopefully the server). The exchange also provides a shared
    // ephemeral key to use for further communications.
    shared_key = authenticate(sock, key_len);
#ifdef DEBUG
    print_shared_key(shared_key, key_len);
#endif

    // Interaction loop. The user can perform a set of actions, until he decides
    // to terminate the session.
    while (true) {
        print_menu();
        if (!getline(cin, action)) {
            cout << "Error reading input!" << endl;
        }

        if (action == "list") {
            // list_files(server_fd, key);
        } else if (action == "upload") {
            // upload_file(server_fd, key);
        } else if (action == "rename") {
            // rename_file(server_fd, key);
        } else if (action == "delete") {
            // delete_file(server_fd, key);
        } else if (action == "exit") {
            // gracefully_exit(server_fd, key);
        } else {
            cout << "Invalid action!" << endl;
        }
    }
}

int main() {
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
    interact();

    // Close socket when we are done
    close(sock);
}
