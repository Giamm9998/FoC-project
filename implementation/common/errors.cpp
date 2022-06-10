#include "errors.h"
#include <openssl/err.h>
#include <stdio.h>

void handle_errors() {
    ERR_print_errors_fp(stderr);
    throw "OPENSSL error occurred";
}
