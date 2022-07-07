#include "seq.h"
#include "types.h"
#include <signal.h>
#include <unistd.h>

seqnum seq_num = 0;

#define LOGOUT_THRESHOLD 5
void check_wraparound() {
    if (seq_num + 1 > (SEQNUM_MAX - LOGOUT_THRESHOLD))
        kill(getpid(), SIGUSR1);
}

seqnum inc_seqnum() {
    check_wraparound();
    seq_num++;
    return seq_num;
}

unsigned char *seqnum_to_uc() { return (unsigned char *)&seq_num; }
