/* Disposable Linux guest PID1 for Stop qualification; not product code.
 * Build with musl-gcc -static -O2, mount its private directory at /test,
 * then use --init /test/delayed-poweroff-init --init-arg 12.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/reboot.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t requested;
static volatile sig_atomic_t got_term;

static void shutdown_signal(int signal) {
    if (signal == SIGTERM) got_term = 1;
    else requested = 1;
}

static int marker(const char *path) {
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    if (write(fd, "observed\n", 9) != 9 || fsync(fd)) {
        close(fd);
        return -1;
    }
    return close(fd);
}

int main(int argc, char **argv) {
    unsigned long delay = argc == 2 ? strtoul(argv[1], NULL, 10) : 12;
    if (getpid() != 1 || delay < 3 || delay > 30) return 2;
    struct sigaction action = {.sa_handler = shutdown_signal};
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGRTMIN + 4, &action, NULL) || sigaction(SIGTERM, &action, NULL)) return 3;
    if (marker("/test/init-ready")) return 4;
    /* Polling avoids a signal-delivery/pause race; this is an idle test PID1. */
    while (!requested) {
        struct timespec idle = {.tv_sec = 0, .tv_nsec = 10000000};
        nanosleep(&idle, NULL);
        while (waitpid(-1, NULL, WNOHANG) > 0) {}
    }
    if (marker("/test/shutdown-requested")) return 5;
    struct timespec remaining = {.tv_sec = (time_t)delay, .tv_nsec = 0};
    while (nanosleep(&remaining, &remaining) && errno == EINTR) {}
    if (got_term && marker("/test/unexpected-sigterm")) return 6;
    if (marker("/test/poweroff")) return 7;
    sync();
    if (reboot(RB_POWER_OFF)) {
        marker("/test/reboot-failed");
        /* Keep failed fixtures observable; do not manufacture success by exiting PID1. */
        for (;;) pause();
    }
    return 0;
}
