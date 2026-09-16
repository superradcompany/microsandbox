/* Test-only Linux preload shim. Never link this into the product.
 * It delays one immutable-object read on a checkpoint reader, while the real
 * VMM and launcher run normally. Configuration is consumed only by this shim.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static ssize_t (*next_read)(int, void *, size_t);
static ssize_t (*next_pread)(int, void *, size_t, off_t);
static ssize_t (*next_pread64)(int, void *, size_t, off64_t);
static ssize_t (*next_write)(int, const void *, size_t);
static const char *fixture_prefix;
static const char *trace_path;
static unsigned delay_ms;
static int inject_error;
static atomic_int delayed;
static int trace_fd = -1;

static unsigned long long monotonic_ns(void) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (unsigned long long)now.tv_sec * 1000000000ULL + now.tv_nsec;
}

static void trace_bytes(const char *bytes, size_t length) {
    if (trace_fd >= 0) {
        /* Raw write cannot recursively enter our startup-frame interceptor. */
        syscall(SYS_write, trace_fd, bytes, length);
    }
}

static void trace_delay(const char *event, int fd, const char *path) {
    char line[PATH_MAX + 256];
    int length = snprintf(line, sizeof(line),
        "{\"event\":\"%s\",\"pid\":%ld,\"tid\":%ld,\"monotonic_ns\":%llu,"
        "\"fd\":%d,\"path\":\"%s\"}\n",
        event, (long)getpid(), (long)syscall(SYS_gettid), monotonic_ns(), fd, path);
    if (length > 0 && (size_t)length < sizeof(line)) {
        trace_bytes(line, (size_t)length);
    }
}

__attribute__((constructor)) static void initialize(void) {
    next_read = dlsym(RTLD_NEXT, "read");
    next_pread = dlsym(RTLD_NEXT, "pread");
    next_pread64 = dlsym(RTLD_NEXT, "pread64");
    next_write = dlsym(RTLD_NEXT, "write");
    fixture_prefix = getenv("MSB_TEST_EAGER_PREFIX");
    trace_path = getenv("MSB_TEST_EAGER_TRACE");
    const char *configured = getenv("MSB_TEST_EAGER_DELAY_MS");
    const char *mode = getenv("MSB_TEST_EAGER_MODE");
    unsigned long parsed = configured ? strtoul(configured, NULL, 10) : 0;
    /* The bounded test cannot accidentally install an indefinite I/O stall. */
    if (fixture_prefix && fixture_prefix[0] == '/' && trace_path && parsed <= 45000) {
        delay_ms = (unsigned)parsed;
        inject_error = mode && !strcmp(mode, "error");
        trace_fd = open(trace_path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0600);
    }
}

static int maybe_intercept(int fd) {
    if ((!delay_ms && !inject_error) || trace_fd < 0 || atomic_load(&delayed)) {
        return 0;
    }
    char name[16] = {0};
    /* Linux truncates Rust's "checkpoint-reader" name to fifteen bytes. No
     * SDK manifest read, guest disk I/O, or unrelated process is slowed. */
    if (prctl(PR_GET_NAME, name, 0, 0, 0) || strcmp(name, "checkpoint-read")) {
        return 0;
    }
    char descriptor[64], path[PATH_MAX];
    snprintf(descriptor, sizeof(descriptor), "/proc/self/fd/%d", fd);
    ssize_t length = readlink(descriptor, path, sizeof(path) - 1);
    if (length <= 0) {
        return 0;
    }
    path[length] = 0;
    size_t prefix_len = strlen(fixture_prefix);
    if (strncmp(path, fixture_prefix, prefix_len) || path[prefix_len] != '/' ||
        !strstr(path + prefix_len, "/objects/") || strchr(path, '"') || strchr(path, '\n')) {
        return 0;
    }
    int expected = 0;
    if (!atomic_compare_exchange_strong(&delayed, &expected, 1)) {
        return 0;
    }
    if (inject_error) {
        trace_delay("read_error", fd, path);
        errno = EIO;
        return 1;
    }
    int saved_errno = errno;
    trace_delay("delay_begin", fd, path);
    struct timespec remaining = {.tv_sec = delay_ms / 1000,
                                 .tv_nsec = (long)(delay_ms % 1000) * 1000000};
    while (nanosleep(&remaining, &remaining) && errno == EINTR) {}
    trace_delay("delay_end", fd, path);
    errno = saved_errno;
    return 0;
}

ssize_t read(int fd, void *bytes, size_t length) {
    if (maybe_intercept(fd)) return -1;
    return next_read ? next_read(fd, bytes, length) : syscall(SYS_read, fd, bytes, length);
}

ssize_t pread(int fd, void *bytes, size_t length, off_t offset) {
    if (maybe_intercept(fd)) return -1;
    return next_pread ? next_pread(fd, bytes, length, offset)
                      : syscall(SYS_pread64, fd, bytes, length, offset);
}

ssize_t pread64(int fd, void *bytes, size_t length, off64_t offset) {
    if (maybe_intercept(fd)) return -1;
    return next_pread64 ? next_pread64(fd, bytes, length, offset)
                        : syscall(SYS_pread64, fd, bytes, length, offset);
}

ssize_t write(int fd, const void *bytes, size_t length) {
    ssize_t result = next_write ? next_write(fd, bytes, length)
                                : syscall(SYS_write, fd, bytes, length);
    int saved_errno = errno;
    /* Record successfully delivered startup frames, not ordinary log text.
     * The observer cannot affect telemetry or create an activation signal. */
    if (trace_fd >= 0 && result == (ssize_t)length && result > 0 && length < 4096 &&
        length >= 10 && !memcmp(bytes, "{\"phase\":", 9)) {
        char line[4608];
        size_t written = (size_t)result;
        while (written && (((const char *)bytes)[written - 1] == '\n' ||
                           ((const char *)bytes)[written - 1] == '\r')) --written;
        int count = snprintf(line, sizeof(line),
            "{\"event\":\"startup\",\"pid\":%ld,\"monotonic_ns\":%llu,\"progress\":%.*s}\n",
            (long)getpid(), monotonic_ns(), (int)written, (const char *)bytes);
        if (count > 0 && (size_t)count < sizeof(line)) {
            trace_bytes(line, (size_t)count);
        }
    }
    errno = saved_errno;
    return result;
}
