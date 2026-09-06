// One temporary native pointer operation, never a daemon or browser controller.
// Caller must verify active Koi and (before click) pointer over an internal control.
#include <libevdev/libevdev.h>
#include <libevdev/libevdev-uinput.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int number(const char *text, long low, long high, int *value) {
    char *end;
    errno = 0;
    long parsed = strtol(text, &end, 10);
    if (errno || !*text || *end || parsed < low || parsed > high) return 0;
    *value = (int)parsed;
    return 1;
}

static int installed(int pid) {
    char path[64], executable[PATH_MAX];
    snprintf(path, sizeof(path), "/proc/%d/exe", pid);
    ssize_t length = readlink(path, executable, sizeof(executable) - 1);
    if (length < 0) return 0;
    executable[length] = '\0';
    return strcmp(executable, "/usr/bin/koi-desktop") == 0;
}

static int emit(struct libevdev_uinput *input, unsigned int type,
                unsigned int code, int value) {
    return libevdev_uinput_write_event(input, type, code, value) >= 0;
}

int main(int argc, char **argv) {
    int pid, dx = 0, dy = 0;
    if (argc < 3 || !number(argv[1], 1, INT_MAX, &pid)) return 2;
    int click = strcmp(argv[2], "click") == 0;
    if (click ? argc != 3 : (argc != 5 || strcmp(argv[2], "move") != 0 ||
        !number(argv[3], -2048, 2048, &dx) || !number(argv[4], -2048, 2048, &dy))) return 2;
    if (!installed(pid)) return 2;
    struct libevdev *device = libevdev_new();
    struct libevdev_uinput *input = NULL;
    int result = 1;
    if (!device) return result;
    libevdev_set_name(device, "Koi temporary native pointer probe");
    if (libevdev_enable_event_type(device, EV_KEY) < 0 ||
        libevdev_enable_event_code(device, EV_KEY, BTN_LEFT, NULL) < 0 ||
        libevdev_enable_event_type(device, EV_REL) < 0 ||
        libevdev_enable_event_code(device, EV_REL, REL_X, NULL) < 0 ||
        libevdev_enable_event_code(device, EV_REL, REL_Y, NULL) < 0 ||
        libevdev_uinput_create_from_device(device, LIBEVDEV_UINPUT_OPEN_MANAGED, &input) < 0) goto cleanup;
    sleep(1); // Allow the compositor to discover the short-lived device.
    if (!installed(pid)) goto cleanup;
    if (click) {
        if (!emit(input, EV_KEY, BTN_LEFT, 1) || !emit(input, EV_SYN, SYN_REPORT, 0)) goto cleanup;
        usleep(50000);
        if (!emit(input, EV_KEY, BTN_LEFT, 0) || !emit(input, EV_SYN, SYN_REPORT, 0)) goto cleanup;
    } else if (!emit(input, EV_REL, REL_X, dx) || !emit(input, EV_REL, REL_Y, dy) ||
               !emit(input, EV_SYN, SYN_REPORT, 0)) goto cleanup;
    usleep(200000);
    result = 0;
cleanup:
    if (input) {
        // Best-effort release even on an interrupted write; destruction is final.
        if (click) {
            emit(input, EV_KEY, BTN_LEFT, 0);
            emit(input, EV_SYN, SYN_REPORT, 0);
        }
        libevdev_uinput_destroy(input);
    }
    libevdev_free(device);
    if (result) fputs("Native pointer probe failed; no acceptance claim.\n", stderr);
    return result;
}
