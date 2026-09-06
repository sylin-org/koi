// Bounded navigation-only input. Run as the desktop user after activating Koi.
// No text, modifiers, pointer, listener, service or persistent input device.
#include <libevdev/libevdev.h>
#include <libevdev/libevdev-uinput.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    int key = KEY_TAB;
    int count = 1;
    if (argc < 2 || argc > 3) return 2;
    if (strcmp(argv[1], "tab") == 0) key = KEY_TAB;
    else if (strcmp(argv[1], "enter") == 0) key = KEY_ENTER;
    else if (strcmp(argv[1], "home") == 0) key = KEY_HOME;
    else if (strcmp(argv[1], "end") == 0) key = KEY_END;
    else return 2;
    if (argc == 3) {
        char *end;
        long parsed = strtol(argv[2], &end, 10);
        if (*end || parsed < 1 || parsed > 8 || key != KEY_TAB) return 2;
        count = (int)parsed;
    }
    struct libevdev *device = libevdev_new();
    struct libevdev_uinput *input = NULL;
    int result = 1;
    if (!device) return result;
    libevdev_set_name(device, "Koi shared-shell temporary navigation probe");
    if (libevdev_enable_event_type(device, EV_KEY) < 0 ||
        libevdev_enable_event_code(device, EV_KEY, key, NULL) < 0 ||
        libevdev_uinput_create_from_device(device, LIBEVDEV_UINPUT_OPEN_MANAGED, &input) < 0) goto cleanup;
    sleep(1);
    for (int i = 0; i < count; ++i) {
        if (libevdev_uinput_write_event(input, EV_KEY, key, 1) < 0 ||
            libevdev_uinput_write_event(input, EV_SYN, SYN_REPORT, 0) < 0 ||
            libevdev_uinput_write_event(input, EV_KEY, key, 0) < 0 ||
            libevdev_uinput_write_event(input, EV_SYN, SYN_REPORT, 0) < 0) goto cleanup;
        usleep(100000);
    }
    sleep(1);
    result = 0;
cleanup:
    if (input) libevdev_uinput_destroy(input);
    libevdev_free(device);
    if (result) fputs("Native navigation probe failed; no acceptance claim.\n", stderr);
    return result;
}
