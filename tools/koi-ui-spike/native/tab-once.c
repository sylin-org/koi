// A two-second native Wayland focus probe, using installed libevdev. Run as the
// desktop user only after activating the evaluation window. Only Tab (or explicit
// --page-down for the card capture) is enabled;
// no text, Enter, pointer action, listener, daemon or persistent input device.
#include <libevdev/libevdev.h>
#include <libevdev/libevdev-uinput.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    int key = KEY_TAB;
    if (argc == 2 && strcmp(argv[1], "--page-down") == 0) key = KEY_PAGEDOWN;
    else if (argc != 1) return 2;
    struct libevdev *device = libevdev_new();
    struct libevdev_uinput *input = NULL;
    int result = 1;
    if (!device) return result;
    libevdev_set_name(device, "Koi R06 temporary navigation-only probe");
    if (libevdev_enable_event_type(device, EV_KEY) < 0 ||
        libevdev_enable_event_code(device, EV_KEY, key, NULL) < 0 ||
        libevdev_uinput_create_from_device(device,
            LIBEVDEV_UINPUT_OPEN_MANAGED, &input) < 0) goto cleanup;
    sleep(1); // Let the compositor discover the temporary input device.
    if (libevdev_uinput_write_event(input, EV_KEY, key, 1) < 0 ||
        libevdev_uinput_write_event(input, EV_SYN, SYN_REPORT, 0) < 0 ||
        libevdev_uinput_write_event(input, EV_KEY, key, 0) < 0 ||
        libevdev_uinput_write_event(input, EV_SYN, SYN_REPORT, 0) < 0) goto cleanup;
    sleep(1);
    result = 0;
cleanup:
    if (input) libevdev_uinput_destroy(input);
    libevdev_free(device);
    if (result) fputs("Native Tab probe failed; no focus claim.\n", stderr);
    return result;
}
