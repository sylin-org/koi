// A two-second native Wayland focus probe, using installed libevdev. Run as the
// desktop user only after activating the evaluation window. Only Tab is enabled;
// no text, Enter, pointer action, listener, daemon or persistent input device.
#include <libevdev/libevdev.h>
#include <libevdev/libevdev-uinput.h>
#include <stdio.h>
#include <unistd.h>

int main(void) {
    struct libevdev *device = libevdev_new();
    struct libevdev_uinput *input = NULL;
    int result = 1;
    if (!device) return result;
    libevdev_set_name(device, "Koi R06 temporary Tab-only probe");
    if (libevdev_enable_event_type(device, EV_KEY) < 0 ||
        libevdev_enable_event_code(device, EV_KEY, KEY_TAB, NULL) < 0 ||
        libevdev_uinput_create_from_device(device,
            LIBEVDEV_UINPUT_OPEN_MANAGED, &input) < 0) goto cleanup;
    sleep(1); // Let the compositor discover the temporary input device.
    if (libevdev_uinput_write_event(input, EV_KEY, KEY_TAB, 1) < 0 ||
        libevdev_uinput_write_event(input, EV_SYN, SYN_REPORT, 0) < 0 ||
        libevdev_uinput_write_event(input, EV_KEY, KEY_TAB, 0) < 0 ||
        libevdev_uinput_write_event(input, EV_SYN, SYN_REPORT, 0) < 0) goto cleanup;
    sleep(1);
    result = 0;
cleanup:
    if (input) libevdev_uinput_destroy(input);
    libevdev_free(device);
    if (result) fputs("Native Tab probe failed; no focus claim.\n", stderr);
    return result;
}
