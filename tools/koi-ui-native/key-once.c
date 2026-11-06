// Bounded navigation/search input. Run as the desktop user after activating Koi.
// Text is at most 80 lowercase ASCII letters, digits, spaces or hyphens.
// No modifiers, pointer, listener, service or persistent input device.
#include <libevdev/libevdev.h>
#include <libevdev/libevdev-uinput.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int text_key(char c) {
    static const int letters[] = {KEY_A, KEY_B, KEY_C, KEY_D, KEY_E, KEY_F,
        KEY_G, KEY_H, KEY_I, KEY_J, KEY_K, KEY_L, KEY_M, KEY_N, KEY_O, KEY_P,
        KEY_Q, KEY_R, KEY_S, KEY_T, KEY_U, KEY_V, KEY_W, KEY_X, KEY_Y, KEY_Z};
    if (c >= 'a' && c <= 'z') return letters[c - 'a'];
    if (c >= '1' && c <= '9') return KEY_1 + c - '1';
    if (c == '0') return KEY_0;
    if (c == ' ') return KEY_SPACE;
    if (c == '-') return KEY_MINUS;
    return -1;
}

int main(int argc, char **argv) {
    int key = KEY_TAB;
    int count = 1;
    if (argc < 2 || argc > 3) return 2;
    const char *text = NULL;
    if (strcmp(argv[1], "text") == 0) {
        if (argc != 3 || !strlen(argv[2]) || strlen(argv[2]) > 80) return 2;
        text = argv[2];
        count = (int)strlen(text);
        for (int i = 0; i < count; ++i) if (text_key(text[i]) < 0) return 2;
    }
    else if (strcmp(argv[1], "tab") == 0) key = KEY_TAB;
    else if (strcmp(argv[1], "enter") == 0) key = KEY_ENTER;
    else if (strcmp(argv[1], "home") == 0) key = KEY_HOME;
    else if (strcmp(argv[1], "end") == 0) key = KEY_END;
    else return 2;
    if (argc == 3 && !text) {
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
    if (libevdev_enable_event_type(device, EV_KEY) < 0) goto cleanup;
    for (int i = 0; i < count; ++i)
        if (libevdev_enable_event_code(device, EV_KEY, text ? text_key(text[i]) : key, NULL) < 0) goto cleanup;
    if (libevdev_uinput_create_from_device(device, LIBEVDEV_UINPUT_OPEN_MANAGED, &input) < 0) goto cleanup;
    sleep(1);
    for (int i = 0; i < count; ++i) {
        if (text) key = text_key(text[i]);
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
