// Read-only GTK3 observer. No window, settings write, daemon or network listener.
// Compile with pkg-config gtk+-3.0; run in the workbench's native session/backend.
#include <gtk/gtk.h>
#include <stdio.h>

static int observe(void) {
    GtkSettings *settings = gtk_settings_get_default();
    GdkScreen *screen = gdk_screen_get_default();
    GdkDisplay *display = gdk_display_get_default();
    if (!settings || !screen || !display) return 1;
    gboolean animations = TRUE;
    g_object_get(settings, "gtk-enable-animations", &animations, NULL);
    GValue value = G_VALUE_INIT;
    g_value_init(&value, G_TYPE_BOOLEAN);
    gboolean available = gdk_screen_get_setting(screen, "gtk-enable-animations", &value);
    printf("backend=%s gtk-enable-animations=%d gdk-setting-available=%d gdk-enable-animations=%d\n",
        G_OBJECT_TYPE_NAME(display), animations, available,
        available ? g_value_get_boolean(&value) : -1);
    fflush(stdout);
    g_value_unset(&value);
    return 0;
}
#ifdef MOTION_MODULE
static void changed(GObject *object, GParamSpec *spec, gpointer data) {
    (void)object; (void)spec; (void)data;
    observe();
}
void gtk_module_init(gint *argc, gchar ***argv) {
    (void)argc; (void)argv;
    observe();
    g_signal_connect(gtk_settings_get_default(), "notify::gtk-enable-animations",
        G_CALLBACK(changed), NULL);
}
#else
int main(int argc, char **argv) {
    if (!gtk_init_check(&argc, &argv)) {
        fputs("GTK display unavailable; no native preference evidence.\n", stderr);
        return 1;
    }
    return observe();
}
#endif
