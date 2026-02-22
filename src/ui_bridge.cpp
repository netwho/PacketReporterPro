#include "ui_bridge.h"
#include "pro_window.h"

#include <QApplication>
#include <QDebug>
#include <wsutil/wslog.h>
#include <epan/plugin_if.h>
#include <cfile.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

#define WS_LOG_DOMAIN "packetreporterpro"

static ProWindow *g_pro_window = NULL;
static bool g_quit_connected = false;

static void destroy_pro_window()
{
    if (g_pro_window) {
        g_pro_window->hide();
        delete g_pro_window;
        g_pro_window = NULL;
    }
}

static void *extract_cf_cb(capture_file *cf, void *user_data)
{
    (void)user_data;
    return (void *)cf;
}

static capture_file *resolve_capture_file(capture_file *cf_hint)
{
    if (cf_hint && cf_hint->count > 0)
        return cf_hint;

    capture_file *cf = (capture_file *)
        plugin_if_get_capture_file(extract_cf_cb, NULL);
    if (cf && cf->count > 0)
        return cf;

#ifdef _WIN32
    void *sym = (void *)GetProcAddress(GetModuleHandle(NULL), "cfile");
#else
    void *sym = dlsym(RTLD_DEFAULT, "cfile");
#endif
    if (sym)
        return (capture_file *)sym;

    return cf_hint;
}

#ifdef __cplusplus
extern "C" {
#endif

void reporter_pro_open_window(capture_file *cf)
{
    if (!QApplication::instance()) {
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING,
               "No QApplication instance — cannot open window");
        return;
    }

    cf = resolve_capture_file(cf);

    if (!g_pro_window) {
        g_pro_window = new ProWindow(NULL);

        /*
         * Clean up BEFORE plugin unload.
         *
         * aboutToQuit fires while QApplication::exec() is still
         * returning, i.e. before Wireshark calls epan_cleanup()
         * which unloads plugin .so files.  This avoids the crash
         * caused by qAddPostRoutine (which runs during
         * ~QApplication, AFTER our code has been dlclose'd).
         */
        if (!g_quit_connected) {
            QObject::connect(qApp, &QCoreApplication::aboutToQuit,
                             []() { destroy_pro_window(); });
            g_quit_connected = true;
        }
    }

    g_pro_window->setCaptureFile(cf);

    g_pro_window->show();
    g_pro_window->raise();
    g_pro_window->activateWindow();
}

void reporter_pro_close_window(void)
{
    destroy_pro_window();
}

#ifdef __cplusplus
}
#endif
