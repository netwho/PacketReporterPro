#include <config.h>
#include <wireshark.h>

#include "reporter_plugin.h"
#include "packet_collector.h"
#include "ui_bridge.h"

#include <epan/epan_dissect.h>
#include <epan/proto.h>
#include <epan/tap.h>
#include <epan/plugin_if.h>
#include <wsutil/wslog.h>
#include <cfile.h>

int proto_packet_reporter_pro = -1;

static ext_menu_t *reporter_menu = NULL;

/* ----------------------------------------------------------------
 * Helper: extract capture_file from plugin_if callback
 * ---------------------------------------------------------------- */
static void *extract_capture_file_cb(capture_file *cf,
                                     void *user_data G_GNUC_UNUSED)
{
    return (void *)cf;
}

/* ----------------------------------------------------------------
 * Menu callback — opens the main window
 * ---------------------------------------------------------------- */

static void open_pro_window_cb(ext_menubar_gui_type gui_type G_GNUC_UNUSED,
                                void *gui_object G_GNUC_UNUSED,
                                void *user_data G_GNUC_UNUSED)
{
    capture_file *cf;

    cf = (capture_file *)plugin_if_get_capture_file(extract_capture_file_cb, NULL);

    if (cf) {
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO,
               "Opening PacketReporter Pro window (capture: %u packets)",
               cf->count);
    } else {
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING,
               "Opening PacketReporter Pro window (no capture loaded)");
    }

    reporter_pro_open_window(cf);
}

/* ----------------------------------------------------------------
 * Plugin registration — called by auto-generated plugin.c
 * ---------------------------------------------------------------- */
void proto_register_packet_reporter_pro(void)
{
    int existing_id;

    existing_id = proto_get_id_by_filter_name("packetreporterpro");
    if (existing_id != -1) {
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING,
               "PacketReporter Pro already registered (id=%d); skipping",
               existing_id);
        proto_packet_reporter_pro = existing_id;
        return;
    }

    proto_packet_reporter_pro = proto_register_protocol(
        "PacketReporter Pro " PLUGIN_VERSION_STR
        " (Author & Architect: Walter Hofstetter, "
        "AI-Assisted: yes (Claude) -- build system, installers, cross-platform, docs; "
        "Repo: https://github.com/netwho/PacketReporterPro)",
        "PacketReporter Pro",
        "packetreporterpro"
    );

    reporter_menu = ext_menubar_register_menu(
        proto_packet_reporter_pro,
        "PacketReporter Pro",
        TRUE
    );

    ext_menubar_set_parentmenu(reporter_menu, "Tools");

    ext_menubar_add_entry(reporter_menu,
        "Open PacketReporter Pro",
        "Open the PacketReporter Pro window to customize and generate reports",
        open_pro_window_cb, NULL);

    packet_collector_init();

    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO,
           "PacketReporter Pro plugin registered");
}

void proto_reg_handoff_packet_reporter_pro(void)
{
    /* Nothing needed at handoff time */
}
