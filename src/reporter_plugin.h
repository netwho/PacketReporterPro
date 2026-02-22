#ifndef REPORTER_PLUGIN_H
#define REPORTER_PLUGIN_H

#include <glib.h>
#include <epan/epan.h>

#define WS_LOG_DOMAIN "packetreporterpro"
#define PLUGIN_VERSION_STR "v0.1.1"

extern int proto_packet_reporter_pro;

void proto_register_packet_reporter_pro(void);
void proto_reg_handoff_packet_reporter_pro(void);

#endif /* REPORTER_PLUGIN_H */
