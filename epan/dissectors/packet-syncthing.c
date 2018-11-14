/* packet-protobuf.c
 * Routines for Syncthing Local Discovery Protocol v4
 * Copyright 2018, Antoine d'Otreppe <a.dotreppe@aspyct.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <glib.h>
#include <epan/expert.h>
#include <epan/packet.h>
#include <epan/tvbuff.h>

#define SYNCTHING_LOCAL_DISCOVERY_PORT 21027

typedef struct {
    tvbuff_t *tvb;
    packet_info *pinfo;
    proto_tree *tree;
    
    int machine_id_count;
    int instance_id_count;
    int addresses_count;
} syncthing_local_discovery_summary;
// We all live in a yellow summary!


/* Internal functions */
// TODO: start_offset and offset are poorly namedTODO
static gint dissect_next_field(syncthing_local_discovery_summary *summary, guint offset);
static gint dissect_machine_id(syncthing_local_discovery_summary *summary, guint start_offset, guint offset);
static gint dissect_address(syncthing_local_discovery_summary *summary, guint start_offset, guint offset);
static gint dissect_instance_id(syncthing_local_discovery_summary *summary, guint start_offset, guint offset);

/* Protocols */
void proto_register_syncthing(void);

static int proto_syncthing_local_discovery = -1;

/* Fields */
static int hf_syncthing_local_magic = -1;
static int hf_syncthing_local_machine_id = -1;
static int hf_syncthing_local_address = -1;
static int hf_syncthing_local_instance_id = -1;

/* Trees */
static gint ett_syncthing_local = -1;
static gint ett_syncthing_local_machine_id = -1;
static gint ett_syncthing_local_address = -1;
static gint ett_syncthing_local_instance_id = -1;

/* Expert infos */
// TODO: static expert_field ei_syncthing_local_malformed = EI_INIT;


static int
dissect_syncthing_local_discovery(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    g_print("Dissecting a new packet\n");

    // The first four bytes are 0x2EA7D90B in networ.k (big endian) byte order.
    if (tvb_bytes_exist(tvb, 0, 4)) {
        guint32 magic = tvb_get_ntohl(tvb, 0);
    
        if (magic == 0x2EA7D90B) {
            // Ok, this looks like a syncthing local discovery packet
            col_set_str(pinfo->cinfo, COL_PROTOCOL, "Syncthing");
            col_clear(pinfo->cinfo, COL_INFO);


            proto_item *ti = proto_tree_add_item(tree, proto_syncthing_local_discovery, tvb, 0,-1, ENC_NA);
            proto_tree *syncthing_tree = proto_item_add_subtree(ti, ett_syncthing_local);
            proto_tree_add_item(syncthing_tree, hf_syncthing_local_magic, tvb, 0, 4, ENC_BIG_ENDIAN);

            guint offset = 4;
            syncthing_local_discovery_summary summary = { tvb, pinfo, tree, 0, 0, 0 };

            while (offset < tvb_reported_length(tvb)) {
                gint data_used = dissect_next_field(&summary, offset);

                g_print("data_used = %i\n", data_used);

                if (data_used != -1) {
                    offset += data_used;
                }
                else {
                    // TODO: Handle this error
                    return offset;
                }
            }

            return tvb_captured_length(tvb);
        }
    }

    return 0;
}

static gint
dissect_next_field(syncthing_local_discovery_summary *summary, guint start_offset)
{
    g_print("Dissecting next field\n");

    gint varint_length;
    guint64 key;
	
    guint offset = start_offset;
    varint_length = tvb_get_varint(summary->tvb, offset, 4, &key, ENC_VARINT_PROTOBUF);
    if (varint_length != 0) {
        offset += varint_length;

        int wire_type = key & 0x07;
        int tag = key >> 3;

        g_print("wire_type: %i\n", wire_type);
        g_print("tag: %i\n", tag);

        /*
        * The format is defined as follows:
        * message Announce {
        *   bytes           id          = 1;
        *   repeated string addresses   = 2;
        *   int64           instance_id = 3;
        * }
        */

       // TODO: Replace this switch with an array
        gint result;
        switch (tag)
        {
            case 1:
                if (wire_type != 2) {
                    // Not a length-delimited field.
                    // TOOD: Add expert info
                    return -1;
                }

                result = dissect_machine_id(summary, start_offset, offset);
                break;
            case 2:
                if (wire_type != 2) {
                    // Not a length-delimited field.
                    // TODO: Add expert info
                    return -1;
                }

                result = dissect_address(summary, start_offset, offset);
                break;
            case 3:
                if (wire_type != 0) {
                    // Not a varint.
                    // TODO: Add expert info
                    return -1;
                }
                result = dissect_instance_id(summary, start_offset, offset);
                break;
            default:
                result = -1;
                break;
        }

        // TODO: Add expert info
        g_print("result = %i\n", result);
        if (result != -1) {
            return (offset + result) - start_offset;
        }
        else {
            return -1;
        }
    }

    // TODO: Add expert info
    g_print("Invalid varint at beginning of field\n");
    return -1;
}

gint
dissect_machine_id(syncthing_local_discovery_summary *summary, guint start_offset _U_, guint offset)
{
    g_print("Dissecting machine id\n");
    
    guint varint_length;
    guint64 field_length;

    varint_length = tvb_get_varint(summary->tvb, offset, 4, &field_length, ENC_VARINT_PROTOBUF);
    if (varint_length != 0) {
        offset += varint_length;
        summary->machine_id_count += 1;

        const guint8 *buf = tvb_get_ptr(summary->tvb, offset, field_length);
        proto_tree_add_bytes(summary->tree, hf_syncthing_local_machine_id, summary->tvb, offset, field_length, buf);

        return varint_length + field_length;
    }
    else {
        // TODO: Add expert info
        return -1;
    }
}

gint
dissect_address(syncthing_local_discovery_summary *summary, guint start_offset _U_, guint offset)
{
    g_print("Dissecting address\n");

    guint varint_length;
    guint64 field_length;

    varint_length = tvb_get_varint(summary->tvb, offset, 4, &field_length, ENC_VARINT_PROTOBUF);
    if (varint_length != 0) {
        offset += varint_length;
        summary->addresses_count += 1;

        guint8 *buf = (guint8*) wmem_alloc(wmem_packet_scope(), field_length + 1);
        tvb_get_nstringz0(summary->tvb, offset, field_length + 1, buf);
        proto_tree_add_string(summary->tree, hf_syncthing_local_address, summary->tvb, offset, field_length, buf);

        return varint_length + field_length;
    }
    else {
        // TODO: Add expert info
        return -1;
    }
}

gint
dissect_instance_id(syncthing_local_discovery_summary *summary, guint start_offset _U_, guint offset)
{
    g_print("Dissecting instance_id\n");

    gint varint_length;
    gint64 instance_id;

    // The maximum byte length of a int64 in varint can reach 10
    varint_length = tvb_get_varint(summary->tvb, offset, 10, &instance_id, ENC_VARINT_PROTOBUF);
    if (varint_length != 0)
    {
        summary->instance_id_count += 1;
        proto_tree_add_int64(summary->tree, hf_syncthing_local_instance_id, summary->tvb, offset, varint_length, instance_id);

        return varint_length;
    }
    else {
        // Could not read the instance ID as a varint
        // TODO: Add expert info
        return -1;
    }
}

void
proto_register_syncthing(void)
{
    static hf_register_info hf[] = {
        { &hf_syncthing_local_magic,
            { "Magic (constant)", "syncthing.local.magic",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_syncthing_local_machine_id,
            { "ID", "syncthing.local.machine_id",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_syncthing_local_address,
            { "Sync Service Address", "syncthing.local.address",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_syncthing_local_instance_id,
            { "Instance ID", "syncthing.local.instance_id",
            FT_INT64, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        }
    };

    static gint *ett[] = {
        &ett_syncthing_local,
        &ett_syncthing_local_machine_id,
        &ett_syncthing_local_address,
        &ett_syncthing_local_instance_id
    };

    proto_syncthing_local_discovery = proto_register_protocol(
        "Syncthing Local Discovery Protocol v4",
        "Syncthing",
        "syncthing.local"
    );

    proto_register_field_array(proto_syncthing_local_discovery, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_syncthing(void)
{
    static dissector_handle_t syncthing_local_discovery_handle;

    syncthing_local_discovery_handle = create_dissector_handle(
        dissect_syncthing_local_discovery,
        proto_syncthing_local_discovery
    );

    dissector_add_uint(
        "udp.port",
        SYNCTHING_LOCAL_DISCOVERY_PORT,
        syncthing_local_discovery_handle
    );
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
