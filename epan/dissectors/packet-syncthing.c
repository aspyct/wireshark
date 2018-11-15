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

typedef const struct {
    tvbuff_t *tvb;
    packet_info *pinfo;
    proto_tree *tree;
} syncthing_local_discovery_summary;
// We all live in a yellow summary!

typedef gint (*syncthing_protobuf_field_handler)(syncthing_local_discovery_summary *summary, proto_item *header, guint offset);

typedef const struct {
    int tag;
    int wire_type;
    syncthing_protobuf_field_handler handler;
    int ett;
} syncthing_protobuf_field_definition;


/* Protocols */
/* Yeah ok, there's only one right now, but syncthing has 4 of them, so maybe later */
void proto_register_syncthing(void);
static int proto_syncthing_local_discovery = -1;


/* Fields */
static int hf_syncthing_protobuf_entry = -1;
static int hf_syncthing_protobuf_key = -1;
static int hf_syncthing_protobuf_field_length = -1;
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


gint
dissect_machine_id(syncthing_local_discovery_summary *summary, proto_item *header _U_, guint offset)
{
    guint varint_length;
    guint64 field_length;

    varint_length = tvb_get_varint(summary->tvb, offset, 4, &field_length, ENC_VARINT_PROTOBUF);
    if (varint_length != 0) {
        offset += varint_length;

        const guint8 *buf = tvb_get_ptr(summary->tvb, offset, field_length);

        // TODO: Format ID
        proto_tree_add_bytes(summary->tree, hf_syncthing_local_machine_id, summary->tvb, offset, field_length, buf);
        proto_item_set_text(header, "Machine ID: <TODO>");

        return varint_length + field_length;
    }
    else {
        // TODO: Add expert info
        return -1;
    }
}

gint
dissect_address(syncthing_local_discovery_summary *summary, proto_item *header _U_, const guint start_offset)
{
    guint varint_length;
    guint64 field_length;
    guint offset = start_offset;

    varint_length = tvb_get_varint(summary->tvb, offset, 4, &field_length, ENC_VARINT_PROTOBUF);
    if (varint_length != 0) {
        offset += varint_length;

        proto_tree_add_uint64(
            summary->tree,
            hf_syncthing_protobuf_field_length,
            summary->tvb,
            start_offset,
            varint_length,
            field_length
        );

        guint8 *buf = (guint8*) wmem_alloc(wmem_packet_scope(), field_length + 1);
        tvb_get_nstringz0(summary->tvb, offset, field_length + 1, buf);
        proto_tree_add_string(summary->tree, hf_syncthing_local_address, summary->tvb, offset, field_length, buf);

        // TODO: Can I reuse the labels I put in the hf fields?
        proto_item_set_text(header, "Sync address: %s", buf);

        // TODO: Is it correct to free this here?
        wmem_free(wmem_packet_scope(), buf);

        return varint_length + field_length;
    }
    else {
        // TODO: Add expert info
        return -1;
    }
}

gint
dissect_instance_id(syncthing_local_discovery_summary *summary, proto_item *header _U_, guint offset)
{
    gint varint_length;
    gint64 instance_id;

    // The maximum byte length of a int64 in varint can reach 10
    varint_length = tvb_get_varint(summary->tvb, offset, 10, &instance_id, ENC_VARINT_PROTOBUF);
    if (varint_length != 0)
    {
        // TODO: How should I display this instance ID?
        // Check with the guys from syncthing
        proto_tree_add_int64(summary->tree, hf_syncthing_local_instance_id, summary->tvb, offset, varint_length, instance_id);
        proto_item_set_text(header, "Instance ID: %li", instance_id);
        return varint_length;
    }
    else {
        // Could not read the instance ID as a varint
        // TODO: Add expert info
        return -1;
    }
}

static gint
dissect_protobuf_field(
    const syncthing_local_discovery_summary * summary,
    const guint start_offset,
    const syncthing_protobuf_field_definition *definitions,
    const int defcount)
{
    gint varint_length;
    guint64 key;
    guint offset = start_offset;
	
    varint_length = tvb_get_varint(summary->tvb, offset, 4, &key, ENC_VARINT_PROTOBUF);
    if (varint_length != 0) {
        offset += varint_length;

        const int tag = key >> 3;
        int wire_type = key & 0x07;

        for (int i = 0; i < defcount; ++i) {
            syncthing_protobuf_field_definition *def = &definitions[i];

            if (tag == def->tag) {
                if (wire_type == def->wire_type) {
                    // TODO: This is a lot of ifs. Can I make it flatter?

                    proto_item *header = proto_tree_add_item(
                        summary->tree,
                        hf_syncthing_protobuf_entry,
                        summary->tvb,
                        start_offset,
                        0, // don't know yet,
                        ENC_NA
                    );
                    proto_tree *subtree = proto_item_add_subtree(header, def->ett);

                    // TODO: This should probably be a bit field or something?
                    // Or a subtree itself
                    proto_tree_add_uint64(subtree, hf_syncthing_protobuf_key, summary->tvb, start_offset, varint_length, key);

                    syncthing_local_discovery_summary subsummary = { summary->tvb, summary->pinfo, subtree };
                    gint result = def->handler(&subsummary, header, offset);

                    proto_item_set_len(header, varint_length + result);
                    return varint_length + result;
                }
                else {
                    // TODO: Add expert info
                    return -1;
                }
            }
        }
    }

    // TODO: Invalid varint. Add expert info
    return -1;
}

static gint
dissect_next_field(syncthing_local_discovery_summary *summary, guint offset)
{
    /*
    * The format is defined as follows:
    * message Announce {
    *   bytes           id          = 1;
    *   repeated string addresses   = 2;
    *   int64           instance_id = 3;
    * }
    */

    // TODO: This should be initialized only once, maybe in the proto_register_syncthing?
    syncthing_protobuf_field_definition field_definitions[] = {
        /* { tag, wire_type, handler, ett, label } */
        { 1, 2, &dissect_machine_id, ett_syncthing_local_machine_id },
        { 2, 2, &dissect_address, ett_syncthing_local_address },
        { 3, 0, &dissect_instance_id, ett_syncthing_local_instance_id }
    };

    return dissect_protobuf_field(summary, offset, field_definitions, sizeof(field_definitions));
}

static int
dissect_syncthing_local_discovery(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
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
            syncthing_local_discovery_summary summary = { tvb, pinfo, syncthing_tree };

            while (offset < tvb_reported_length(tvb)) {
                gint data_used = dissect_next_field(&summary, offset);

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

void
proto_register_syncthing(void)
{
    static hf_register_info hf[] = {
        { &hf_syncthing_protobuf_entry,
            { "Protobuf entry", "syncthing.protobuf.entry",
            FT_STRINGZ, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_syncthing_protobuf_key,
            { "Protobuf key", "syncthing.protobuf.key",
            FT_UINT64, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_syncthing_protobuf_field_length,
            { "Protobuf field length", "syncthing.protobuf.length",
            FT_UINT64, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
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
            { "Sync address", "syncthing.local.address",
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
