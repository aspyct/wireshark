/* packet-syncthing.c
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
#define MAX_VARINT_LENGTH 10

// TODO: Add an expert error?
#define CONSTRAIN_TO_GINT_OR_FAIL(constrained, minus) \
    if ((constrained) > G_MAXINT - (minus)) { \
        return -1;\
    }

typedef const struct {
    tvbuff_t *tvb;
    packet_info *pinfo;
    proto_tree *tree;
} syncthing_local_discovery_summary;
// We all live in a yellow summary!

typedef gint (*syncthing_protobuf_field_handler)(syncthing_local_discovery_summary *summary, proto_item *header, guint offset);

typedef const struct {
    guint64 tag;
    guint8 wire_type;
    syncthing_protobuf_field_handler handler;
    int ett;
} syncthing_protobuf_field_definition;


/* Protocols */
/* Yeah ok, there's only one right now, but syncthing has 4 of them, so maybe later */
void proto_register_syncthing(void);
static int proto_syncthing_local_discovery = -1;


/* Fields */
// TODO: For the sake of consistency, should I use gint everywhere?
static int hf_syncthing_protobuf_entry = -1;
static int hf_syncthing_protobuf_key = -1;
static int hf_syncthing_protobuf_tag = -1;
static int hf_syncthing_protobuf_wire_type = -1;
static int hf_syncthing_protobuf_field_length = -1;
static int hf_syncthing_local_magic = -1;
static int hf_syncthing_local_node_id = -1;
static int hf_syncthing_local_address = -1;
static int hf_syncthing_local_instance_id = -1;


/* Trees */
static gint ett_syncthing_local = -1;
static gint ett_syncthing_local_node_id = -1;
static gint ett_syncthing_local_address = -1;
static gint ett_syncthing_local_instance_id = -1;
static gint ett_syncthing_protobuf_key = -1;


/* Expert infos */
// TODO: static expert_field ei_syncthing_local_malformed = EI_INIT;


static gint
dissect_node_id(syncthing_local_discovery_summary *summary, proto_item *header, guint start_offset)
{
    guint varint_length;
    guint64 field_length;
    guint offset = start_offset;

    varint_length = tvb_get_varint(summary->tvb, offset, 4, &field_length, ENC_VARINT_PROTOBUF);
    if (varint_length != 0 && field_length <= G_MAXINT) {
        CONSTRAIN_TO_GINT_OR_FAIL(field_length, varint_length);
        gint buflen = (gint)field_length;

        offset += varint_length;

        proto_tree_add_uint64(
            summary->tree,
            hf_syncthing_protobuf_field_length,
            summary->tvb,
            start_offset,
            varint_length,
            field_length
        );

        const guint8 *buf = tvb_get_ptr(summary->tvb, offset, buflen);

        // TODO: Format ID
        proto_tree_add_bytes(summary->tree, hf_syncthing_local_node_id, summary->tvb, offset, buflen, buf);
        proto_item_set_text(header, "Node ID: <TODO>");

        return varint_length + buflen;
    }
    else {
        // TODO: invalid varint, add expert info
        return -1;
    }
}

static gint
dissect_address(syncthing_local_discovery_summary *summary, proto_item *header, const guint start_offset)
{
    guint varint_length;
    guint64 field_length;
    guint offset = start_offset;

    varint_length = tvb_get_varint(summary->tvb, offset, MAX_VARINT_LENGTH, &field_length, ENC_VARINT_PROTOBUF);
    if (varint_length != 0) {
        CONSTRAIN_TO_GINT_OR_FAIL(field_length, varint_length);
        gint buflen = (gint)field_length;

        offset += varint_length;

        proto_tree_add_uint64(
            summary->tree,
            hf_syncthing_protobuf_field_length,
            summary->tvb,
            start_offset,
            varint_length,
            field_length
        );

        guint8 *buf = (guint8*) wmem_alloc(wmem_packet_scope(), buflen + 1);
        tvb_get_nstringz0(summary->tvb, offset, buflen + 1, buf);
        proto_tree_add_string(summary->tree, hf_syncthing_local_address, summary->tvb, offset, buflen, buf);

        // TODO: Can I reuse the labels I put in the hf fields?
        proto_item_set_text(header, "Sync address: %s", buf);

        return varint_length + buflen;
    }
    else {
        // TODO: Add expert info
        return -1;
    }
}

static gint
dissect_instance_id(syncthing_local_discovery_summary *summary, proto_item *header, guint offset)
{
    gint varint_length;
    gint64 instance_id;

    varint_length = tvb_get_varint(summary->tvb, offset, MAX_VARINT_LENGTH, &instance_id, ENC_VARINT_PROTOBUF);
    if (varint_length != 0)
    {
        proto_tree_add_int64(summary->tree, hf_syncthing_local_instance_id, summary->tvb, offset, varint_length, instance_id);
        proto_item_set_text(header, "Instance ID: %" G_GINT64_MODIFIER "i", instance_id);
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

    if (varint_length == 0) {
        // TODO: Invalid varint. Add expert info
        return -1;
    }

    offset += varint_length;

    const guint64 tag = key >> 3;
    guint8 wire_type = key & 0x07;

    for (int i = 0; i < defcount; ++i) {
        syncthing_protobuf_field_definition *def = &definitions[i];

        if (tag != def->tag) {
            // This definition doesn't handle the current tag, try the next one
            continue;
        }

        if (wire_type != def->wire_type) {
            // Unexpected wire type, packet is invalid
            // TODO: Add expert info
            return -1;
        }

        // TODO: This results in a weird filter
        // syncthing.protobuf.entry == "[Empty]"
        // Can we fix this once we have the length?
        proto_item *header = proto_tree_add_item(
            summary->tree,
            hf_syncthing_protobuf_entry,
            summary->tvb,
            start_offset,
            0, // we'll know it after parsing the field
            ENC_NA
        );
        proto_tree *subtree = proto_item_add_subtree(header, def->ett);

        proto_item *key_item = proto_tree_add_uint64_format(
            subtree,
            hf_syncthing_protobuf_key,
            summary->tvb,
            start_offset,
            varint_length,
            key,
            "Protobuf Key, ID: %" G_GINT64_MODIFIER "i, Wire type: %i",
            tag, wire_type
        );
        proto_item *key_tree = proto_item_add_subtree(key_item, ett_syncthing_protobuf_key);

        // TODO: These two should be bit fields instead
        proto_tree_add_uint64(key_tree, hf_syncthing_protobuf_tag, summary->tvb, start_offset, varint_length, tag);
        proto_tree_add_uint(key_tree, hf_syncthing_protobuf_wire_type, summary->tvb, start_offset, varint_length, wire_type);

        syncthing_local_discovery_summary subsummary = { summary->tvb, summary->pinfo, subtree };
        gint result = def->handler(&subsummary, header, offset);

        if (result == -1) {
            // TODO: Invalid format. Add expert info
            return -1;
        }

        gint total_length = varint_length + result;
        proto_item_set_len(header, total_length);
        return total_length;
    }

    // No handler defined for this tag
    // TODO: Add expert info
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
        /* { tag, wire_type, handler, ett } */
        { 1, 2, &dissect_node_id, ett_syncthing_local_node_id },
        { 2, 2, &dissect_address, ett_syncthing_local_address },
        { 3, 0, &dissect_instance_id, ett_syncthing_local_instance_id }
    };

    return dissect_protobuf_field(summary, offset, field_definitions, sizeof(field_definitions)/sizeof(field_definitions[0]));
}

static int
dissect_syncthing_local_discovery(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    // The first four bytes are 0x2EA7D90B in network (big endian) byte order.
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
        { &hf_syncthing_protobuf_tag,
            { "ID", "syncthing.protobuf.tag",
            FT_UINT64, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_syncthing_protobuf_wire_type,
            { "Wire type", "syncthing.protobuf.wire_type",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_syncthing_protobuf_field_length,
            { "Field length", "syncthing.protobuf.length",
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
        { &hf_syncthing_local_node_id,
            { "Node ID", "syncthing.local.node_id",
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
        &ett_syncthing_local_node_id,
        &ett_syncthing_local_address,
        &ett_syncthing_local_instance_id,
        &ett_syncthing_protobuf_key
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
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
