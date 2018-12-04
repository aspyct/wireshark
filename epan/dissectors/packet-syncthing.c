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

// TODO: Should I do something about libwsutil0.symbols?
// It contains a reference to the base32 method I moved
// I could also add references to the new base32 encode method.

// TODO: Test the fc00 dissector if possible. The change was small, but eh...

// TODO: Make sure no _U_ is left

#include "config.h"

#include <glib.h>
#include <epan/expert.h>
#include <epan/packet.h>
#include <epan/tvbuff.h>
#include <wsutil/base32.h>

#define SYNCTHING_LOCAL_DISCOVERY_PORT 21027
#define MAX_VARINT_LENGTH 10
#define NODE_ID_BYTE_LENGTH 32
#define NODE_ID_STRING_LENGTH 63

// TODO: Add an expert error?
#define CONSTRAIN_TO_GINT_OR_FAIL(constrained, minus) \
    if ((constrained) > G_MAXINT - (minus)) { \
        return -1;\
    }

typedef gint (*syncthing_protobuf_field_handler)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *header, guint offset);

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
static expert_field ei_syncthing_local_malformed = EI_INIT;


/*
 * ! Beware !
 * This is _not_ the standard luhn algorithm.
 * The developers of syncthing made a mistake while implementing it,
 * and later decided not to change it.
 *
 * TODO: Add url to forum post
 */
/*
static char // TODO: Is it correct to use char, or should I use a guint8 instead?
generate_luhn_checksum_char(const char *str, gint length)
{
    static char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    static gint alphabet_length = array_length(alphabet);

    gint factor = 1;
    gint sum = 0;

    for (int i = 0; i < length; ++i) {
        str
    }
}*/

static gint
stringify_node_id(const guint8 *node_id_bytes, guint8 *node_id_string)
{
    size_t base32_length = ws_base32_encode_length(NODE_ID_BYTE_LENGTH);

    guint8 *base32_string = (guint8 *) wmem_alloc(wmem_packet_scope(), base32_length + 1);
    base32_string[base32_length] = '\0';

    // This is slightly dangerous and might result in a segfault if function is called improperly
    // TODO: Maybe replace the parameter with a tvb?
    ws_base32_encode(node_id_bytes, NODE_ID_BYTE_LENGTH, base32_string);

    // Now split the base32 string into our chunks
    for (int i = 0; i < 4; ++i)
    {
        // Base32 -> SIDRUKEDIRUMIDEKILUIJITEPL7657PSETURITEKPS...
        // Result -> SIDRUKE-DIRUMI.-DEKILUI-JITEPL.-7657PSE-TURITE.-KPS...
        // where . is a luhn check char
        int group_offset = i * 16;
        int dash1_offset = group_offset + 7;
        int part2_offset = dash1_offset + 1;
        int luhn_offset = part2_offset + 6;
        int dash2_offset = luhn_offset + 1;

        int group_offset_in_base32 = i * 13;
        int part2_offset_in_base32 = group_offset_in_base32 + 7;

        memcpy(node_id_string + group_offset, base32_string + group_offset_in_base32, 7);
        node_id_string[dash1_offset] = '-';
        memcpy(node_id_string + part2_offset, base32_string + part2_offset_in_base32, 6);
        node_id_string[luhn_offset] = '%';
        node_id_string[dash2_offset] = '-';
    }

    node_id_string[NODE_ID_STRING_LENGTH] = '\0';

    return 0;
}

static gint
dissect_node_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *header, guint start_offset)
{
    guint varint_length;
    guint64 field_length;
    guint offset = start_offset;

    varint_length = tvb_get_varint(tvb, offset, 4, &field_length, ENC_VARINT_PROTOBUF);
    if (varint_length != 0 && field_length <= G_MAXINT) {
        CONSTRAIN_TO_GINT_OR_FAIL(field_length, varint_length);
        gint buflen = (gint)field_length;

        if (buflen != NODE_ID_BYTE_LENGTH) {
            // Not a valid node ID
            // TODO: Add expert info
            expert_add_info_format(
                pinfo, header, &ei_syncthing_local_malformed,
                "Invalid node ID length. Expected %i but got %i",
                NODE_ID_BYTE_LENGTH, buflen
            );

            return -1;
        }

        offset += varint_length;

        proto_tree_add_uint64(
            tree,
            hf_syncthing_protobuf_field_length,
            tvb,
            start_offset,
            varint_length,
            field_length
        );

        const guint8 *node_id_bytes = tvb_get_ptr(tvb, offset, buflen);

        // A node ID is split into 4 groups of 13+1 chars
        // Each group is itself split into 2 groups of 8 chars
        // The first 13 chars of each group are from the base32 string
        // And the last char is the (syncthing-specific-)luhn checksum
        // The resulting string looks like this:
        // 76SSOKL-4IDHXB7-KP6R3N5-IYVDIWL-SO5JUM7-ZI67AV2-E5576TD-ICSMNQV
        // A total of 63 chars. With the \0, we need 64 chars.
        guint8 node_id_string[NODE_ID_STRING_LENGTH + 1];
        stringify_node_id(node_id_bytes, node_id_string);

        // TODO: There was a remark on this from Peter. Fix it.
        proto_tree_add_bytes(tree, hf_syncthing_local_node_id, tvb, offset, buflen, node_id_bytes);
        proto_item_set_text(header, "Node ID: %s", node_id_string);

        return varint_length + buflen;
    }
    else {
        // TODO: invalid varint, add expert info
        return -1;
    }
}

static gint
dissect_address(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *header, const guint start_offset)
{
    guint varint_length;
    guint64 field_length;
    guint offset = start_offset;

    varint_length = tvb_get_varint(tvb, offset, MAX_VARINT_LENGTH, &field_length, ENC_VARINT_PROTOBUF);
    if (varint_length != 0) {
        CONSTRAIN_TO_GINT_OR_FAIL(field_length, varint_length);
        gint buflen = (gint)field_length;

        offset += varint_length;

        proto_tree_add_uint64(
            tree,
            hf_syncthing_protobuf_field_length,
            tvb,
            start_offset,
            varint_length,
            field_length
        );

        guint8 *buf = (guint8*) wmem_alloc(wmem_packet_scope(), buflen + 1);
        tvb_get_nstringz0(tvb, offset, buflen + 1, buf);
        proto_tree_add_string(tree, hf_syncthing_local_address, tvb, offset, buflen, buf);

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
dissect_instance_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *header, guint offset)
{
    gint varint_length;
    gint64 instance_id;

    varint_length = tvb_get_varint(tvb, offset, MAX_VARINT_LENGTH, &instance_id, ENC_VARINT_PROTOBUF);
    if (varint_length != 0)
    {
        proto_tree_add_int64(tree, hf_syncthing_local_instance_id, tvb, offset, varint_length, instance_id);
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
    // TODO: Can I make this const? And in other functions?
    tvbuff_t *tvb,
    packet_info *pinfo,
    proto_tree *tree,
    const guint start_offset,
    const syncthing_protobuf_field_definition *definitions,
    const int defcount)
{
    gint varint_length;
    guint64 key;
    guint offset = start_offset;
	
    varint_length = tvb_get_varint(tvb, offset, 4, &key, ENC_VARINT_PROTOBUF);

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
            tree,
            hf_syncthing_protobuf_entry,
            tvb,
            start_offset,
            0, // we'll know it after parsing the field
            ENC_NA
        );
        proto_tree *subtree = proto_item_add_subtree(header, def->ett);

        proto_item *key_item = proto_tree_add_uint64_format(
            subtree,
            hf_syncthing_protobuf_key,
            tvb,
            start_offset,
            varint_length,
            key,
            "Protobuf Key, ID: %" G_GINT64_MODIFIER "i, Wire type: %i",
            tag, wire_type
        );
        proto_item *key_tree = proto_item_add_subtree(key_item, ett_syncthing_protobuf_key);

        // TODO: These two should be bit fields instead
        proto_tree_add_uint64(key_tree, hf_syncthing_protobuf_tag, tvb, start_offset, varint_length, tag);
        proto_tree_add_uint(key_tree, hf_syncthing_protobuf_wire_type, tvb, start_offset, varint_length, wire_type);

        gint result = def->handler(tvb, pinfo, subtree, header, offset);

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
dissect_next_field(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset)
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

    return dissect_protobuf_field(tvb, pinfo, tree, offset, field_definitions, array_length(field_definitions));
}

static int
dissect_syncthing_local_discovery(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    // We need a tree in every case, if only to display an error
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Syncthing");
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, proto_syncthing_local_discovery, tvb, 0,-1, ENC_NA);

    // The first four bytes are 0x2EA7D90B in network (big endian) byte order.
    if (tvb_bytes_exist(tvb, 0, 4)) {
        guint32 magic = tvb_get_ntohl(tvb, 0);
    
        if (magic != 0x2EA7D90B) {
            // This is not a valid syncthing packet
            // TODO: Test this
            expert_add_info_format(
                pinfo,
                ti,
                &ei_syncthing_local_malformed,
                "Magic number is incorrect"
            );

            return tvb_captured_length(tvb);
        }

        proto_tree *syncthing_tree = proto_item_add_subtree(ti, ett_syncthing_local);
        proto_tree_add_item(syncthing_tree, hf_syncthing_local_magic, tvb, 0, 4, ENC_BIG_ENDIAN);

        guint offset = 4;

        while (offset < tvb_reported_length(tvb)) {
            gint data_used = dissect_next_field(tvb, pinfo, syncthing_tree, offset);

            if (data_used != -1) {
                offset += data_used;
            }
            else {
                // The field could not be parsed
                // TODO: Test this
                expert_add_info_format(pinfo, ti, &ei_syncthing_local_malformed, "Could not parse field");
                return tvb_captured_length(tvb);
            }
        }

        return tvb_captured_length(tvb);
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

    static ei_register_info ei[] = {
        { &ei_syncthing_local_malformed,
          { "syncthing.malformed", PI_MALFORMED, PI_ERROR,
            "Packet is malformed", EXPFILL }
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

    expert_module_t *expert_local = expert_register_protocol(proto_syncthing_local_discovery);
    expert_register_field_array(expert_local, ei, array_length(ei));
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
