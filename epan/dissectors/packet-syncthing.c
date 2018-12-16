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

// Question: Should I do something about libwsutil0.symbols?
// It contains a reference to the base32 method I moved
// I could also add references to the new base32 encode method.

// TODO: Run another pass of fuzz testing when all else is done

#include "config.h"

#include <glib.h>
#include <strings.h>
#include <epan/expert.h>
#include <epan/packet.h>
#include <epan/tvbuff.h>
#include <wsutil/base32.h>

#define SYNCTHING_LOCAL_DISCOVERY_PORT 21027
#define MAX_VARINT_LENGTH 10
#define NODE_ID_BYTE_LENGTH 32
#define NODE_ID_STRING_LENGTH 64 // Including the \0

#define CONSTRAIN_TO_GINT_OR_FAIL(constrained, minus) \
    if ((constrained) > G_MAXINT - (minus)) { \
        return -1;\
    }

typedef gint (*syncthing_protobuf_field_handler)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *header, guint offset);

/*
 * Define a protobuf field and how to parse it
 */
typedef const struct {
    guint64 tag;
    guint8 wire_type;
    syncthing_protobuf_field_handler handler;
    int ett;
    int hf;
} syncthing_protobuf_field_definition;

/*
 * Protocols
 *
 * There's only one right now, but syncthing has 4.
 * Let's keep some room for that.
 */
void proto_register_syncthing(void);

static int proto_syncthing_local_discovery = -1;


/*
 * Fields
 */
// Question: For the sake of consistency, should I use gint everywhere?
static int hf_syncthing_protobuf_key = -1;
static int hf_syncthing_protobuf_tag = -1;
static int hf_syncthing_protobuf_wire_type = -1;

static int hf_syncthing_local_magic = -1;

static int hf_syncthing_local_node_id = -1;
static int hf_syncthing_local_node_id_length = -1;
static int hf_syncthing_local_node_id_value = -1;

static int hf_syncthing_local_address = -1;
static int hf_syncthing_local_address_length = -1;
static int hf_syncthing_local_address_value = -1;

static int hf_syncthing_local_instance_id = -1;
static int hf_syncthing_local_instance_id_value = -1;


/*
 * Trees
 */
static gint ett_syncthing_local = -1;
static gint ett_syncthing_local_node_id = -1;
static gint ett_syncthing_local_address = -1;
static gint ett_syncthing_local_instance_id = -1;
static gint ett_syncthing_protobuf_key = -1;


/*
 * Expert infos
 */
static expert_field ei_syncthing_local_malformed = EI_INIT;


/*
 * ! Beware !
 * This is _not_ the standard luhn algorithm.
 * The developers of syncthing made a mistake while implementing it,
 * and later decided not to change it.
 *
 * https://forum.syncthing.net/t/v0-9-0-new-node-id-format/478/6
 */
static gint
generate_nonstandard_luhn_checksum_char(const char *str, gint length, char *output)
{
    static char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    // -1 to exclude the \0
    static gint alphabet_length = array_length(alphabet) - 1;

    gint factor = 1;
    gint sum = 0;

    for (int i = 0; i < length; ++i) {
        char *position = index(alphabet, str[i]);

        if (position == NULL)
        {
            // Wrong encoding
            return -1;
        }

        // The position is garanteed to be at most 33, so the cast is safe
        int codepoint = (int)(position - alphabet);

        gint addend = factor * codepoint;
        addend = (addend / alphabet_length) + (addend % alphabet_length);
        sum += addend;

        factor = factor == 2 ? 1 : 2;
    }

    gint remainder = sum % alphabet_length;
    gint check_codepoint = (alphabet_length - remainder) % alphabet_length;

    *output = alphabet[check_codepoint];
    return 0;
}

static gint
stringify_node_id(
    const guint8 *node_id_bytes, guint bytes_length,
    guint8 *node_id_string, guint string_length)
{
    // These two tests are redundant,
    // but it might come in handy when we refactor the code.
    if (bytes_length != NODE_ID_BYTE_LENGTH) {
        // Must be exactly this size
        return -1;
    }

    if (string_length != NODE_ID_STRING_LENGTH) {
        // Must be exactly this size, too
        return -1;
    }

    size_t base32_length = ws_base32_encode_length(NODE_ID_BYTE_LENGTH);

    guint8 *base32_string = (guint8 *) wmem_alloc(wmem_packet_scope(), base32_length + 1);
    base32_string[base32_length] = '\0';

    // This is slightly dangerous and might result in a segfault,
    // if node_id_bytes is not the right length.
    ws_base32_encode(node_id_bytes, NODE_ID_BYTE_LENGTH, base32_string);

    // Now split the base32 string into our chunks
    for (guint i = 0; i < 4; ++i)
    {
        // Base32 -> SIDRUKEDIRUMIDEKILUIJITEPL7657PSETURITEKPS...
        // Result -> SIDRUKE-DIRUMI.-DEKILUI-JITEPL.-7657PSE-TURITE.-KPS...
        // where . is a luhn check char
        guint group_offset = i * 16;
        guint dash1_offset = group_offset + 7;
        guint part2_offset = dash1_offset + 1;
        guint luhn_offset = part2_offset + 6;
        guint dash2_offset = luhn_offset + 1;

        // Make sure we're not overstepping the boundaries
        if (dash2_offset >= string_length) {
            // Too far, let's not break stuff
            return -1;
        }

        guint group_offset_in_base32 = i * 13;
        guint part2_offset_in_base32 = group_offset_in_base32 + 7;

        memcpy(node_id_string + group_offset, base32_string + group_offset_in_base32, 7);
        node_id_string[dash1_offset] = '-';
        memcpy(node_id_string + part2_offset, base32_string + part2_offset_in_base32, 6);

        if (generate_nonstandard_luhn_checksum_char(base32_string + group_offset_in_base32, 13, node_id_string + luhn_offset) == -1) {
            return -1;
        }

        node_id_string[dash2_offset] = '-';
    }

    node_id_string[NODE_ID_STRING_LENGTH - 1] = '\0';

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
            hf_syncthing_local_node_id_length,
            tvb,
            start_offset,
            varint_length,
            field_length
        );

        // Question: It's not recommended to use tvb_get_ptr, but in this case
        // I need the bytes to convert them to the string node ID
        // I would love to get rid of this unsafe pointer though.
        // Any suggestion?
        const guint8 *node_id_bytes = tvb_get_ptr(tvb, offset, buflen);

        // A node ID is split into 4 groups of 13+1 chars
        // Each group is itself split into 2 groups of 8 chars
        // The first 13 chars of each group are from the base32 string
        // And the last char is the (syncthing-specific-)luhn checksum
        // The resulting string looks like this:
        // 76SSOKL-4IDHXB7-KP6R3N5-IYVDIWL-SO5JUM7-ZI67AV2-E5576TD-ICSMNQV
        // A total of 63 chars. With the \0, we need 64 chars.
        guint8 node_id_string[NODE_ID_STRING_LENGTH];

        if (stringify_node_id(node_id_bytes, buflen, node_id_string, NODE_ID_STRING_LENGTH) != -1) {
            proto_tree_add_bytes_format(
                tree,
                hf_syncthing_local_node_id_value,
                tvb,
                offset,
                buflen,
                node_id_bytes,
                "Value: %s",
                node_id_string
            );
            proto_item_set_text(header, "Node ID: %s", node_id_string);

            return varint_length + buflen;
        }
        else {
            expert_add_info_format(pinfo, header, &ei_syncthing_local_malformed, "Could not format node ID");
            return -1;
        }
    }
    else {
        expert_add_info_format(pinfo, header, &ei_syncthing_local_malformed, "Invalid node ID length varint.");
        return -1;
    }
}

static gint
dissect_address(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *header, const guint start_offset)
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
            hf_syncthing_local_address_length,
            tvb,
            start_offset,
            varint_length,
            field_length
        );

        guint8 *buf = (guint8*) wmem_alloc(wmem_packet_scope(), buflen + 1);
        tvb_get_nstringz0(tvb, offset, buflen + 1, buf);
        proto_tree_add_string(tree, hf_syncthing_local_address_value, tvb, offset, buflen, buf);

        // Question: I tried using append_text instead of set_text,
        // but then I end up with a "Sync address: <Missing>" followed by my text.
        // The "<Missing>" seems to be there because of the length == -1
        // So i defaulted back to set_text.
        // Any suggestion?
        proto_item_set_text(header, "Sync address: %s", buf);

        return varint_length + buflen;
    }
    else {
        expert_add_info_format(pinfo, header, &ei_syncthing_local_malformed, "Invalid address length varint.");
        return -1;
    }
}

static gint
dissect_instance_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *header, guint offset)
{
    gint varint_length;
    gint64 instance_id;

    varint_length = tvb_get_varint(tvb, offset, MAX_VARINT_LENGTH, &instance_id, ENC_VARINT_PROTOBUF);
    if (varint_length != 0)
    {
        proto_tree_add_int64(tree, hf_syncthing_local_instance_id_value, tvb, offset, varint_length, instance_id);
        proto_item_set_text(header, "Instance ID: %" G_GINT64_MODIFIER "i", instance_id);
        return varint_length;
    }
    else {
        // Could not read the instance ID as a varint
        expert_add_info_format(pinfo, header, &ei_syncthing_local_malformed, "Invalid instance ID varint.");
        return -1;
    }
}

static gint
dissect_protobuf_field(
    tvbuff_t *tvb,
    packet_info *pinfo,
    proto_tree *tree,
    proto_item *header,
    const guint start_offset,
    const syncthing_protobuf_field_definition *definitions,
    const int defcount)
{
    gint varint_length;
    guint64 key;
    guint offset = start_offset;
	
    varint_length = tvb_get_varint(tvb, offset, 4, &key, ENC_VARINT_PROTOBUF);

    if (varint_length == 0) {
        expert_add_info_format(pinfo, header, &ei_syncthing_local_malformed, "Invalid field key varint.");
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
            expert_add_info_format(
                pinfo, header, &ei_syncthing_local_malformed,
                "Unexpected wire type for field tag %" G_GINT64_MODIFIER "i. Got %i, expected %i",
                tag, wire_type, def->wire_type);
            return -1;
        }

        // Question: This results in a broken filter
        // To test this, right click on a top-level Node Id column (or address or instance Id),
        // and apply as filter. No packet will be displayed.
        // How can I fix this?
        proto_item *field_header = proto_tree_add_item(
            tree,
            def->hf,
            tvb,
            start_offset,
            -1, // we'll know the length after parsing the field
            ENC_NA
        );
        proto_tree *subtree = proto_item_add_subtree(field_header, def->ett);

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

        proto_tree_add_uint64(key_tree, hf_syncthing_protobuf_tag, tvb, start_offset, varint_length, tag);
        proto_tree_add_uint(key_tree, hf_syncthing_protobuf_wire_type, tvb, start_offset, varint_length, wire_type);

        gint result = def->handler(tvb, pinfo, subtree, field_header, offset);

        if (result == -1) {
            expert_add_info_format(
                pinfo, key_tree, &ei_syncthing_local_malformed,
                "Could not parse field"
            );
            return -1;
        }

        gint total_length = varint_length + result;
        proto_item_set_len(field_header, total_length);
        return total_length;
    }

    // No handler defined for this tag
    expert_add_info_format(
        pinfo, header, &ei_syncthing_local_malformed,
        "Unknown tag: %" G_GINT64_MODIFIER "i",
        tag
    );
    return -1;
}

static gint
dissect_next_field(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *header, guint offset)
{
    /*
    * The format is defined as follows:
    * message Announce {
    *   bytes           id          = 1;
    *   repeated string addresses   = 2;
    *   int64           instance_id = 3;
    * }
    */

    syncthing_protobuf_field_definition field_definitions[] = {
        /* { tag, wire_type, handler, ett, hf } */
        { 1, 2, &dissect_node_id, ett_syncthing_local_node_id, hf_syncthing_local_node_id },
        { 2, 2, &dissect_address, ett_syncthing_local_address, hf_syncthing_local_address },
        { 3, 0, &dissect_instance_id, ett_syncthing_local_instance_id, hf_syncthing_local_instance_id }
    };

    return dissect_protobuf_field(tvb, pinfo, tree, header, offset, field_definitions, array_length(field_definitions));
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
            expert_add_info_format(
                pinfo,
                ti,
                &ei_syncthing_local_malformed,
                "Probably not a syncthing packet: magic number should be 0x2EA7D90B"
            );

            return tvb_captured_length(tvb);
        }

        proto_tree *syncthing_tree = proto_item_add_subtree(ti, ett_syncthing_local);
        proto_tree_add_item(syncthing_tree, hf_syncthing_local_magic, tvb, 0, 4, ENC_BIG_ENDIAN);

        guint offset = 4;

        while (offset < tvb_reported_length(tvb)) {
            gint data_used = dissect_next_field(tvb, pinfo, syncthing_tree, ti, offset);

            if (data_used != -1) {
                offset += data_used;
            }
            else {
                // The field could not be parsed
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
        /*
         * Generic protobuf fields
         */
        { &hf_syncthing_protobuf_key,
            { "Protobuf key", "syncthing.protobuf.key",
            FT_UINT64, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_syncthing_protobuf_tag,
            { "ID", "syncthing.protobuf.tag", // TODO: Fix ID/tag inconsistency.
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

        /*
         * Magic number field
         */
        { &hf_syncthing_local_magic,
            { "Magic (constant)", "syncthing.local.magic",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },

        /*
         * Node ID field
         */
        { &hf_syncthing_local_node_id,
            { "Node ID", "syncthing.local.node_id",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_syncthing_local_node_id_length,
            { "Length", "syncthing.local.node_id.length",
            FT_UINT64, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_syncthing_local_node_id_value,
            { "Value", "syncthing.local.node_id.value",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL}
        },

        /*
         * Address field
         */
        { &hf_syncthing_local_address,
            { "Sync address", "syncthing.local.address",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_syncthing_local_address_length,
            { "Length", "syncthing.local.address.length",
            FT_UINT64, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_syncthing_local_address_value,
            { "Value", "syncthing.local.address.value",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },

        /*
         * Instance ID field
         */
        { &hf_syncthing_local_instance_id,
            { "Instance ID", "syncthing.local.instance_id",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_syncthing_local_instance_id_value,
            { "Value", "syncthing.local.instance_id.value",
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
