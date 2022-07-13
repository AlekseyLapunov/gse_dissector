#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/etypes.h>

#define BIT_IS_SET(var, bit) ((var) & (1 << (bit)))
#define BIT_IS_CLEAR(var, bit) !BIT_IS_SET(var, bit)

static dissector_handle_t ip_handle;
static dissector_handle_t ipv6_handle;

// Инициализация полей протокола GSE
static int proto_gse = -1;
static int hf_gse_hdr = -1;
static int hf_gse_hdr_start = -1;
static int hf_gse_hdr_stop = -1;
static int hf_gse_hdr_labeltype = -1;
static int hf_gse_hdr_length = -1;
static int hf_gse_proto = -1;
static int hf_gse_label6 = -1;
static int hf_gse_label3 = -1;
static int hf_gse_fragid = -1;
static int hf_gse_totlength = -1;
static int hf_gse_exthdr = -1;
static int hf_gse_data = -1;
static int hf_gse_crc32 = -1;

// Инициализия указателей subtree
static gint ett_gse = -1;
static gint ett_gse_hdr = -1;

void proto_register_gse(void);
void proto_reg_handoff_gse(void);

// Протокол GSE

#define GSE_MINSIZE              2

#define GSE_OFFS_HDR             0
#define GSE_HDR_START_MASK       0x8000
#define GSE_HDR_START_POS        15
#define GSE_HDR_STOP_MASK        0x4000
#define GSE_HDR_STOP_POS         14
static const true_false_string tfs_gse_ss = {
    "enabled",
    "disabled"
};

#define GSE_HDR_LABELTYPE_MASK   0x3000
#define GSE_HDR_LABELTYPE_POS1   13
#define GSE_HDR_LABELTYPE_POS2   12

static const value_string gse_labeltype[] = {
    {0, "6 byte"},
    {1, "3 byte"},
    {2, "0 byte (Broadcast)"},
    {3, "re-use last label"},
    {0, NULL}
};

#define GSE_HDR_LENGTH_MASK      0x0FFF

static const range_string gse_proto_str[] = {
    {0x0000        , 0x00FF        , "not implemented"},
    {0x0100        , 0x05FF        , "not implemented"},
    {0x0600        , 0x07FF        , "not implemented"},
    {ETHERTYPE_IP  , ETHERTYPE_IP  , "IPv4 Payload"   },
    {0x0801        , 0x86DC        , "not implemented"},
    {ETHERTYPE_IPv6, ETHERTYPE_IPv6, "IPv6 Payload"   },
    {0x86DE        , 0xFFFF        , "not implemented"},
    {0             , 0             , NULL             }
};

#define GSE_CRC32_LEN            4

static int dissect_gse(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  int         new_off                      = 0;
  int cur_off = 0;
    int         frag_len;
    guint16     gse_hdr, data_len, gse_proto = 0;

    proto_item *ti, *tf;
    proto_tree *gse_tree, *gse_hdr_tree;

    tvbuff_t   *next_tvb;
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "GSE");
    col_clear(pinfo->cinfo, COL_INFO);
    col_append_str(pinfo->cinfo, COL_INFO, "GSE");

    /* get header and determine length */
    gse_hdr = tvb_get_ntohs(tvb, cur_off + GSE_OFFS_HDR);
    new_off += 2;
    frag_len = (gse_hdr & GSE_HDR_LENGTH_MASK)+2;

    ti = proto_tree_add_item(tree, proto_gse, tvb, cur_off, frag_len, ENC_NA);
    gse_tree = proto_item_add_subtree(ti, ett_gse);

    tf = proto_tree_add_item(gse_tree, hf_gse_hdr, tvb, cur_off + GSE_OFFS_HDR, 2, gse_hdr);

    gse_hdr_tree = proto_item_add_subtree(tf, ett_gse_hdr);
    proto_tree_add_item(gse_hdr_tree, hf_gse_hdr_start, tvb, cur_off + GSE_OFFS_HDR, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(gse_hdr_tree, hf_gse_hdr_stop, tvb, cur_off + GSE_OFFS_HDR, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(gse_hdr_tree, hf_gse_hdr_labeltype, tvb,
                        cur_off + GSE_OFFS_HDR, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(gse_hdr_tree, hf_gse_hdr_length, tvb, cur_off + GSE_OFFS_HDR, 2, ENC_BIG_ENDIAN);

    if (BIT_IS_CLEAR(gse_hdr, GSE_HDR_START_POS) &&
        BIT_IS_CLEAR(gse_hdr, GSE_HDR_STOP_POS) &&
        BIT_IS_CLEAR(gse_hdr, GSE_HDR_LABELTYPE_POS1) && BIT_IS_CLEAR(gse_hdr, GSE_HDR_LABELTYPE_POS2)) {
        col_append_str(pinfo->cinfo, COL_INFO, " ");
        return new_off;
    } else {

        if (BIT_IS_CLEAR(gse_hdr, GSE_HDR_START_POS) || BIT_IS_CLEAR(gse_hdr, GSE_HDR_STOP_POS)) {

            proto_tree_add_item(gse_tree, hf_gse_fragid, tvb, cur_off + new_off, 1, ENC_BIG_ENDIAN);

            new_off += 1;
        }
        if (BIT_IS_SET(gse_hdr, GSE_HDR_START_POS) && BIT_IS_CLEAR(gse_hdr, GSE_HDR_STOP_POS)) {

            proto_tree_add_item(gse_tree, hf_gse_totlength, tvb, cur_off + new_off, 2, ENC_BIG_ENDIAN);
            col_append_str(pinfo->cinfo, COL_INFO, "(frag) ");

            new_off += 2;
        }
        if (BIT_IS_SET(gse_hdr, GSE_HDR_START_POS)) {
            gse_proto = tvb_get_ntohs(tvb, cur_off + new_off);

            proto_tree_add_item(gse_tree, hf_gse_proto, tvb, cur_off + new_off, 2, ENC_BIG_ENDIAN);

            new_off += 2;

            if (BIT_IS_CLEAR(gse_hdr, GSE_HDR_LABELTYPE_POS1) && BIT_IS_CLEAR(gse_hdr, GSE_HDR_LABELTYPE_POS2)) {
                /* 6 byte label */
                if (BIT_IS_SET(gse_hdr, GSE_HDR_STOP_POS))
                    col_append_str(pinfo->cinfo, COL_INFO, "6 ");

                proto_tree_add_item(gse_tree, hf_gse_label6, tvb, cur_off + new_off, 6, ENC_NA);

                new_off += 6;
            } else if (BIT_IS_CLEAR(gse_hdr, GSE_HDR_LABELTYPE_POS1) &&
                       BIT_IS_SET(gse_hdr, GSE_HDR_LABELTYPE_POS2)) {
                /* 3 byte label */
                if (BIT_IS_SET(gse_hdr, GSE_HDR_STOP_POS))
                    col_append_str(pinfo->cinfo, COL_INFO, "3 ");

                proto_tree_add_item(gse_tree, hf_gse_label3, tvb, cur_off + new_off, 3, ENC_NA);

                new_off += 3;
            } else {
                /* 0 byte label */
                if (BIT_IS_SET(gse_hdr, GSE_HDR_STOP_POS))
                    col_append_str(pinfo->cinfo, COL_INFO, "0 ");
            }
            /*
            if (gse_proto < 0x0600 && gse_proto >= 0x100) {
            	  proto_tree_add_item(gse_tree, hf_gse_exthdr, tvb, cur_off + new_off, 1, ENC_BIG_ENDIAN);

                new_off += 1;
            } */
        }
        else
        {
            /* correct cinfo */
            col_append_str(pinfo->cinfo, COL_INFO, "(frag) ");
        }

        next_tvb = tvb_new_subset_remaining(tvb, cur_off + new_off);

        int full_dissection = 1;

        if (full_dissection)
        {
            switch (gse_proto) {
            case ETHERTYPE_IP:
                new_off += call_dissector(ip_handle, next_tvb, pinfo, tree);
                break;
            case ETHERTYPE_IPv6:
                new_off += call_dissector(ipv6_handle, next_tvb, pinfo, tree);
                break;
            default:
                if (BIT_IS_CLEAR(gse_hdr, GSE_HDR_START_POS) && BIT_IS_SET(gse_hdr, GSE_HDR_STOP_POS)) {
                    data_len = (gse_hdr & GSE_HDR_LENGTH_MASK) - (new_off - GSE_MINSIZE) - GSE_CRC32_LEN;
                } else
                    data_len = (gse_hdr & GSE_HDR_LENGTH_MASK) - (new_off - GSE_MINSIZE);

                proto_tree_add_item(gse_tree, hf_gse_data, tvb, cur_off + new_off, data_len, ENC_NA);
                new_off += data_len;
                break;
            }
        }
        else
        {
            if (BIT_IS_CLEAR(gse_hdr, GSE_HDR_START_POS) && BIT_IS_SET(gse_hdr, GSE_HDR_STOP_POS)) {
                data_len = (gse_hdr & GSE_HDR_LENGTH_MASK) - (new_off - GSE_MINSIZE) - GSE_CRC32_LEN;

            } else
            {
                data_len = (gse_hdr & GSE_HDR_LENGTH_MASK) - (new_off - GSE_MINSIZE);
            }

            proto_tree_add_item(gse_tree, hf_gse_data, tvb, cur_off + new_off, data_len, ENC_NA);

            new_off += data_len;
        }

        /* add crc32 if last fragment */
        if (BIT_IS_CLEAR(gse_hdr, GSE_HDR_START_POS) && BIT_IS_SET(gse_hdr, GSE_HDR_STOP_POS)) {
            proto_tree_add_item(gse_tree, hf_gse_crc32, tvb, cur_off + new_off, GSE_CRC32_LEN, ENC_NA);
            new_off += GSE_CRC32_LEN;
        }
    }
  return new_off;
}

void proto_register_gse(void)
{
  static hf_register_info hf_gse[] = {
      {&hf_gse_hdr, {
              "GSE header", "gse.hdr",
              FT_UINT16, BASE_HEX, NULL, 0x0,
              "GSE Header (start/stop/length)", HFILL}
      },
      {&hf_gse_hdr_start, {
              "Start", "gse.hdr.start",
              FT_BOOLEAN, 16, TFS(&tfs_gse_ss), GSE_HDR_START_MASK,
              "Start Indicator", HFILL}
      },
      {&hf_gse_hdr_stop, {
              "Stop", "gse.hdr.stop",
              FT_BOOLEAN, 16, TFS(&tfs_gse_ss), GSE_HDR_STOP_MASK,
              "Stop Indicator", HFILL}
      },
      {&hf_gse_hdr_labeltype, {
              "Label Type", "gse.hdr.labeltype",
              FT_UINT16, BASE_HEX, VALS(gse_labeltype), GSE_HDR_LABELTYPE_MASK,
              "Label Type Indicator", HFILL}
      },
      {&hf_gse_hdr_length, {
              "Length", "gse.hdr.length",
              FT_UINT16, BASE_DEC, NULL, GSE_HDR_LENGTH_MASK,
              "GSE Length", HFILL}
      },
      {&hf_gse_proto, {
              "Protocol", "gse.proto",
              FT_UINT16, BASE_HEX | BASE_RANGE_STRING, RVALS(gse_proto_str), 0x0,
              "Protocol Type", HFILL}
      },
      {&hf_gse_label6, {
              "Label", "gse.label",
              FT_ETHER, BASE_NONE, NULL, 0x0,
              "Label Field", HFILL}
      },
      {&hf_gse_label3, {
              "Label", "gse.label",
              FT_UINT24, BASE_HEX, NULL, 0x0,
              "Label Field", HFILL}
      },
      {&hf_gse_fragid, {
              "Frag ID", "gse.fragid",
              FT_UINT8, BASE_HEX, NULL, 0x0,
              "Fragment ID", HFILL}
      },
      {&hf_gse_totlength, {
              "Total Length", "gse.totlength",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              "GSE Total Frame Length", HFILL}
      },
      {&hf_gse_exthdr, {
              "Extension Header", "gse.exthdr",
              FT_UINT8, BASE_HEX, NULL, 0x0,
              "optional Extension Header", HFILL}
      },
      {&hf_gse_data, {
              "PDU Data", "gse.data",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              "GSE Frame User Data", HFILL}
      },
      {&hf_gse_crc32, {
              "CRC", "gse.crc",
              FT_UINT32, BASE_HEX, NULL, 0x0,
              "CRC-32", HFILL}
      }
  };

    static gint *ett[] = { &ett_gse, &ett_gse_hdr };
    proto_gse = proto_register_protocol (
        "Generic Stream Encapsulation",
        "GSE",
        "gse"
        );

    proto_register_field_array(proto_gse, hf_gse, array_length(hf_gse));
    proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_gse(void)
{
    static dissector_handle_t gse_handle;

    gse_handle = create_dissector_handle(dissect_gse, proto_gse);
    dissector_add_uint("ethertype", 0x2f16, gse_handle);
    dissector_add_uint("udp.port", 5000, gse_handle);
    ip_handle = find_dissector("ip");
    ipv6_handle = find_dissector("ipv6");
}
