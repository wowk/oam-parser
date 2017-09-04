#ifndef OAM_H
#define OAM_H

#include <stdlib.h>
#include <stdint.h>
#include <sys/queue.h>
#include <linux/if_ether.h>

typedef enum {
    OamOpInfo                   = 0x00,
    OamOpEventNotification      = 0x01,
    OamOpVarRequest             = 0x02,
    OamOpVarResponse            = 0x03,
    OamOpLookback               = 0x04,
    OamLegacyOpVendeorExt       = 0x80,
    OamLegacyOpPingRequest      = 0x8B,
    OamLegacyOpPingResponse     = 0x8C,
    OamOpVendorOui              = 0xfe
} oam_opcode_e;

typedef enum {
    OamTlvNull          = 0x00,
    OamTlvLocalInfo     = 0x01,
    OamTlvRemoteInfo    = 0x02,
    OamTlvOrgSpec       = 0xfe
} oam_tlv_type_e;

typedef struct tlv_t {
    uint8_t type;
    uint8_t len;
    uint8_t data[0];
} tlv_t;

typedef struct tlv_elem_t {
    STAILQ_ENTRY(tlv_elem_t) entry;
    tlv_t tlv;
} tlv_elem_t;

typedef struct ethhdr ethhdr_t;

/*
-------------------------------------------
[6] [5]   |  Remote Discovery status       |
[4] [3]   |  Local Discovery status        |
-------------------------------------------|
0    0    |  Unsatisfied, can’t complete   |
0    1    |  Discovery in process          |
1    0    |  Satisfied, Discovery complete |
1    1    |  Reserved                      |
-------------------------------------------
*/
typedef struct {
    uint16_t link_fault:1;
    uint16_t dying_gasp:1;
    uint16_t critical:1;
    uint16_t local_evaluating:1;          //3
    uint16_t local_stable:1;              //4
    uint16_t remove_evaluating:1;         //5
    uint16_t remote_stable:1;             //6
    uint16_t _reserved:9;
} __attribute__((packed)) oam_flags_t;

typedef struct {
    uint8_t  subtype;
    oam_flags_t flags;
    uint8_t opcode;
} __attribute__((packed)) oam_msg_t;

typedef struct {
    oam_msg_t hdr;
    uint8_t payload[0];
} __attribute__((packed)) oam_pdu_t;

typedef struct {
    STAILQ_HEAD(, tlv_elem_t) tlvs;
} oam_pdu_info_t;

typedef struct {
    uint16_t sequence;
    STAILQ_HEAD(, tlv_elem_t) tlvs;
} oam_pdu_event_t;

typedef struct req_item_t {
    uint8_t branch;
    union {
        uint16_t leaf;
        STAILQ_HEAD(,tlv_elem_t) tlvs; //branch 6
    }v;
} req_item_t;

typedef struct {
    STAILQ_HEAD(,req_item_t) reqs;
} oam_pdu_req_t;

typedef struct resp_item_t {
    uint8_t branch;
    uint16_t leaf;
    uint8_t width;
    uint8_t value[0];
} resp_item_t;

typedef struct {
    STAILQ_HEAD(,resp_item_t) resps;
} oam_pdu_resp_t;


typedef struct {
    uint8_t branch;
    union {
        uint16_t leaf;
        STAILQ_HEAD(,tlv_elem_t) tlvs; //for branch 6
    }v;
} oam_pdu_teknovus_get_req_t;

typedef struct {
    uint8_t branch;

} oam_pdu_teknovus_info_t;

typedef struct {
    uint8_t branch;

} oam_pdu_teknovus_get_resp_t;

typedef struct {

} oam_pdu_teknovus_set_req_t;

typedef struct {

} oam_pdu_teknovus_set_resp_t;

typedef struct {
    uint32_t oui:24;
    uint32_t ext_opcode;
    union {
        oam_pdu_teknovus_get_req_t greq;
        oam_pdu_teknovus_get_resp_t gresp;
        oam_pdu_teknovus_set_req_t sreq;
        oam_pdu_teknovus_set_resp_t sresp;
        oam_pdu_teknovus_info_t info;
    }v;
} oam_pdu_org_t;

typedef struct {
    /**
     * 0x00       : reserved
     * 0x01       : enable loopback
     * 0x02       : disable loopback
     * 0x03-0xFF  : reserved
     */
    uint8_t cmd;
} oam_pdu_loopback_ctl_t;

typedef struct {
    ethhdr_t    ethhdr;
    oam_pdu_t   pdu;
    union {
        oam_pdu_info_t info;
        oam_pdu_event_t event;
        oam_pdu_org_t org;
        oam_pdu_req_t req;
        oam_pdu_resp_t resp;
        oam_pdu_loopback_ctl_t loopback;
    }payload;
} __attribute__((packed)) oam_frame_t;

extern oam_frame_t* oampdu_parse(oam_frame_t** frame, uint8_t* pkt, size_t len);

#endif // OAM_H
