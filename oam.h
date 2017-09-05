#ifndef OAM_H
#define OAM_H

#include "oamdefs.h"
#include <stdlib.h>
#include <stdint.h>
#include <sys/queue.h>
#include <linux/if_ether.h>

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
    uint16_t sequence;
    STAILQ_HEAD(, tlv_elem_t) tlvs;
} oam_pdu_event_t;

typedef struct leaf_t {
    uint8_t branch;
    union {
        uint16_t leaf;
        uint16_t type;
    }v;
    uint8_t width;
    uint8_t value[0];
} __attribute__((packed)) leaf_t;

typedef struct leaf_item_t {
    STAILQ_ENTRY(leaf_item_t) entry;
    leaf_t leaf;
}leaf_item_t;

typedef struct {
    uint8_t branch;
    uint16_t fw_ver;
    struct {
        uint8_t part1;
        uint16_t part2;
    }oui;
    uint16_t product_id;
    uint16_t version;
    uint8_t extended_id[64];
    uint8_t base_mac[6];
    uint8_t max_links;
    uint8_t num_ports;
    uint8_t num_assignable_upstream_queues;
    uint8_t max_queue_per_link_upstream;
    uint8_t queue_increment_upstream;
    uint8_t num_assignable_downstream_queues;
    uint8_t max_queue_per_link_downstream;
    uint8_t queue_increment_downstream;
    uint16_t upstream_buffer_available;
    uint16_t downstream_buffer_available;
    uint16_t jedec_manufacturer_id;
    uint16_t chip_id;
    uint32_t chip_ver;
} __attribute__((packed)) oam_pdu_teknovus_info_t;

typedef struct {
    uint32_t oui:24;
    uint32_t ext_opcode:8;
    union {
        STAILQ_HEAD(,leaf_item_t) greq;
        STAILQ_HEAD(,leaf_item_t) gresp;
        STAILQ_HEAD(,leaf_item_t) sreq;
        STAILQ_HEAD(,leaf_item_t) sresp;
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
        STAILQ_HEAD(,tlv_elem_t) info;
        oam_pdu_event_t event;
        oam_pdu_org_t org;
        STAILQ_HEAD(,leaf_item_t) req;
        STAILQ_HEAD(,leaf_item_t) resp;
        oam_pdu_loopback_ctl_t loopback;
    }payload;
} __attribute__((packed)) oam_frame_t;

extern oam_frame_t* oampdu_parse(oam_frame_t** frame, uint8_t* pkt, size_t len);
extern void oampdu_free_frame(oam_frame_t** frame);

#endif // OAM_H
