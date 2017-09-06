#include "oam.h"
#include "logmsg.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <errno.h>
#include <assert.h>
#include <arpa/inet.h>

/**
 * release queue
 */
#define STAILQ_RELEASE(head, field) do{     \
    while( !STAILQ_EMPTY((head)) ){         \
        STAILQ_REMOVE_HEAD((head), field);\
    }                                       \
}while(0)


/**
 * @brief oampdu_parse_info
 * @param frame
 * @param pkt
 * @param len
 * @return false : failed, true : success
 */
bool oampdu_parse_info(oam_frame_t* frame, uint8_t* pkt, size_t len)
{
    tlv_t* ptlv = (tlv_t*)pkt;

    STAILQ_INIT(&(frame->payload.info));

    //parse tlv information
    while( len >= sizeof(tlv_t) && ptlv->len && ptlv->len <= len ){
        size_t elen = sizeof( tlv_elem_t) + ptlv->len - sizeof(tlv_t);
        tlv_elem_t* e = (tlv_elem_t*)malloc(elen);

        if( !e ){
            goto free_tlvs;
        }else{
            memcpy(&(e->tlv), pkt, ptlv->len);
            STAILQ_INSERT_TAIL(&(frame->payload.info), e, entry);
            pkt += ptlv->len;
            len -= ptlv->len;
            ptlv = (tlv_t*)pkt;
        }
    }

    return true;

free_tlvs:
    STAILQ_RELEASE(&(frame->payload.info), entry);

    return false;
}


/**
 * @brief oampdu_parse_event
 * @param frame
 * @param pkt
 * @param len
 * @return
 */
bool oampdu_parse_event(oam_frame_t* frame, uint8_t* pkt, size_t len)
{
    tlv_t* ptlv = (tlv_t*)pkt;
    oam_pdu_event_t* ev = &(frame->payload.event);

    STAILQ_INIT(&(ev->tlvs));

    ev->sequence = ntohs(*(uint16_t*)(pkt));
    pkt += sizeof(uint16_t);
    len -= sizeof(uint16_t);

    std_errmsg("found event notification: %d", ev->sequence);
    while( len >= sizeof(tlv_t) && ptlv->len && ntohs(ptlv->len) <= len ){
        size_t elen = sizeof( tlv_elem_t) + ptlv->len - sizeof(tlv_t);
        tlv_elem_t* e = (tlv_elem_t*)malloc(elen);

        if( !e ){
            goto free_tlvs;
        }else{
            std_errmsg("get tlv");
            memcpy(&(e->tlv), pkt, ptlv->len);
            STAILQ_INSERT_TAIL(&(ev->tlvs), e, entry);
            pkt += ptlv->len;
            len -= ptlv->len;
        }
    }

    return true;

free_tlvs:
    STAILQ_RELEASE(&(frame->payload.event.tlvs), entry);
    return false;
}


/**
 * @brief oampdu_parse_org_teknovus_info
 * @param frame
 * @param pkt
 * @param len
 * @return
 */
bool oampdu_parse_org_teknovus_info(oam_frame_t* frame, uint8_t* pkt, size_t len)
{
    oam_pdu_teknovus_info_t* p = (oam_pdu_teknovus_info_t*)pkt;
    oam_pdu_teknovus_info_t* tmp = &frame->payload.org.v.info;
    if( len < sizeof(oam_pdu_teknovus_info_t) ){
        return false;
    }
    memcpy(tmp, p, sizeof(oam_pdu_teknovus_info_t));

    tmp->chip_id    = ntohs(tmp->chip_id);
    tmp->chip_ver   = ntohl(tmp->chip_ver);
    tmp->version    = ntohs(tmp->version);
    tmp->fw_ver     = ntohs(tmp->fw_ver);
    tmp->product_id = ntohs(tmp->product_id);
    tmp->oui.low    = ntohs(tmp->oui.low);
    tmp->jedec_manufacturer_id  = ntohs(tmp->jedec_manufacturer_id);
    tmp->upstream_buffer_available = ntohs(tmp->upstream_buffer_available);
    tmp->downstream_buffer_available = ntohs(tmp->downstream_buffer_available);

    return true;
}


static leaf_item_t* get_leaf(uint8_t ext_code, uint8_t* pkt, size_t len, bool* finished)
{

    leaf_t* pleaf = (leaf_t*)pkt;
    leaf_item_t* pleafitem;
    size_t ext_len;

    *finished = false;

    if( len < 3  ){

        finished = true;
        return NULL;

    }else if( pleaf->branch == OamBranchOrgTekEnd ){

        pleafitem = (leaf_item_t*)calloc(1, sizeof(leaf_item_t));
        if( !pleafitem ){
            std_errmsg("malloc(failed) => %s", strerror(errno));
            return NULL;
        }

        pleafitem->leaflen = sizeof(leaf_item_t);

        *finished = true;

    }else if( pleaf->branch == OamBranchOrgTekNameBinding ){ //we process NameBinding here beacause of GetRequest

        if( len < 4 ){
            std_errmsg("invalid pkt");
            return NULL;
        }else{
            ext_len = 4;
        }

        if( pleaf->width != 0x80 ){
            ext_len += pleaf->width;
        }

        if( len < ext_len ){
            return NULL;
        }

        pleafitem = (leaf_item_t*)calloc(1, ext_len);
        if( !pleafitem ){
            return NULL;
        }else{
            pleafitem->leaflen = ext_len;
            memcpy(&(pleafitem->leaf), pleaf, pleafitem->leaflen);
        }

    }else if( ext_code == OamOpOrgTekGetRequest ){

        pleafitem = (leaf_item_t*)calloc(1, sizeof( leaf_item_t));
        if( !pleafitem ){
            return NULL;
        }

        pleafitem->leaf.branch = pleaf->branch;
        pleafitem->leaf.v.leaf = pleaf->v.leaf;
        pleafitem->leaflen = 3;

    }else{
        switch (ext_code) {
        case OamOpOrgTekGetResponse:
        case OamOpOrgTekSetRequest:
        case OamOpOrgTekSetResponse:
            if( len < 4 ){
                return NULL;
            }else{
                ext_len = 4;
            }

            if( pleaf->width != 0x80 ){
                ext_len += pleaf->width;
            }else if( ext_code == OamOpOrgTekSetResponse || ext_code == OamOpOrgTekGetResponse ){
                if( pleaf->width != 0xA1 ){
                    ext_len += pleaf->width;
                }
            }else{
                ext_len += pleaf->width;
            }

            if( len < ext_len ){
                return NULL;
            }

            pleafitem = (leaf_item_t*)calloc(1, ext_len);
            if( !pleafitem ){
                return NULL;
            }else{
                pleafitem->leaflen = ext_len;
                memcpy(&(pleafitem->leaf), pleaf, pleafitem->leaflen);
            }
            break;
        default:
            return NULL;
        }
    }

    pleafitem->leaf.v.leaf = ntohs(pleafitem->leaf.v.leaf);

    std_errmsg("opcode: %d, branch = %d, leaf = %d",
               ext_code,
               pleafitem->leaf.branch,
               pleafitem->leaf.v.leaf);
    return pleafitem;
}


/**
 * @brief oampdu_parse_org_teknovus_get_request
 * @param frame
 * @param pkt
 * @param len
 * @return
 */
bool oampdu_parse_org_teknovus_get_request(oam_frame_t* frame, uint8_t* pkt, size_t len)
{
    bool finished;
    leaf_item_t* p;

    if( len < 3 ){
        return true;
    }

    STAILQ_INIT(&(frame->payload.org.v.greq));

    while( 1 ){
        p = get_leaf(OamOpOrgTekGetRequest, pkt, len, &finished);
        if( finished ){
            if( p ){
                STAILQ_INSERT_TAIL(&(frame->payload.org.v.greq), p, entry);
            }
            break;
        }else if( p ){
            STAILQ_INSERT_TAIL(&(frame->payload.org.v.greq), p, entry);
            len -= p->leaflen;
            pkt += p->leaflen;
        }else{
            std_errmsg("get leaf failed");
            return false;
        }
    }

    return true;

free_tlvs:
    STAILQ_RELEASE(&(frame->payload.org.v.greq), entry);

    return false;
}


/**
 * @brief oampdu_parse_org_teknovus_get_response
 * @param frame
 * @param pkt
 * @param len
 * @return
 */
bool oampdu_parse_org_teknovus_get_response(oam_frame_t* frame, uint8_t* pkt, size_t len)
{
    bool finished;
    leaf_item_t* p;

    if( len < 3 ){
        return true;
    }

    STAILQ_INIT(&(frame->payload.org.v.gresp));

    while( 1 ){
        p = get_leaf(OamOpOrgTekGetRequest, pkt, len, &finished);
        if( finished ){
            if( p ){
                STAILQ_INSERT_TAIL(&(frame->payload.org.v.gresp), p, entry);
            }
            break;
        }else if( p ){
            STAILQ_INSERT_TAIL(&(frame->payload.org.v.gresp), p, entry);
            len -= p->leaflen;
            pkt += p->leaflen;
        }else{
            std_errmsg("get leaf failed");
            return false;
        }
    }

    return true;

free_tlvs:
    STAILQ_RELEASE(&(frame->payload.org.v.gresp), entry);

    return false;
}


/**
 * @brief oampdu_parse_org_teknovus_set_request
 * @param frame
 * @param pkt
 * @param len
 * @return
 */
bool oampdu_parse_org_teknovus_set_request(oam_frame_t* frame, uint8_t* pkt, size_t len)
{
    bool finished;
    leaf_item_t* p;

    if( len < 3 ){
        return true;
    }

    STAILQ_INIT(&(frame->payload.org.v.sreq));

    while( 1 ){
        p = get_leaf(OamOpOrgTekGetRequest, pkt, len, &finished);
        if( finished ){
            if( p ){
                STAILQ_INSERT_TAIL(&(frame->payload.org.v.sreq), p, entry);
            }
            break;
        }else if( p ){
            STAILQ_INSERT_TAIL(&(frame->payload.org.v.sreq), p, entry);
            len -= p->leaflen;
            pkt += p->leaflen;
        }else{
            std_errmsg("get leaf failed");
            return false;
        }
    }

    return true;

free_tlvs:
    STAILQ_RELEASE(&(frame->payload.org.v.sreq), entry);

    return false;
}


/**
 * @brief oampdu_parse_org_teknovus_set_response
 * @param frame
 * @param pkt
 * @param len
 * @return
 */
bool oampdu_parse_org_teknovus_set_response(oam_frame_t* frame, uint8_t* pkt, size_t len)
{
    bool finished;
    leaf_item_t* p;

    if( len < 3 ){
        return true;
    }

    STAILQ_INIT(&(frame->payload.org.v.sresp));

    while( 1 ){
        p = get_leaf(OamOpOrgTekGetRequest, pkt, len, &finished);
        if( finished ){
            if( p ){
                STAILQ_INSERT_TAIL(&(frame->payload.org.v.sresp), p, entry);
            }
            break;
        }else if( p ){
            STAILQ_INSERT_TAIL(&(frame->payload.org.v.sresp), p, entry);
            len -= p->leaflen;
            pkt += p->leaflen;
        }else{
            std_errmsg("get leaf failed");
            return false;
        }
    }

    return true;

free_tlvs:
    STAILQ_RELEASE(&(frame->payload.org.v.sresp), entry);

    return false;
}


/**
 * @brief oampdu_parse_org_teknovus
 * @param frame
 * @param pkt
 * @param len
 * @return
 */
bool oampdu_parse_org_teknovus(oam_frame_t* frame, uint8_t* pkt, size_t len)
{
    bool ret;
    oam_pdu_org_t* org = &(frame->payload.org);

    pkt += 4;
    len -= 4;

    std_errmsg("ext_opcode: %d", org->ext_opcode);
    switch (org->ext_opcode) {
    case OamOpOrgTekInfo:
        ret = oampdu_parse_org_teknovus_info(frame, pkt, len);
        break;
    case OamOpOrgTekGetRequest:
        ret = oampdu_parse_org_teknovus_get_request(frame, pkt, len);
        break;
    case OamOpOrgTekGetResponse:
        ret = oampdu_parse_org_teknovus_get_response(frame, pkt, len);
        break;
    case OamOpOrgTekSetRequest:
        ret = oampdu_parse_org_teknovus_set_request(frame, pkt, len);
        break;
    case OamOpOrgTekSetResponse:
        ret = oampdu_parse_org_teknovus_set_response(frame, pkt, len);
        break;
    case OamOpOrgTekMCRegRequest:
        std_errmsg("ext_opcode not supported");
        ret = false;
        break;
    case OamOpOrgTekMCRegResponse:
        std_errmsg("ext_opcode not supported");
        ret = false;
        break;
    default:
        std_errmsg("ext_opcode not supported");
        break;
    }

    if( !ret ){
        return false;
    }

    return true;
}


/**
 * @brief oampdu_parse_org
 * @param frame
 * @param pkt
 * @param len
 * @return
 */
bool oampdu_parse_org(oam_frame_t* frame, uint8_t* pkt, size_t len)
{
    oam_pdu_org_t* org = &(frame->payload.org);

    memcpy(org, pkt, sizeof(uint32_t));
    org->oui = ntohl(org->oui)>>8;
    if( org->oui == 0x000db6 ){
        std_errmsg("oam pdu");
        return oampdu_parse_org_teknovus(frame, pkt, len);
    }else{
        std_errmsg("not supported OUI: %.8X", ntohl(org->oui));
        return false;
    }

    return true;
}


bool oampdu_parse_request(oam_frame_t* frame, uint8_t* pkt, size_t len)
{
    return true;
}


bool oampdu_parse_response(oam_frame_t* frame, uint8_t* pkt, size_t len)
{
    return true;
}


bool oampdu_parse_loopback_ctl(oam_frame_t* frame, uint8_t* pkt, size_t len)
{
    return true;
}


/**
 * @brief oampdu_free_frame
 * @param frame
 */
void oampdu_free_frame(oam_frame_t** frame)
{
    oam_frame_t* p = NULL;

    assert( frame && *frame );

    p = *frame;
    *frame = NULL;

    switch (p->pdu.hdr.opcode) {
    case OamOpInfo:
        break;
    case OamOpEventNotification:
        STAILQ_RELEASE(&(p->payload.event.tlvs), entry);
        break;
    case OamOpVarRequest:
        STAILQ_RELEASE(&(p->payload.req),entry);
        break;
    case OamOpVarResponse:
        STAILQ_RELEASE(&(p->payload.resp),entry);
        break;
    case OamOpLookback:
        break;
    case OamOpVendorOui:
        if( p->payload.org.oui == 0x000db6 ){
            switch( p->payload.org.ext_opcode ){
            case OamOpOrgTekInfo:
                break;
            case OamOpOrgTekGetRequest:
                STAILQ_RELEASE(&(p->payload.org.v.greq),entry);
                break;
            case OamOpOrgTekGetResponse:
                STAILQ_RELEASE(&(p->payload.org.v.gresp),entry);
                break;
            case OamOpOrgTekSetRequest:
                STAILQ_RELEASE(&(p->payload.org.v.sreq),entry);
                break;
            case OamOpOrgTekSetResponse:
                STAILQ_RELEASE(&(p->payload.org.v.sresp),entry);
                break;
            case OamOpOrgTekMCRegRequest:
            case OamOpOrgTekMCRegResponse:
                break;
            default:
                break;
            }
        }
        break;
    default:
        break;
    }
    free(p);
}


/**
 * @brief oampdu_parse
 * @param frame
 * @param pkt
 * @param len
 * @return
 */
oam_frame_t *oampdu_parse(oam_frame_t **frame, uint8_t *pkt, size_t len)
{
    bool ret;
    size_t hlen;
    oam_frame_t* p = NULL;

    //allocate a frame object
    p = *frame = (oam_frame_t*)malloc(sizeof(oam_frame_t));
    if( *frame == NULL ){
        std_errmsg("%s", strerror(errno));
        return NULL;
    }

    //parse ether frame header
    hlen = sizeof(p->ethhdr);
    if( hlen > len ){
        std_errmsg("invalid ether frame");
        goto free_frame;
    }
    memcpy(&(p->ethhdr), pkt, hlen);
    p->ethhdr.h_proto = ntohs(p->ethhdr.h_proto);
    pkt += hlen;
    len -= hlen;

    //protocol num MUST be 0x8809
    if( p->ethhdr.h_proto != 0x8809 ){
        goto free_frame;
    }

    //parse oam pdu header
    hlen = sizeof((*frame)->pdu);
    if( hlen > len ){
        goto free_frame;
    }
    memcpy(&((*frame)->pdu), pkt, hlen);
    *(uint16_t*)&(*frame)->pdu.hdr.flags
            = ntohs(*(uint16_t*)&(*frame)->pdu.hdr.flags);
    pkt += hlen;
    len -= hlen;

    //subtype must be 0x3
    if( p->pdu.hdr.subtype != 0x3 ){
        goto free_frame;
    }

    switch( p->pdu.hdr.opcode ){
    case OamOpInfo:
        ret = oampdu_parse_info(p, pkt, len);
        break;
    case OamOpVarRequest:
        ret = oampdu_parse_request(p, pkt, len);
        break;
    case OamOpVarResponse:
        ret = oampdu_parse_response(p, pkt, len);
        break;
    case OamOpEventNotification:
        ret = oampdu_parse_event(p, pkt, len);
        break;
    case OamLegacyOpPingRequest:
        //ret = oampdu_parse_org(p, pkt, len);
        ret = false;
        break;
    case OamLegacyOpPingResponse:
        //ret = oampdu_parse_org(p, pkt, len);
        ret = false;
        break;
    case OamLegacyOpVendeorExt:
        ret = oampdu_parse_org(p, pkt, len);
        break;
    case OamOpVendorOui:
        ret = oampdu_parse_org(p, pkt, len);
        break;
    default:
        std_errmsg("opcode not support: %.2X\n", p->pdu.hdr.opcode);
        goto free_frame;
    }

    if( ret == false ){
        goto free_frame;
    }

    return p;

free_frame:
    free(*frame);
    *frame = NULL;

    return NULL;
}


void oampdu_dump_info(const oam_frame_t* frame, uint8_t* buf, size_t buflen)
{
    size_t usedlen = 0;
    tlv_elem_t* ptlvelem = NULL;
    STAILQ_FOREACH(ptlvelem, &(frame->payload.info), entry){
        switch( ptlvelem->tlv.type ){
        case    0x01:   //local information
            usedlen += snprintf(buf + usedlen, buflen, "Local Information TLV\n");
            break;
        case    0x02:   //remote information
            usedlen += snprintf(buf + usedlen, buflen, "Remote Information TLV\n");
            break;
        case    0xfe:   //vendor information
            usedlen += snprintf(buf + usedlen, buflen, "Vender Information TLV\n");
            break;
        default:
            usedlen += snprintf(buf + usedlen, buflen, "Not Supported TLV Type\n");
            break;
        }
    }
}

void oampdu_dump_org_tek_info(const oam_frame_t* frame, uint8_t* buf, size_t buflen)
{
    size_t usedlen = 0;
    uint32_t i, j;
    uint32_t oui = frame->payload.org.v.info.oui.high;
    oui = (oui << 16) + frame->payload.org.v.info.oui.low;

    buflen = (buflen - usedlen > 0) ? buflen - usedlen : 0;
    usedlen += snprintf(buf + usedlen, buflen, "Broadcom OAM Inforamtion:\n");

    buflen = (buflen - usedlen > 0) ? buflen - usedlen : 0;
    usedlen += snprintf(buf + usedlen, buflen,
                        "\tFirmware Version-----------------------------: %.2X\n"
                        "\tOUI------------------------------------------: %.6X\n"
                        "\tProduct ID-----------------------------------: %.4X\n"
                        "\tVersion--------------------------------------: %.4X\n",
                        frame->payload.org.v.info.fw_ver, oui,
                        frame->payload.org.v.info.product_id,
                        frame->payload.org.v.info.version);

    buflen = (buflen - usedlen > 0) ? buflen - usedlen : 0;
    usedlen += snprintf(buf + usedlen, buflen,
                        "\n\tExtended ID----------------------------------:\n");

    for( i = 0 ; i < sizeof(frame->payload.org.v.info.extended_id) / 16 ; i ++){
        buflen = (buflen - usedlen > 0) ? buflen - usedlen : 0;
        usedlen += snprintf(buf + usedlen, buflen,
                 "\t%.2X %.2X %.2X %.2X %.2X %.2X %.2X %.2X "
                 "%.2X %.2X %.2X %.2X %.2X %.2X %.2X %.2X\n",
                frame->payload.org.v.info.extended_id[i*16 + 0x0],
                frame->payload.org.v.info.extended_id[i*16 + 0x1],
                frame->payload.org.v.info.extended_id[i*16 + 0x2],
                frame->payload.org.v.info.extended_id[i*16 + 0x3],
                frame->payload.org.v.info.extended_id[i*16 + 0x4],
                frame->payload.org.v.info.extended_id[i*16 + 0x5],
                frame->payload.org.v.info.extended_id[i*16 + 0x6],
                frame->payload.org.v.info.extended_id[i*16 + 0x7],
                frame->payload.org.v.info.extended_id[i*16 + 0x8],
                frame->payload.org.v.info.extended_id[i*16 + 0x9],
                frame->payload.org.v.info.extended_id[i*16 + 0xA],
                frame->payload.org.v.info.extended_id[i*16 + 0xB],
                frame->payload.org.v.info.extended_id[i*16 + 0xC],
                frame->payload.org.v.info.extended_id[i*16 + 0xD],
                frame->payload.org.v.info.extended_id[i*16 + 0xE],
                frame->payload.org.v.info.extended_id[i*16 + 0xF]);
    }

    buflen = (buflen - usedlen > 0) ? buflen - usedlen : 0;
    usedlen += snprintf(buf + usedlen, buflen,
                        "\n\n\tBase MAC------------: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",
                        frame->payload.org.v.info.base_mac[0],
                        frame->payload.org.v.info.base_mac[1],
                        frame->payload.org.v.info.base_mac[2],
                        frame->payload.org.v.info.base_mac[3],
                        frame->payload.org.v.info.base_mac[4],
                        frame->payload.org.v.info.base_mac[5]);

    buflen = (buflen - usedlen > 0) ? buflen - usedlen : 0;
    usedlen += snprintf(buf + usedlen, buflen,
                        "\tMax Links------------------------------------: %d\n"
                        "\tNum Of Ports---------------------------------: %d\n"
                        "\tNum Of Assignable UpStream Queues------------: %d\n"
                        "\tMax Queues of UpStream Link------------------: %d\n"
                        "\tQueues Increment of UpStream-----------------: %d\n"
                        "\tNum Of Assignable DownStream Queues----------: %d\n"
                        "\tMax Queues of DownStream Link----------------: %d\n"
                        "\tQueues Increment of DownStream---------------: %d\n"
                        "\tUpStream Buffer Available--------------------: %d\n"
                        "\tDownStream Buffer Available------------------: %d\n"
                        "\tJEDEC Manufacturer ID------------------------: %d\n"
                        "\tChip ID--------------------------------------: %d\n"
                        "\tChip Version---------------------------------: %d\n",
                        frame->payload.org.v.info.max_links,
                        frame->payload.org.v.info.num_ports,
                        frame->payload.org.v.info.num_assignable_upstream_queues,
                        frame->payload.org.v.info.max_queue_per_link_upstream,
                        frame->payload.org.v.info.queue_increment_upstream,
                        frame->payload.org.v.info.num_assignable_downstream_queues,
                        frame->payload.org.v.info.max_queue_per_link_downstream,
                        frame->payload.org.v.info.queue_increment_downstream,
                        frame->payload.org.v.info.upstream_buffer_available,
                        frame->payload.org.v.info.downstream_buffer_available,
                        frame->payload.org.v.info.jedec_manufacturer_id,
                        frame->payload.org.v.info.chip_id,
                        frame->payload.org.v.info.chip_ver);

}


void oampdu_dump_org_tek_get_request(const oam_frame_t* frame, uint8_t* buf, size_t buflen)
{
}


void oampdu_dump_org_tek_get_response(const oam_frame_t* frame, uint8_t* buf, size_t buflen){}


void oampdu_dump_org_tek_set_request(const oam_frame_t* frame, uint8_t* buf, size_t buflen){}


void oampdu_dump_org_tek_set_response(const oam_frame_t *frame, uint8_t *buf, size_t buflen){}


void oampdu_dump_org_tek(const oam_frame_t* frame, uint8_t* buf, size_t buflen)
{
    switch (frame->payload.org.ext_opcode) {
    case OamOpOrgTekInfo:
        oampdu_dump_org_tek_info(frame, buf, buflen);
        break;
    case OamOpOrgTekGetRequest:
        oampdu_dump_org_tek_get_request(frame, buf, buflen);
        break;
    case OamOpOrgTekGetResponse:
        oampdu_dump_org_tek_get_response(frame, buf, buflen);
        break;
    case OamOpOrgTekSetRequest:
        oampdu_dump_org_tek_set_request(frame, buf, buflen);
        break;
    case OamOpOrgTekSetResponse:
        oampdu_dump_org_tek_set_response(frame, buf, buflen);
        break;
    default:
        snprintf(buf, buflen, "Not Supported Vender OpCode: %.2X\n", frame->payload.org.ext_opcode);
        break;
    }
}


void oampdu_dump_org(const oam_frame_t* frame, uint8_t* buf, size_t buflen)
{
    switch (frame->payload.org.oui) {
    case OamOUI_BROADCOM:
        oampdu_dump_org_tek(frame, buf, buflen);
        break;
    default:
        snprintf(buf, buflen, "Not Supported OUI\n");
        break;
    }
}


void oampdu_dump_attr_request(const oam_frame_t* frame, uint8_t* buf, size_t buflen)
{
    size_t usedlen = 0;

    usedlen += snprintf(buf + usedlen, buflen, "Attribute Request\n");
}


void oampdu_dump_attr_response(const oam_frame_t* frame, uint8_t* buf, size_t buflen)
{
    size_t usedlen = 0;

    usedlen += snprintf(buf + usedlen, buflen, "Attribute Response\n");
}


void oampdu_dump_loopback(const oam_frame_t* frame, uint8_t* buf, size_t buflen)
{
    size_t usedlen = 0;

    usedlen += snprintf(buf + usedlen, buflen, "Loopback Control Information\n");
}


void oampdu_dump_event(const oam_frame_t* frame, uint8_t* buf, size_t buflen)
{
    size_t usedlen = 0;

    usedlen += snprintf(buf + usedlen, buflen, "Event Notification\n");
}


void oampdu_dump(const oam_frame_t* frame, uint8_t* buf, size_t buflen)
{
    size_t usedlen;

    usedlen = 0;

    //source & destination MAC
    buflen = (buflen - usedlen) > 0 ? (buflen - usedlen) : 0;
    usedlen += snprintf(buf + usedlen, buflen, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x --> %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
                        frame->ethhdr.h_source[0], frame->ethhdr.h_source[1], frame->ethhdr.h_source[2],
                        frame->ethhdr.h_source[3], frame->ethhdr.h_source[4], frame->ethhdr.h_source[5],
                        frame->ethhdr.h_dest[0], frame->ethhdr.h_dest[1], frame->ethhdr.h_dest[2],
                        frame->ethhdr.h_dest[3], frame->ethhdr.h_dest[4], frame->ethhdr.h_dest[5]);

    //ether protocol
    buflen = (buflen - usedlen) > 0 ? (buflen - usedlen) : 0;
    usedlen += snprintf(buf + usedlen, buflen, "ether proto: %.4X\n", frame->ethhdr.h_proto);

    buflen = (buflen - usedlen) > 0 ? (buflen - usedlen) : 0;
    usedlen += snprintf(buf + usedlen, buflen, "====================OAM==================\n");

    /**
    uint16_t link_fault:1;
    uint16_t dying_gasp:1;
    uint16_t critical:1;
    uint16_t local_evaluating:1;          //3
    uint16_t local_stable:1;              //4
    uint16_t remove_evaluating:1;         //5
    uint16_t remote_stable:1;             //6
    uint16_t _reserved:9;
    */
    buflen = (buflen - usedlen) > 0 ? (buflen - usedlen) : 0;
    usedlen += snprintf(buf + usedlen, buflen, "flags:\n");

    buflen = (buflen - usedlen) > 0 ? (buflen - usedlen) : 0;
    usedlen += snprintf(buf + usedlen, buflen,
                        "\tlink fault--------------------%d\n\tdying gasp--------------------%d\n"
                        "\tcritical----------------------%d\n\tlocal evaluating--------------%d\n"
                        "\tlocal stable------------------%d\n\tremote evaluating-------------%d\n"
                        "\tremote stable-----------------%d\n\treserved----------------------%X\n",
                        frame->pdu.hdr.flags.link_fault, frame->pdu.hdr.flags.dying_gasp,
                        frame->pdu.hdr.flags.critical, frame->pdu.hdr.flags.local_evaluating,
                        frame->pdu.hdr.flags.local_stable, frame->pdu.hdr.flags.remove_evaluating,
                        frame->pdu.hdr.flags.remote_stable, frame->pdu.hdr.flags._reserved);

    buflen = (buflen - usedlen) > 0 ? (buflen - usedlen) : 0;
    usedlen += snprintf(buf + usedlen, buflen,"opcode: %.2X => %s\n",
                        frame->pdu.hdr.opcode,
                        frame->pdu.hdr.opcode == OamOpInfo ? "OAM Information" :
                        frame->pdu.hdr.opcode == OamOpEventNotification ? "Event Notification" :
                        frame->pdu.hdr.opcode == OamOpVendorOui ? "Vendor Specific" :
                        frame->pdu.hdr.opcode == OamOpVarRequest ? "Attribute Request" :
                        frame->pdu.hdr.opcode == OamOpVarResponse ? "Attribute Response" :
                        frame->pdu.hdr.opcode == OamOpLookback ? "Loopback Control" : "Not support");

    buflen = (buflen - usedlen) > 0 ? (buflen - usedlen) : 0;
    switch( frame->pdu.hdr.opcode ){
    case OamOpInfo:
        oampdu_dump_info(frame, buf + usedlen, buflen);
        break;
    case OamOpEventNotification:
        oampdu_dump_event(frame, buf + usedlen, buflen);
        break;
    case OamOpLookback:
        oampdu_dump_loopback(frame, buf + usedlen, buflen);
        break;
    case OamOpVarRequest:
        oampdu_dump_attr_request(frame, buf + usedlen, buflen);
        break;
    case OamOpVarResponse:
        oampdu_dump_attr_response(frame, buf + usedlen, buflen);
        break;
    case OamOpVendorOui:
        oampdu_dump_org(frame, buf + usedlen, buflen);
        break;
    default:
        usedlen += snprintf(buf + usedlen, buflen, "Not Supported");
        break;
    }
}
