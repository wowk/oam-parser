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

    tmp->jedec_manufacturer_id  = ntohs(tmp->jedec_manufacturer_id);
    tmp->upstream_buffer_available = ntohs(tmp->upstream_buffer_available);
    tmp->downstream_buffer_available = ntohs(tmp->downstream_buffer_available);

    return true;
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
    bool done = false;
    leaf_item_t* tmp = NULL;
    leaf_t* p = NULL;

    if( len < 3 ){
        return false;
    }

    STAILQ_INIT(&(frame->payload.org.v.greq));

    while( !done && len >= 3 ){

        p = (leaf_t*)pkt;

        switch( p->branch ){
        case OamBranchOrgTekEnd:
        case OamBranchOrgTekObject:
        case OamBranchOrgTekPackage:
        case OamBranchOrgTekAttribute:
        case OamBranchOrgTekAction:
            tmp = (leaf_item_t*)malloc(sizeof(leaf_item_t));
            if( !tmp ) goto free_tlvs;
            tmp->leaf.branch = p->branch;
            tmp->leaf.v.leaf = ntohs(p->v.leaf);
            STAILQ_INSERT_TAIL(&(frame->payload.org.v.greq), tmp, entry);
            pkt += 3;
            len -= 3;
            if( p->branch == OamBranchOrgTekEnd ){
                done = true;
            }
            std_errmsg("branch= %.2X, leaf= %.4X", p->branch, tmp->leaf.v.leaf);
            break;

        case OamBranchOrgTekNameBinding:
            std_errmsg("len = %d", len);
            if( len < 4 ) goto free_tlvs;

            size_t ext_len = (p->width == 0x80 ? 0 : p->width);
            tmp = (leaf_item_t*)malloc(sizeof(leaf_item_t) + ext_len);
            if( !tmp ) goto free_tlvs;

            tmp->leaf.branch = p->branch;
            tmp->leaf.v.leaf = ntohs(p->v.leaf);
            tmp->leaf.width = p->width;
            memcpy(tmp->leaf.value, p->value, ext_len);
            STAILQ_INSERT_TAIL(&(frame->payload.org.v.greq), tmp, entry);

            pkt += 4 + ext_len;
            len -= 4 + ext_len;

            std_errmsg("branch= %.2X, leaf= %.4X", p->branch, tmp->leaf.v.type);
            if( p->branch == 0 ) done = true;
            break;
        default:
            goto free_tlvs;
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
    bool done = false;
    leaf_item_t* tmp = NULL;
    leaf_t* p = NULL;

    if( len < 3 ){
        return false;
    }

    STAILQ_INIT(&(frame->payload.org.v.gresp));

    while( !done && len >= 3 ){

        p = (leaf_t*)pkt;

        switch( p->branch ){
        case OamBranchOrgTekEnd:
            tmp = (leaf_item_t*)malloc(sizeof(leaf_item_t));
            if( !tmp ) goto free_tlvs;
            tmp->leaf.branch = p->branch;
            tmp->leaf.v.leaf = ntohs(p->v.leaf);
            STAILQ_INSERT_TAIL(&(frame->payload.org.v.gresp), tmp, entry);
            pkt += 3;
            len -= 3;
            done = true;
            std_errmsg("branch= %.2X, leaf= %.4X", p->branch, tmp->leaf.v.leaf);
            break;

        case OamBranchOrgTekObject:
        case OamBranchOrgTekPackage:
        case OamBranchOrgTekAttribute:
        case OamBranchOrgTekAction:
        case OamBranchOrgTekNameBinding:
            std_errmsg("len = %d", len);
            if( len < 4 ) goto free_tlvs;

            size_t ext_len = (p->width == 0x80 ? 0 : p->width);
            tmp = (leaf_item_t*)malloc(sizeof(leaf_item_t) + ext_len);
            if( !tmp ) goto free_tlvs;

            tmp->leaf.branch = p->branch;
            tmp->leaf.v.leaf = ntohs(p->v.leaf);
            tmp->leaf.width = p->width;
            memcpy(tmp->leaf.value, p->value, ext_len);
            STAILQ_INSERT_TAIL(&(frame->payload.org.v.gresp), tmp, entry);

            pkt += 4 + ext_len;
            len -= 4 + ext_len;

            std_errmsg("branch= %.2X, leaf= %.4X", p->branch, tmp->leaf.v.type);
            if( p->branch == 0 ) done = true;
            break;

        default:
            std_errmsg("branch ID=%.2X", p->branch);
            goto free_tlvs;
            break;
        }
    }

    return true;

free_tlvs:
    STAILQ_RELEASE(&(frame->payload.org.v.greq), entry);
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
    bool done = false;
    leaf_item_t* tmp = NULL;
    leaf_t* p = NULL;

    if( len < 3 ){
        return false;
    }

    STAILQ_INIT(&(frame->payload.org.v.sreq));

    while( !done && len >= 3 ){

        p = (leaf_t*)pkt;

        switch( p->branch ){
        case OamBranchOrgTekEnd:
            tmp = (leaf_item_t*)malloc(sizeof(leaf_item_t));
            if( !tmp ) goto free_tlvs;
            tmp->leaf.branch = p->branch;
            tmp->leaf.v.leaf = ntohs(p->v.leaf);
            STAILQ_INSERT_TAIL(&(frame->payload.org.v.gresp), tmp, entry);
            pkt += 3;
            len -= 3;
            done = true;
            std_errmsg("branch= %.2X, leaf= %.4X", p->branch, tmp->leaf.v.leaf);
            break;

        case OamBranchOrgTekObject:
        case OamBranchOrgTekPackage:
        case OamBranchOrgTekAttribute:
        case OamBranchOrgTekAction:
        case OamBranchOrgTekNameBinding:
            std_errmsg("len = %d", len);
            if( len < 4 ) goto free_tlvs;

            size_t ext_len = (p->width == 0x80 ? 0 : p->width);
            tmp = (leaf_item_t*)malloc(sizeof(leaf_item_t) + ext_len);
            if( !tmp ) goto free_tlvs;

            tmp->leaf.branch = p->branch;
            tmp->leaf.v.leaf = ntohs(p->v.leaf);
            tmp->leaf.width = p->width;
            memcpy(tmp->leaf.value, p->value, ext_len);
            STAILQ_INSERT_TAIL(&(frame->payload.org.v.sreq), tmp, entry);

            pkt += 4 + ext_len;
            len -= 4 + ext_len;

            std_errmsg("branch= %.2X, leaf= %.4X", p->branch, tmp->leaf.v.type);
            if( p->branch == 0 ) done = true;
            break;

        default:
            std_errmsg("branch ID=%.2X", p->branch);
            goto free_tlvs;
            break;
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
    bool done = false;
    leaf_item_t* tmp = NULL;
    leaf_t* p = NULL;

    if( len < 3 ){
        return false;
    }

    STAILQ_INIT(&(frame->payload.org.v.sresp));

    while( !done && len >= 3 ){

        p = (leaf_t*)pkt;

        switch( p->branch ){
        case OamBranchOrgTekEnd:
            tmp = (leaf_item_t*)malloc(sizeof(leaf_item_t));
            if( !tmp ) goto free_tlvs;

            tmp->leaf.branch = p->branch;
            tmp->leaf.v.leaf = ntohs(p->v.leaf);
            STAILQ_INSERT_TAIL(&(frame->payload.org.v.gresp), tmp, entry);
            pkt += 3;
            len -= 3;
            done = true;
            std_errmsg("branch= %.2X, leaf= %.4X", p->branch, tmp->leaf.v.leaf);
            break;

        case OamBranchOrgTekObject:
        case OamBranchOrgTekPackage:
        case OamBranchOrgTekAttribute:
        case OamBranchOrgTekAction:
        case OamBranchOrgTekNameBinding:
            std_errmsg("len = %d", len);
            if( len < 4 ) goto free_tlvs;

            size_t ext_len = ((p->width == 0x80 || p->width == 0xA1) ? 0 : p->width);
            tmp = (leaf_item_t*)malloc(sizeof(leaf_item_t) + ext_len);
            if( !tmp ) goto free_tlvs;

            tmp->leaf.branch = p->branch;
            tmp->leaf.v.leaf = ntohs(p->v.leaf);
            tmp->leaf.width = p->width;
            memcpy(tmp->leaf.value, p->value, ext_len);
            STAILQ_INSERT_TAIL(&(frame->payload.org.v.sresp), tmp, entry);

            pkt += 4 + ext_len;
            len -= 4 + ext_len;

            std_errmsg("branch= %.2X, leaf= %.4X", p->branch, tmp->leaf.v.type);
            if( p->branch == 0 ) done = true;
            break;

        default:
            std_errmsg("branch ID=%.2X", p->branch);
            goto free_tlvs;
            break;
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
    //support branch 0/3/4/6/7/9
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
    pkt += hlen;
    len -= hlen;

    //protocol num MUST be 0x8809
    if( ntohs(p->ethhdr.h_proto) != 0x8809 ){
        goto free_frame;
    }

    //parse oam pdu header
    hlen = sizeof((*frame)->pdu);
    if( hlen > len ){
        goto free_frame;
    }
    memcpy(&((*frame)->pdu), pkt, hlen);
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


void oampdu_dump(const oam_frame_t* frame)
{

}
