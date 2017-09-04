#include "oam.h"
#include "logmsg.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <errno.h>
#include <arpa/inet.h>



bool oampdu_parse_info(oam_frame_t* frame, uint8_t* pkt, size_t len)
{
    tlv_t* ptlv = (tlv_t*)pkt;
    oam_pdu_info_t* info = &(frame->payload.info);

    STAILQ_INIT(&(info->tlvs));

    std_errmsg("oampdu: len = %d, tlvLen = %d", len, ptlv->len);
    while( len >= sizeof(tlv_t) && ptlv->len && ptlv->len <= len ){
        size_t elen = sizeof( tlv_elem_t) + ptlv->len - sizeof(tlv_t);
        tlv_elem_t* e = (tlv_elem_t*)malloc(elen);

        if( !e ){
            goto free_tlvs;
        }else{
            memcpy(&(e->tlv), pkt, ptlv->len);
            STAILQ_INSERT_TAIL(&(info->tlvs), e, entry);
            pkt += ptlv->len;
            len -= ptlv->len;
            ptlv = (tlv_t*)pkt;
        }
    }

    return true;

free_tlvs:
    while( 1 ){
        tlv_elem_t* e = STAILQ_FIRST(&(info->tlvs));
        if( e ){
            STAILQ_REMOVE_HEAD(&(info->tlvs), entry);
            free(e);
        }
    }

    return false;
}

bool oampdu_parse_event(oam_frame_t* frame, uint8_t* pkt, size_t len)
{
    tlv_t* ptlv = (tlv_t*)pkt;
    oam_pdu_event_t* ev = &(frame->payload.event);

    STAILQ_INIT(&(ev->tlvs));

    ev->sequence = ntohs(*(uint16_t*)(pkt));
    pkt += sizeof(uint16_t);
    len -= sizeof(uint16_t);

    std_errmsg("found event notification");
    while( len >= sizeof(tlv_t) && ptlv->len && ntohs(ptlv->len) <= len ){
        size_t elen = sizeof( tlv_elem_t) + ptlv->len - sizeof(tlv_t);
        tlv_elem_t* e = (tlv_elem_t*)malloc(elen);

        if( !e ){
            goto free_tlvs;
        }else{
            memcpy(&(e->tlv), pkt, ptlv->len);
            STAILQ_INSERT_TAIL(&(ev->tlvs), e, entry);
            pkt += ptlv->len;
            len -= ptlv->len;
        }
    }

    return true;

free_tlvs:
    while( 1 ){
        tlv_elem_t* e = STAILQ_FIRST(&(ev->tlvs));
        if( e ){
            STAILQ_REMOVE_HEAD(&(ev->tlvs), entry);
            free(e);
        }
    }
    return false;
}

bool oampdu_parse_org_teknovus_info(oam_frame_t* frame, uint8_t* pkt, size_t len)
{
    return true;
}

bool oampdu_parse_org_teknovus_get_request(oam_frame_t* frame, uint8_t* pkt, size_t len)
{
    return true;
}

bool oampdu_parse_org_teknovus_get_response(oam_frame_t* frame, uint8_t* pkt, size_t len)
{
    return true;
}

bool oampdu_parse_org_teknovus_set_request(oam_frame_t* frame, uint8_t* pkt, size_t len)
{
    return true;
}

bool oampdu_parse_org_teknovus_set_response(oam_frame_t* frame, uint8_t* pkt, size_t len)
{
    return true;
}

bool oampdu_parse_org_teknovus(oam_frame_t* frame, uint8_t* pkt, size_t len)
{
    bool ret;
    oam_pdu_org_t* org = &(frame->payload.org);

    static const uint8_t GET_INFO = 0x0;
    static const uint8_t GET_REQUEST = 0x1;
    static const uint8_t GET_RESPONSE = 0x2;
    static const uint8_t SET_REQUEST = 0x3;
    static const uint8_t SET_RESPONSE = 0x4;

    pkt += 4;
    len -= 4;

    if( GET_INFO == org->ext_opcode ){
        ret = oampdu_parse_org_teknovus_info(frame, pkt, len);
    }else if( GET_REQUEST == org->ext_opcode ){
        ret = oampdu_parse_org_teknovus_get_request(frame, pkt, len);
    }else if( GET_RESPONSE == org->ext_opcode ){
        ret = oampdu_parse_org_teknovus_get_response(frame, pkt, len);
    }else if( SET_REQUEST == org->ext_opcode ){
        ret = oampdu_parse_org_teknovus_set_request(frame, pkt, len);
    }else if( SET_RESPONSE == org->ext_opcode ){
        ret = oampdu_parse_org_teknovus_set_response(frame, pkt, len);
    }else{
        std_errmsg("ext_opcode not supported");
        return false;
    }

    if( !ret ){
        std_errmsg("error happend");
        return false;
    }

    return true;
}

bool oampdu_parse_org(oam_frame_t* frame, uint8_t* pkt, size_t len)
{
    //support branch 0/3/4/6/7/9
    oam_pdu_org_t* org = &(frame->payload.org);

    memcpy(org, pkt, sizeof(uint32_t));

    if( ntohl(org->oui) == 0x000db600 ){
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
        std_errmsg("not oam pdu: %.4X", ntohs(p->ethhdr.h_proto));
        goto free_frame;
    }

    //parse oam pdu header
    hlen = sizeof((*frame)->pdu);
    if( hlen > len ){
        std_errmsg("invalid oam pdu");
        goto free_frame;
    }
    memcpy(&((*frame)->pdu), pkt, hlen);
    pkt += hlen;
    len -= hlen;

    //subtype must be 0x3
    if( p->pdu.hdr.subtype != 0x3 ){
        std_errmsg("not a oam pdu");
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
