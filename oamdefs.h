#ifndef __OAMDEFS_H__
#define __OAMDEFS_H__

typedef enum {
    OamOpOrgTekInfo          = 0x0,
    OamOpOrgTekGetRequest    = 0x1,
    OamOpOrgTekGetResponse   = 0x2,
    OamOpOrgTekSetRequest    = 0x3,
    OamOpOrgTekSetResponse   = 0x4,
    OamOpOrgTekMCRegRequest  = 0x6,
    OamOpOrgTekMCRegResponse = 0x7,
} oam_opcode_org_tek_e;

typedef enum {
    OamOpInfo                   = 0x00,
    OamOpEventNotification      = 0x01,
    OamOpVarRequest             = 0x02,
    OamOpVarResponse            = 0x03,
    OamOpLookback               = 0x04,
    OamLegacyOpVendeorExt       = 0x80,
    OamLegacyOpPingRequest      = 0x8B,
    OamLegacyOpPingResponse     = 0x8C,
    OamOpVendorOui              = 0xfe,
} oam_opcode_e;

typedef enum {
    OamTlvNull          = 0x00,
    OamTlvLocalInfo     = 0x01,
    OamTlvRemoteInfo    = 0x02,
    OamTlvOrgSpec       = 0xfe,
} oam_tlv_type_e;

typedef enum {
    OamBranchOrgTekEnd          = 0x00,
    OamBranchOrgTekObject       = 0x03,
    OamBranchOrgTekPackage      = 0x04,
    OamBranchOrgTekNameBinding  = 0x06,
    OamBranchOrgTekAttribute    = 0x07,
    OamBranchOrgTekAction       = 0x09,
} oam_branch_org_tek_e;

#endif // __OAMDEFS_H__
