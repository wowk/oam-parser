#ifndef __OAMDEFS_H__
#define __OAMDEFS_H__

typedef enum {
    OamOUI_BROADCOM     = 0x000DB6,
}oam_oui_e;

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

typedef enum {
    OamBranchMACID              = 0x0001,
    OamFrameTxOK                = 0x0002,
    OamSingleCollisionFrames    = 0x0003,
    OamMultiCollisionFrames     = 0x0004,
    OamFramesRxOK               = 0x0005,
    OamFramesFCSErr             = 0x0006,
    OamAlignmentError           = 0x0007,
    OamOctetsTxOK               = 0x0008,
    OamFramesDeferred           = 0x0009,
    OamLastCollisions           = 0x000A,
    OamExcessiveCollisions      = 0x000B,
    OamLostMACTxErr             = 0x000C,
    OamOctetsRxOK               = 0x000E,
    OamFramesLostMACRxError     = 0x000F,
    OamMulticastFramesTx        = 0x0012,
    OamBroadcastFamesTx         = 0x0013,
    OamFramesExcessiveDeferral  = 0x0014,
    OamMulticastFramesRx        = 0x0015,
    OamBroadcastFramesRx        = 0x0016,
    OamInRangeLengthError       = 0x0017,
    OamOutOfRangeLengthError    = 0x0018,
    OamFrameToolLong            = 0x0019,
    OamMACEnableStatus          = 0x001A,//W
    OamMACAddr                  = 0x001D,
    OamMACCollisionFrames       = 0x001E,
    //PHY
    OamPhyType                  = 0x0020,
    OamPhySymbolErrDuringCarrier= 0x0023,
    OamPhyAdminState            = 0x0025,//W
    //MAU
    OamMAUMediaAvailable        = 0x0047,
    //Auto-negotiation
    OamAutoNegID                = 0x004E,
    OamAutoNegAdminState        = 0x004F,//W
    OamAutoNegRemoteSignal      = 0x0050,
    OamAutoNegConfig            = 0x0051,
    OamAutoNegLocalTech         = 0x0052,//W
    OamAutoNegAdverisedTech     = 0x0053,//W
    OamAutoNegRxTech            = 0x0054,
    OamAutoNegLocalSelect       = 0x0055,
    OamAutoNegAdvertSelect      = 0x0056,
    OamAutoNegRxSelect          = 0x0057,
    //MAC
    OamDuplexStatus             = 0x005A,//W
    //MAC Control
    OamMACCtrlFunctionsSupported= 0x005D,
    OamMACCtrlFramesTx          = 0x005E,
    OamMACCtrlFramesRx          = 0x005F,
    OamMACCtrlUpsupportedOpRx   = 0x0060,
    OamMACCtrlPauseDelay        = 0x0061,
    OamMACCtrlPauseTx           = 0x0062,
    OamMACCtrlPauseRx           = 0x0063,
    //OMP Emulation
    OamMpcpFramesTx             = 0x0118,
    OamMpcpFramesRx             = 0x0119,
    OamMpcpTxDiscovery          = 0x0120,
    OamMpcpDiscTimeout          = 0x0122,
    //FEC
    OamFecCorrectedBlocks       = 0x0124,
    OamFecUncorrectableBlocks   = 0x0125,
    OamFecAbility               = 0x0139,//W
    OamFecMode                  = 0x013A,//W
    //OMP Emulation
    OamMpcpTxGate               = 0x013B,
    OamMpcpTxRegAck             = 0x013C,
    OamMpcpTxRegister           = 0x013D,
    OamMpcpTxRegReq             = 0x013E,
    OamMpcpTxReport             = 0x013F,
    OamMpcpRxGate               = 0x0140,
    OamMpcpRxRegAck             = 0x0141,
    OamMpcpRxRegister           = 0x0142,
    OamMpcpRxRegReq             = 0x0143,
    OamMpcpRxReport             = 0x0144,
}oam_branch7_802_1_e;

#endif // __OAMDEFS_H__
