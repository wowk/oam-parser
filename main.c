#include "oam.h"
#include "logmsg.h"
#include <stdio.h>
#include <sys/queue.h>
#include <pcap.h>


int test(void)
{
    char errbuf[256] = "";
    pcap_t* pcap = pcap_open_live("enp12s0", 1500, 1, 0, errbuf);

    pcap_set_promisc(pcap, 1);

    if( !pcap ){
        std_errmsg("pcap_open_live failed");
        return -1;
    }

    while( 1 ){
        oam_frame_t* frame;
        struct pcap_pkthdr  hdr;
        uint8_t* pkt = pcap_next(pcap, &hdr);
        oampdu_parse(&frame, pkt, hdr.len);
        if( frame ){
            char buf[65536] = "";
            if( frame->pdu.hdr.opcode ){
                oampdu_dump(frame, buf, sizeof(buf) - 1);
                printf("%s\n", buf);
            }
            oampdu_free_frame(&frame);
        }
    }
    //pcap_loop(pcap, 0, pcap_cb, NULL);

    pcap_close(pcap);

    return 0;
}

int main(int argc, char *argv[])
{
    test();
}
