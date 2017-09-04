#include "oam.h"
#include "logmsg.h"
#include <stdio.h>
#include <sys/queue.h>
#include <pcap.h>


void pcap_cb(u_char * user, const struct pcap_pkthdr * hdr, const u_char * bytes)
{
    oam_frame_t* frame;
    oampdu_parse(&frame, bytes, hdr->len);
    if( frame ){
        free(frame);
    }
}

int test(void)
{
    char errbuf[256] = "";
    pcap_t* pcap = pcap_open_live("enp12s0", 1500, 1, 20, errbuf);

    if( !pcap ){
        std_errmsg("pcap_open_live failed");
        return -1;
    }

    pcap_loop(pcap, 0, pcap_cb, NULL);

    pcap_close(pcap);

    return 0;
}

int main(int argc, char *argv[])
{
    test();
}
