#include <stdlib.h>
#include <stdio.h>

#include <string.h>
#include <pcap/pcap.h>

#include <arpa/inet.h>
#include <stdint.h>
#include <linux/if.h>
#include <sys/ioctl.h>
#include <zconf.h>
#include <netinet/in.h>

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
    u_char hlen[1]; // Hardware address's length - 1byte
    u_char plen[1]; // protocol address's length - 1byte
    u_char opcode[2]; // reply & request - 2byte
    u_char srcMAC[6]; // source protocol address - 6byte
    u_char srcIP[4]; // Source protocol Address - 4byte
    u_char dstMAC[6]; // destination protocol address - 6byte
    u_char dstIP[4]; // destination protocol address - 4byte

}ARP_hdr;

// ethernet protocol, ethernet type, arp protocol, arp-operation
typedef struct{
    u_char destination[6];
    u_char source[6];
    u_char Type[2];
}ETHER_hdr;

typedef struct{
    ETHER_hdr eth;
    ARP_hdr arp;
}packet_type;

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

void getSendMac(u_char* MAC, const u_char* pck){
    for(int i = 32;i<32+6;i++){
        MAC[i-32] = pck[i];
    }
}


void getTargetMac(u_char* MAC, const u_char* pck){
    for(int i = 32;i<32+6;i++){
        MAC[i-32] = pck[i];
    }
}

int getMyMac(char* myMac){
    struct ifreq s;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    strcpy(s.ifr_name, "wlp0s20f3");
    if(!ioctl(fd, SIOCGIFHWADDR, &s)){
        printf("\n");
        for(int i =0; i<6; i++){
            myMac[i] = s.ifr_addr.sa_data[i];
            printf("%x ", myMac[i]);
        }
    }
    return 1;
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

    struct pcap_pkthdr* header;
    const uint8_t* packet;

    u_char data[] ={
            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xd0, 0xc6, 0x37, 0xd3, 0x10, 0x0d,
            0x08, 0x06,
            0x00, 0x01,
            0x08, 0x00,
            0x06, 0x04,
            0x00, 0x01,
            0x3c, 0xf0, 0x11, 0x28, 0x2b, 0xbb,
            0xc0, 0xa8, 0x2b, 0x7,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xc0, 0xa8, 0x2b, 43
    };

    u_char dest[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
    memcpy(pck.eth.destination, dest,  6);
    u_char source[6] = {0xd0, 0xc6, 0x37, 0xd3, 0x10, 0x0d};
    memcpy(pck.eth.source, source, 6);
    u_char type[2] = {0x08, 0x06};
    memcpy(pck.eth.Type, type, 6);
    u_char hat[2] = {0x00, 0x01};
    memcpy(pck.arp.hat, )


    // TODO argv로 온 값 대체하기
    // 구조체화 시키기
    u_char seMac[6];
    pcap_sendpacket(handle, (const u_char*) &data, 42);

    while(true){
        if(pcap_next_ex(handle, &header, &packet) == 0)
            continue;

         if(isARP(packet) && isMyRep(packet, &packet[28])){
             //reply 왔을때
             printf("\nREP\n");
             //TODO 맥어드레스 구하기
             getSendMac(seMac, packet);
             printf("%s", seMac);
             break;

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