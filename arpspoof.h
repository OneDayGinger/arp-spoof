#pragma once

#include <cstdint>
#include <iostream>
#include <fstream>
#include <pcap.h>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#include "gilgil_lib/arphdr.h"
#include "gilgil_lib/ethhdr.h"

struct Flow {
    Ip* ip_;
    Mac* mac_;
    Flow* pair_flow_;
};

struct EthArpHeader {
    EthHdr eth_;
    ArpHdr arp_;
};

struct IpHdr{ // header from pcap-test
    u_char header_len; // bit calculation needed (45 -> 5), 15
	u_char dummy1;
    u_short total_len; // 17, 18
	u_char dummy2[5];
    u_char protocol; // has to be 06, 24
	u_char dummy3[2];
	uint32_t saddr_IP; // 27~30
	uint32_t daddr_IP; // 31~34
};

class ArpSpoof {
private:

    Mac* Mac_0_;
    Mac* Mac_f_;

    std::vector<Flow*> flow_list_;
    char* device_;
    Mac* my_MAC_;
    Ip* my_ip_;
    pcap_t* handle_;
    char errbuf_[PCAP_ERRBUF_SIZE];
    enum flow_enum_ {MY_FLOW = 0, PAIR_FLOW = 1};

    void resolve_MAC(Flow* flow);
    void arp_infect(Flow* flow);
    void process_arp(ArpHdr* arphdr);
    void send_arp_packet(Mac* eth_dmac, Mac* eth_smac, int arp_type, Mac* arp_smac, Ip* arp_sip, Mac* arp_tmac, Ip* arp_tip);
    void send_packet(u_char* packet, int size);
    void relay_packet(Flow* flow, u_char* packet, unsigned int size);
    Mac* get_my_MAC();
    Ip* get_my_ip();
    Flow* check_flow(Mac* target_mac, int flow_enum);

public:
    
    ArpSpoof(char* device);
    ~ArpSpoof();

    void connect_flows();
    Mac* capture_packet(Ip* target_ip);
    void append_flows(char* input_ip);
};