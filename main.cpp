#include "arpspoof.h"

using namespace std;

void usage() {
    printf("syntax : arp-spoof <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]){
    if ((argc < 4) || (argc % 2)) { // <=?
        usage();
        return -1;
    }

    ArpSpoof spoofer(argv[1]);
    for(int i = 2; i < argc; i++) {
        spoofer.append_flows(argv[i]);
    }
    spoofer.connect_flows();
    spoofer.capture_packet(NULL);
    
    
    return 0;
}