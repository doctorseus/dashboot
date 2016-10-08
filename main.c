#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

void packet_handler(u_char *args, const struct pcap_pkthdr* header, const u_char* packet);

int main(int argc, char *argv[]) {
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "No device could be found: %s\n", errbuf);
        return EXIT_FAILURE;
    }

    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 0, 5000, errbuf);
    if (handle == NULL) {
         fprintf(stderr, "Failed to open device %s: %s\n", dev, errbuf);
         return EXIT_FAILURE;
    }
     
    struct bpf_program arp_filter;
    char *arp_filter_exp = "arp";
    if (pcap_compile(handle, &arp_filter, arp_filter_exp, 0, 0) == -1) {
        fprintf(stderr, "Failed to compile filter expression: %s\n", errbuf);
        return EXIT_FAILURE;
    }

    if (pcap_setfilter(handle, &arp_filter) == -1) {
        fprintf(stderr, "Failed to set filter: %s\n", errbuf);
        return EXIT_FAILURE;
    }   

    printf("Listing for arp packages on device: %s\n", dev);
    pcap_loop(handle, 0, packet_handler, NULL);

    return EXIT_SUCCESS;
}

void packet_handler(u_char *args, const struct pcap_pkthdr* header, const u_char* packet) {
    struct ether_header *eth;
    eth = (struct ether_header *) packet;

    char* mac_dashbutton = "50:f5:da:2f:4c:d1";
    char *cmd = "etherwake -i wlan0 90:2b:34:a1:c0:67";

    
    if(ntohs(eth->ether_type) == ETHERTYPE_ARP) {
        struct ether_addr source;
        memcpy(&source, eth->ether_shost, sizeof(source));
        char* mac_source = ether_ntoa(&source);

        if(strcmp(mac_dashbutton, mac_source) == 0) {
            printf("Amazon dash button (%s) press detected. Execute command \"%s\".\n", mac_source, cmd);
            
            pid_t pid = fork();
            if(pid == 0){
                if(execl("/bin/sh", "sh", "-c", cmd, (char*)0) == -1) {
                    fprintf(stderr, "Failed run command \"%s\": %s\n", cmd, strerror(errno));
                }
            }

        }

    }
}

