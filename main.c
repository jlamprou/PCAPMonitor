/*
Role: MSc Student
Name: Ioannis Lamprou
Student ID: 2023039016
Email: ilamprou1@tuc.gr
*/

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <string.h>
#include <slcurses.h>


struct hash_map {
    char key[100];
    int value;
    int size;
    struct hash_map *next;
};

struct hash_map *hashmap_new() {
    struct hash_map *map = malloc(sizeof(struct hash_map));
    map->size = 0;
    map->next = NULL;
    return map;
}

bool hash_map_contains(char key[100], struct hash_map *map) {
    struct hash_map *current = map;
    while (current != NULL) {
        if (strcmp(current->key, key) == 0) {
            return TRUE;
        }
        current = current->next;
    }
    return FALSE;
}

void hash_map_insert(char key[100], int value, struct hash_map *map) {
    struct hash_map *current = map;
    while (current != NULL) {
        if (strcmp(current->key, key) == 0) {
            // Key already exists, update the value
            current->value = value;
            return;
        }
        current = current->next;
    }
    // Key does not exist, create a new node
    struct hash_map *new_node = malloc(sizeof(struct hash_map));
    strcpy(new_node->key, key);
    new_node->value = value;
    new_node->next = map->next;
    map->next = new_node;
    map->size++;
}

void hashmap_free(struct hash_map *map) {
    struct hash_map *current = map;
    struct hash_map *next;
    while (current != NULL) {
        next = current->next;
        free(current);
        current = next;
    }
}

void get_tcp_packet(const u_char *packet, struct hash_map *tcp_map) {
    struct iphdr *ip_header = (struct iphdr *) (packet + sizeof(struct ethhdr));
    unsigned short iphdrlen = ip_header->ihl * 4;
    struct tcphdr *tcp_header = (struct tcphdr *) (packet + iphdrlen + sizeof(struct ethhdr));
    int header_size = sizeof(struct ethhdr) + iphdrlen + tcp_header->doff * 4;
    int data_size = ntohs(ip_header->tot_len) - (ip_header->ihl * 4) - (tcp_header->doff * 4);
    char *data = (char *) (packet + header_size);
    printf("    TCP Packet\n");
    printf("       Source Port: %u\n", ntohs(tcp_header->source));
    printf("       Destination Port: %u\n", ntohs(tcp_header->dest));
    printf("       Header Length: %d\n", tcp_header->doff * 4);
    printf("       Payload Length: %d\n", data_size);
    printf("       Payload: ");
    for (int i = 0; i < data_size && data[i] != NULL; i++) {
        printf("%02X ", data[i]);
        if (i == 99 && data_size > 100) {
            printf("......");
            break;
        }
    }
    printf("\n");

    char key[100];
    sprintf(key, "%s:%s:%d:%d:%u", inet_ntoa(*(struct in_addr *) &ip_header->saddr),
            inet_ntoa(*(struct in_addr *) &ip_header->daddr), ntohs(tcp_header->source), ntohs(tcp_header->dest),
            ntohl(tcp_header->seq));
    if (hash_map_contains(key, tcp_map)) {
        printf("       Status: Retransmitted\n");
    }
}

void get_udp_packet(const u_char *packet) {
    struct iphdr *ip_header = (struct iphdr *) (packet + sizeof(struct ethhdr));
    unsigned short iphdrlen = ip_header->ihl * 4;
    struct udphdr *udp_header = (struct udphdr *) (packet + iphdrlen + sizeof(struct ethhdr));
    int header_size = sizeof(struct ethhdr) + iphdrlen + sizeof(udp_header);
    char *data = (char *) (packet + header_size);
    int data_size = ntohs(ip_header->tot_len) - (ip_header->ihl * 4) - sizeof(struct udphdr);
    printf("    UDP Packet\n");
    printf("       Source Port: %u\n", ntohs(udp_header->source));
    printf("       Destination Port: %u\n", ntohs(udp_header->dest));
    printf("       Header Length: %lu\n", sizeof(udp_header));
    printf("       Payload Length: %d\n", data_size);
    printf("       Payload: ");
    for (int i = 0; i < data_size && data[i] != NULL; i++) {
        printf("%02X ", data[i]);
        if (i == 99 && data_size > 100) {
            printf("......");
            break;
        }
    }
    printf("\n");
}

// For IPv4 and IPv6
void get_ip_header(const u_char *packet) {
    struct ether_header *eth_header = (struct ether_header *) packet;
    if (ntohs(eth_header->ether_type) == ETH_P_IP) {
        struct iphdr *ip_header = (struct iphdr *) (packet + sizeof(struct ethhdr));
        printf("    IP Header\n");
        printf("       IP Version: %d\n", (unsigned int) ip_header->version);
        printf("       Header Length: %d\n", ip_header->ihl * 4);
        printf("       Total Length: %d\n", ntohs(ip_header->tot_len));
        printf("       Protocol: %d\n", (unsigned int) ip_header->protocol);
        printf("       Source IP Address: %s\n", inet_ntoa(*(struct in_addr *) &ip_header->saddr));
        printf("       Destination IP Address: %s\n", inet_ntoa(*(struct in_addr *) &ip_header->daddr));
    } else if (ntohs(eth_header->ether_type) == ETH_P_IPV6) {
        struct ip6_hdr *ip6_header = (struct ip6_hdr *) (packet + sizeof(struct ethhdr));
        printf("    IP Header\n");
        printf("       IP Version: %d\n", (unsigned int) ip6_header->ip6_vfc >> 4);
        printf("       Header Length: %d\n", sizeof(struct ip6_hdr));
        printf("       Total Length: %d\n", ntohs(ip6_header->ip6_plen));
        printf("       Protocol: %d\n", (unsigned int) ip6_header->ip6_nxt);

        char str_src[INET6_ADDRSTRLEN];
        char str_dst[INET6_ADDRSTRLEN];

        inet_ntop(AF_INET6, &(ip6_header->ip6_src), str_src, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ip6_header->ip6_dst), str_dst, INET6_ADDRSTRLEN);

        printf("       Source IP Address: %s\n", str_src);
        printf("       Destination IP Address: %s\n", str_dst);
    }
}

void get_ethernet_header(const u_char *packet) {
    struct ethhdr *eth_header = (struct ethhdr *) packet;
    printf("    Ethernet Header\n");
    printf("       Destination MAC Address: %02X:%02X:%02X:%02X:%02X:%02X\n", eth_header->h_dest[0],
           eth_header->h_dest[1], eth_header->h_dest[2], eth_header->h_dest[3], eth_header->h_dest[4],
           eth_header->h_dest[5]);
    printf("       Source MAC Address: %02X:%02X:%02X:%02X:%02X:%02X\n", eth_header->h_source[0],
           eth_header->h_source[1], eth_header->h_source[2], eth_header->h_source[3], eth_header->h_source[4],
           eth_header->h_source[5]);
    printf("       Protocol: %d\n", eth_header->h_proto);
}

void get_data(const u_char *packet, int size) {
    printf("    Data\n");
    printf("       Payload Length: %d\n", size);
    printf("       Payload: ");
    for (int i = 0; i < 100; i++) {
        printf("%02X ", (unsigned char) packet[i]);
    }
    if (packet[101] != NULL) {
        printf("......");
    }
    printf("\n");
}

// Modify the get_statistics function
void get_statistics(int total, int tcp_total, int udp_total, int tcp_bytes, int udp_bytes, int tcp_retransmissions,
                    struct hash_map *tcp_flows, struct hash_map *udp_flows) {
    printf("########################Statistics########################\n");
    printf("Total number of packets: %d\n", total);
    printf("Total number of TCP packets: %d\n", tcp_total);
    printf("Total number of UDP packets: %d\n", udp_total);
    printf("Total number of TCP bytes: %d\n", tcp_bytes);
    printf("Total number of UDP bytes: %d\n", udp_bytes);
    printf("Total number of TCP packets (including retransmissions): %d\n", tcp_total + tcp_retransmissions);
    printf("Total number of network flows captured: %d\n", tcp_flows->size + udp_flows->size);
    printf("Number of TCP network flows captured: %d\n", tcp_flows->size);
    printf("Number of UDP network flows captured: %d\n", udp_flows->size);
    printf("################################################################\n");
}

int main(int argc, char *argv[]) {
    char error_buf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    FILE *ff;
    bpf_u_int32 mask;
    bpf_u_int32 net;
    struct pcap_pkthdr header;
    const u_char *packet;
    int tcp_total = 0;
    int udp_total = 0;
    int tcp_bytes = 0;
    int udp_bytes = 0;
    int total_packets = 0;
    int switcher;
    int tcp_retransmissions = 0;
    struct hash_map *tcp_map = hashmap_new();
    struct hash_map *tcp_flows = hashmap_new();
    struct hash_map *udp_flows = hashmap_new();
    char *filter_exp = NULL;
    char *file_name = NULL;
    char *interface_name = NULL;
    int mode = 0; // 0 for live, 1 for offline
    while ((switcher = getopt(argc, argv, "i:r:f:h")) != -1) {
        switch (switcher) {
            case 'i':
                interface_name = optarg;
                break;
            case 'r':
                file_name = optarg;
                mode = 1;
                break;
            case 'f':
                filter_exp = optarg;
                break;
            case 'h':
                printf("Usage: pcap_ex [-i interface_name] [-r file_name] [-f filter_exp] [-h]\n");
                printf("Filter expressions : https://www.tcpdump.org/manpages/pcap-filter.7.html\n");
                printf("Available filters:\n");
                printf("    dst host host\n");
                printf("    src host host\n");
                printf("    host host\n");
                printf("    ether dst mac\n");
                printf("    ether src mac\n");
                printf("    ether host mac\n");
                printf("    gateway host\n");
                printf("    dst net net\n");
                printf("    src net net\n");
                printf("    net net\n");
                printf("    dst port port\n");
                printf("    src port port\n");
                printf("    port port\n");
                printf("    tcp\n");
                printf("    udp\n");
                printf("    icmp\n");
                printf("    less size\n");
                printf("    greater size\n");
                return 0;
            default:
                printf("Usage: pcap_ex [-i interface_name] [-r file_name] [-f filter_exp] [-h]\n");
                return 0;
        }
    }


    //If the user does not provide any parameter, the program should print the help message
    //and exit.
    if (interface_name == NULL && file_name == NULL) {
        printf("Usage: pcap_ex [-i interface_name] [-r file_name] [-f filter_exp] [-h]\n");
        return 0;
    }
        //If the user provides both -i and -r parameters, the program should print the help
        //message and exit.
    else if (interface_name != NULL && file_name != NULL) {
        printf("Usage: pcap_ex [-i interface_name] [-r file_name] [-f filter_exp] [-h]\n");
        return 0;
    }
        //If the user provides -i parameter, the program should start capturing packets from the network interface.
    else if (interface_name != NULL) {
        //Find the properties for the device
        if (pcap_lookupnet(interface_name, &net, &mask, error_buf) == -1) {
            fprintf(stderr, "Can't get netmask for device %s\n", interface_name);
            net = 0;
            mask = 0;
        }
        //Live session
        handle = pcap_open_live(interface_name, BUFSIZ, 1, 1000, error_buf);
        if (handle == NULL) {
            fprintf(stderr, "Couldn't open device %s: %s\n", interface_name, error_buf);
            return (2);
        }
    }
        //If the user provides -r parameter, the program should read the packets from the pcap file.
    else if (file_name != NULL) {
        handle = pcap_open_offline(file_name, error_buf);
        if (handle == NULL) {
            fprintf(stderr, "Couldn't open file %s: %s\n", file_name, error_buf);
            return (2);
        }
    } else {
        printf("Usage: pcap_ex [-i interface_name] [-r file_name] [-f filter_exp] [-h]\n");
        return 0;
    }
    //Loop through the packets and process them
    int ret;
    while ((ret = pcap_next_ex(handle, (struct pcap_pkthdr **) &header, &packet)) >= 0) {
        if (ret == 0)
            continue; // Timeout set on pcap_open_live has elapsed. Retry.
        if (ret == -2)
            break; // EOF
        if (ret == -1) {
            fprintf(stderr, "Error reading the packets: %s\n", pcap_geterr(handle));
            return (2);
        }
        total_packets++;
        if (filter_exp != NULL) {
            struct ethhdr *eth_header = (struct ethhdr *) packet;
            struct iphdr *ip_header = (struct iphdr *) (packet + sizeof(struct ethhdr));
            unsigned short iphdrlen = ip_header->ihl * 4;
            // Filter expressions : https://www.tcpdump.org/manpages/pcap-filter.7.html
            // dst host:
            if (strstr(filter_exp, "dst host") != NULL) {
                char *token;
                if ((token = strstr(filter_exp, "dst host")) != NULL) {
                    token += strlen("dst host ");
                    if (strcmp(token, inet_ntoa(*(struct in_addr *) &ip_header->daddr)) != 0) {
                        continue;
                    }
                }

            }
            // src host:
            if (strstr(filter_exp, "src host") != NULL) {
                char *token;
                if ((token = strstr(filter_exp, "src host")) != NULL) {
                    token += strlen("src host ");
                    if (strcmp(token, inet_ntoa(*(struct in_addr *) &ip_header->saddr)) != 0) {
                        continue;
                    }
                }
            }
            // host:
            if (strstr(filter_exp, "host") != NULL) {
                char *token;
                if ((token = strstr(filter_exp, "host")) != NULL) {
                    token += strlen("host ");
                    if (strcmp(token, inet_ntoa(*(struct in_addr *) &ip_header->saddr)) != 0 &&
                        strcmp(token, inet_ntoa(*(struct in_addr *) &ip_header->daddr)) != 0) {
                        continue;
                    }
                }
            }
            // ether dst:
            if (strstr(filter_exp, "ether dst") != NULL) {
                char *token;
                if ((token = strstr(filter_exp, "ether dst")) != NULL) {
                    token += strlen("ether dst ");
                    char *mac = strtok(token, ":");
                    int i;
                    for (i = 0; i < 6; i++) {
                        if (mac[i] == '*') {
                            continue;
                        }
                        if (mac[i] != eth_header->h_dest[i]) {
                            break;
                        }
                    }
                    if (i != 6) {
                        continue;
                    }
                }
            }
            // ether src:
            if (strstr(filter_exp, "ether src") != NULL) {
                char *token;
                if ((token = strstr(filter_exp, "ether src")) != NULL) {
                    token += strlen("ether src ");
                    char *mac = strtok(token, ":");
                    int i;
                    for (i = 0; i < 6; i++) {
                        if (mac[i] == '*') {
                            continue;
                        }
                        if (mac[i] != eth_header->h_source[i]) {
                            break;
                        }
                    }
                    if (i != 6) {
                        continue;
                    }
                }
            }
            // ether host:
            if (strstr(filter_exp, "ether host") != NULL) {
                char *token;
                if ((token = strstr(filter_exp, "ether host")) != NULL) {
                    token += strlen("ether host ");
                    char *mac = strtok(token, ":");
                    int i;
                    for (i = 0; i < 6; i++) {
                        if (mac[i] == '*') {
                            continue;
                        }
                        if (mac[i] != eth_header->h_source[i] && mac[i] != eth_header->h_dest[i]) {
                            break;
                        }
                    }
                    if (i != 6) {
                        continue;
                    }
                }
            }
            // gateway:
            if (strstr(filter_exp, "gateway") != NULL) {
                char *token;
                if ((token = strstr(filter_exp, "gateway")) != NULL) {
                    token += strlen("gateway ");
                    if (strcmp(token, inet_ntoa(*(struct in_addr *) &ip_header->daddr)) != 0 &&
                        strcmp(token, inet_ntoa(*(struct in_addr *) &ip_header->saddr)) != 0) {
                        continue;
                    }
                }
            }
            // dst net:
            if (strstr(filter_exp, "dst net") != NULL) {
                char *token;
                if ((token = strstr(filter_exp, "dst net")) != NULL) {
                    token += strlen("dst net ");
                    if (strcmp(token, inet_ntoa(*(struct in_addr *) &ip_header->daddr)) != 0) {
                        continue;
                    }
                }
            }
            // src net:
            if (strstr(filter_exp, "src net") != NULL) {
                char *token;
                if ((token = strstr(filter_exp, "src net")) != NULL) {
                    token += strlen("src net ");
                    if (strcmp(token, inet_ntoa(*(struct in_addr *) &ip_header->saddr)) != 0) {
                        continue;
                    }
                }
            }
            // net:
            if (strstr(filter_exp, "net") != NULL) {
                char *token;
                if ((token = strstr(filter_exp, "net")) != NULL) {
                    token += strlen("net ");
                    if (strcmp(token, inet_ntoa(*(struct in_addr *) &ip_header->saddr)) != 0 &&
                        strcmp(token, inet_ntoa(*(struct in_addr *) &ip_header->daddr)) != 0) {
                        continue;
                    }
                }
            }
            // dst port:
            if (strstr(filter_exp, "dst port") != NULL) {
                char *token;
                if ((token = strstr(filter_exp, "dst port")) != NULL) {
                    token += strlen("dst port ");
                    int port = atoi(token);
                    if (ip_header->protocol == IPPROTO_TCP) {
                        struct tcphdr *tcp_header = (struct tcphdr *) (packet + iphdrlen + sizeof(struct ethhdr));
                        if (ntohs(tcp_header->dest) != port) {
                            continue;
                        }
                    } else if (ip_header->protocol == IPPROTO_UDP) {
                        struct udphdr *udp_header = (struct udphdr *) (packet + iphdrlen + sizeof(struct ethhdr));
                        if (ntohs(udp_header->dest) != port) {
                            continue;
                        }
                    } else {
                        continue;
                    }
                }
            }
            // src port:
            if (strstr(filter_exp, "src port") != NULL) {
                char *token;
                if ((token = strstr(filter_exp, "src port")) != NULL) {
                    token += strlen("src port ");
                    int port = atoi(token);
                    if (ip_header->protocol == IPPROTO_TCP) {
                        struct tcphdr *tcp_header = (struct tcphdr *) (packet + iphdrlen + sizeof(struct ethhdr));
                        if (ntohs(tcp_header->source) != port) {
                            continue;
                        }
                    } else if (ip_header->protocol == IPPROTO_UDP) {
                        struct udphdr *udp_header = (struct udphdr *) (packet + iphdrlen + sizeof(struct ethhdr));
                        if (ntohs(udp_header->source) != port) {
                            continue;
                        }
                    } else {
                        continue;
                    }
                }
            }
            // port:
            if (strstr(filter_exp, "port") != NULL) {
                char *token;
                if ((token = strstr(filter_exp, "port")) != NULL) {
                    token += strlen("port ");
                    int port = atoi(token);
                    if (ip_header->protocol == IPPROTO_TCP) {
                        struct tcphdr *tcp_header = (struct tcphdr *) (packet + iphdrlen + sizeof(struct ethhdr));
                        if (ntohs(tcp_header->source) != port && ntohs(tcp_header->dest) != port) {
                            continue;
                        }
                    } else if (ip_header->protocol == IPPROTO_UDP) {
                        struct udphdr *udp_header = (struct udphdr *) (packet + iphdrlen + sizeof(struct ethhdr));
                        if (ntohs(udp_header->source) != port && ntohs(udp_header->dest) != port) {
                            continue;
                        }
                    } else {
                        continue;
                    }
                }
            }
            // tcp:
            if (strstr(filter_exp, "tcp") != NULL) {
                if (ip_header->protocol != IPPROTO_TCP) {
                    continue;
                }
            }
            // udp:
            if (strstr(filter_exp, "udp") != NULL) {
                if (ip_header->protocol != IPPROTO_UDP) {
                    continue;
                }
            }
            // icmp:
            if (strstr(filter_exp, "icmp") != NULL) {
                if (ip_header->protocol != IPPROTO_ICMP) {
                    continue;
                }
            }
            // less:
            if (strstr(filter_exp, "less") != NULL) {
                char *token;
                if ((token = strstr(filter_exp, "less")) != NULL) {
                    token += strlen("less ");
                    int size = atoi(token);
                    if (size <= ntohs(ip_header->tot_len)) {
                        continue;
                    }
                }
            }
            // greater:
            if (strstr(filter_exp, "greater") != NULL) {
                char *token;
                if ((token = strstr(filter_exp, "greater")) != NULL) {
                    token += strlen("greater ");
                    int size = atoi(token);
                    if (size >= ntohs(ip_header->tot_len)) {
                        continue;
                    }
                }
            }
            // invalid filter expression
            if (strstr(filter_exp, "dst host") == NULL && strstr(filter_exp, "src host") == NULL &&
                strstr(filter_exp, "host") == NULL && strstr(filter_exp, "ether dst") == NULL &&
                strstr(filter_exp, "ether src") == NULL && strstr(filter_exp, "ether host") == NULL &&
                strstr(filter_exp, "gateway") == NULL && strstr(filter_exp, "dst net") == NULL &&
                strstr(filter_exp, "src net") == NULL && strstr(filter_exp, "net") == NULL &&
                strstr(filter_exp, "dst port") == NULL && strstr(filter_exp, "src port") == NULL &&
                strstr(filter_exp, "port") == NULL && strstr(filter_exp, "tcp") == NULL &&
                strstr(filter_exp, "udp") == NULL && strstr(filter_exp, "icmp") == NULL &&
                strstr(filter_exp, "less") == NULL && strstr(filter_exp, "greater") == NULL) {
                printf("Invalid filter expression\n");
                return 0;
            }
            // Counters
            if (ip_header->protocol == IPPROTO_TCP) {
                struct tcphdr *tcp_header = (struct tcphdr *) (packet + iphdrlen + sizeof(struct ethhdr));
                tcp_total++;
                tcp_bytes += ntohs(ip_header->tot_len) - (ip_header->ihl * 4) - (tcp_header->doff * 4);
            } else if (ip_header->protocol == IPPROTO_UDP) {
                udp_total++;
                udp_bytes += ntohs(ip_header->tot_len) - (ip_header->ihl * 4) - sizeof(struct udphdr);
            } else {
                continue;
            }
        } else {
            // check tcp or udp
            struct iphdr *ip_header = (struct iphdr *) (packet + sizeof(struct ethhdr));
            unsigned short iphdrlen = ip_header->ihl * 4;
            // Check if the packet is TCP
            if (ip_header->protocol == IPPROTO_TCP) {
                struct tcphdr *tcp_header = (struct tcphdr *) (packet + iphdrlen + sizeof(struct ethhdr));
                int data_size = ntohs(ip_header->tot_len) - (ip_header->ihl * 4) - (tcp_header->doff * 4);
                tcp_total++;
                tcp_bytes += data_size;
            }
                // Check if the packet is UDP
            else if (ip_header->protocol == IPPROTO_UDP) {
                int data_size = ntohs(ip_header->tot_len) - (ip_header->ihl * 4) - sizeof(struct udphdr);
                udp_total++;
                udp_bytes += data_size;
            } else {
                continue;
            }
        }
        //You should write the outputs of the execution (with -i) in a log.txt file and the outputs of
        //the execution (with -r) appear in the terminal.
        if (mode == 0) {
            ff = freopen("log.txt", "a+", stdout);
        }
        printf("########################Packet number: %d########################\n", total_packets);
        get_ethernet_header(packet);
        get_ip_header(packet);
        // Check if the packet is TCP
        struct iphdr *ip_header = (struct iphdr *) (packet + sizeof(struct ethhdr));
        unsigned short iphdrlen = ip_header->ihl * 4;
        if (ip_header->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp_header = (struct tcphdr *) (packet + iphdrlen + sizeof(struct ethhdr));
            char key[100];
            char flow[200];
            sprintf(key, "%s:%s:%d:%d:%u", inet_ntoa(*(struct in_addr *) &ip_header->saddr),
                    inet_ntoa(*(struct in_addr *) &ip_header->daddr), ntohs(tcp_header->source),
                    ntohs(tcp_header->dest), ntohl(tcp_header->seq));
            sprintf(flow, "%s:%s:%d:%d", inet_ntoa(*(struct in_addr *) &ip_header->saddr),
                    inet_ntoa(*(struct in_addr *) &ip_header->daddr), ntohs(tcp_header->source),
                    ntohs(tcp_header->dest));
            if (hash_map_contains(key, tcp_map)) {
                tcp_retransmissions++;
            } else {
                hash_map_insert(key, 1, tcp_map);
            }
            if (!hash_map_contains(flow, tcp_flows)) {
                hash_map_insert(flow, 1, tcp_flows);
            }
            get_tcp_packet(packet, tcp_map);
        }
            // Check if the packet is UDP
        else if (ip_header->protocol == IPPROTO_UDP) {
            struct udphdr *udp_header = (struct udphdr *) (packet + iphdrlen + sizeof(struct ethhdr));
            char flow[200];
            sprintf(flow, "%s:%s:%d:%d", inet_ntoa(*(struct in_addr *) &ip_header->saddr),
                    inet_ntoa(*(struct in_addr *) &ip_header->daddr), ntohs(udp_header->source),
                    ntohs(udp_header->dest));
            if (!hash_map_contains(flow, udp_flows)) {
                hash_map_insert(flow, 1, udp_flows);
            }
            get_udp_packet(packet);
        } else {
            get_data(packet, header.len);
        }
        printf("################################################################\n");
        if (mode == 0) {
            fclose(ff);
        }
    }
    if (mode == 0) {
        ff = freopen("log.txt", "a+", stdout);
        get_statistics(total_packets, tcp_total, udp_total, tcp_bytes, udp_bytes, tcp_retransmissions, tcp_flows,
                       udp_flows);
        fclose(ff);
    } else {
        get_statistics(total_packets, tcp_total, udp_total, tcp_bytes, udp_bytes, tcp_retransmissions, tcp_flows,
                       udp_flows);
    }
    hashmap_free(tcp_map);
    hashmap_free(tcp_flows);
    hashmap_free(udp_flows);

}