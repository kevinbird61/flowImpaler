/**
 * FlowImpaler: 
 * Provide a CLI to let user inspect the traffic 
 * information in flow-level, e.g. inspect the number of packets
 * by specify "srcIP" + "dstIP".
 * 
 * Author: Kevin Cyu (kevinbird61@gmail.com)
 */
#include <cmath>
#include <iomanip> 
#include <iostream>

#include "header.h"
#include "stats.h"
#include "sh.h"

extern "C"
{
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <unistd.h>
#include "signal.h"
#include "lib/hash.h"
#include "xxhash.h"
}

#define SIZE_ETHER 14
const struct sniff_ethernet *ethernet; // ethernet header
const struct sniff_ipv4 *ipv4; // IPv4 header
const struct sniff_tcp *tcp;   // TCP header
const struct sniff_udp *udp;   // UDP header
const struct sniff_icmp *icmp; // ICMP header
const char *payload; // packet payload
u_int size_existed=0;

using namespace std;

// Directly display status
unsigned long int pktcnt=0;
unsigned long int arpcnt=0;
unsigned long int ipv4cnt=0;
unsigned long int ipv6cnt=0;
unsigned long int icmpcnt=0;
unsigned long int tcpcnt=0;
unsigned long int udpcnt=0; 

// All packet information will be extracted and store in here.
pcap_t *handle; 
// And let user check out those information via shell.
map<string, flow_stats_t> flow_stats; 

// packet processing for live capturing
void pkt_process(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void alarm_handler(int sig){ pcap_breakloop(handle); }

int main(int argc, char **argv){
    // control flags
    int ch,type=0,debug=0,timeout=0,npkts=100;
    vector<string> inputfile;
    while((ch=getopt(argc, argv, "hdc:f:t:"))!=-1)
    {
        switch(ch)
        {
            case 'd':
                // TODO:
                type=1; // denote as "read from device", need to get the device name
                break;
            case 'c':
                // set number of packet
                cout << "Set number of capturing packets: " << optarg << "." << endl;
                npkts = atoi(optarg);
                break;
            case 't':
                // set timeout 
                cout << "Set timeout value: " << optarg << " (s)." << endl;
                timeout = atoi(optarg);
                break;
            case 'f':
                type=0; // denote as "read from file"
                optind--;
                for(;optind<argc && *argv[optind]!='-';optind++){
                    // push new file 
                    inputfile.push_back(argv[optind]);
                }
                break;
            case 'h':
                // print manual 
                cout << "\nWelcome to use FlowImpaler!" << "\n"
                    << "Support options:" << "\n"
                    << "-----------------------------------------------------------------------------------------" << "\n"
                    << "-d : read from device. (will listen on default network interface, i.e. enpXs0)" << "\n"
                    << "-t : specify timeout of reading process in seconds. (only enable when you use '-d')" << "\n"
                    << "-c : specify number of captured packets in reading process. (only enable when you use '-d')" << "\n"
                    << "\t (\033[1;31m Notice! -c has higher priority than -t\33[0m )\n"
                    << "-f \033[1;36m<pcap file>\033[0m : specify the pcap file. (offline mode)\n"
                    << "-----------------------------------------------------------------------------------------" << "\n"
                    << "If you have counter any problem, feel free to contact me: \n"
                    << " Email: kevinbird61@gmail.com\n"
                    << " Github: github.com/kevinbird61\n"
                    << endl;
                exit(1);
        }
    }

    struct pcap_pkthdr *header; 
    const u_char *packet;
    char *device = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];

    if(type){
        // read from device 
        device = pcap_lookupdev(errbuf);
        if(!device){
            fprintf(stderr, "pcap_lookupdev(): %s\n", errbuf);
            exit(1);
        }

        cout << "Sniffing interface: " << device << endl;
        cout << "Timeout value (s): " << timeout << endl;

        // open intf 
        handle = pcap_open_live(device, 65535, 1, 1000, errbuf);
        if(!handle){
            fprintf(stderr, "pcap_open_live(): %s\n", errbuf);
            exit(1);
        }

        // if timeout > 0, then set breakloop
        if(timeout>0){
            alarm(timeout);
            signal(SIGALRM, alarm_handler);
            // process unlimit
            pcap_loop(handle, 0, pkt_process, NULL);
        } else {
            // process pkt
            pcap_loop(handle, npkts, pkt_process, NULL);
        }

    } else {
        // traverse all input files
        for(int i=0;i<inputfile.size();i++){
            cout << "Input pcap filename: " << inputfile.at(i) << endl;
            // open 
            handle=pcap_open_offline(inputfile.at(i).c_str(), errbuf);
            if(handle==NULL){
                fprintf(stderr, "Couldn't open pcap file: %s\n", inputfile.at(i).c_str()); 
                fprintf(stderr, "%s\n", errbuf);
                return(2); 
            }
            // success, read pcap file and store into pre-defined data structure
            pcap_loop(handle, 0, pkt_process, NULL);
        }    
    }

    // free
    pcap_close(handle);

    cout << "=====================================================" << endl;
    cout << "Unique hosts (IP): " << flow_stats.size() << endl;
    cout << "Total amount of packets: " << pktcnt << endl;
    printf("%-10s %-s: %3.5f %%\n", "ARP", "(%)", arpcnt*100/(float)pktcnt);
    printf("%-10s %-s: %3.5f %%\n", "IPv4", "(%)", ipv4cnt*100/(float)pktcnt);
    printf("%-10s %-s: %3.5f %%\n", "|- TCP", "(%)", tcpcnt*100/(float)pktcnt);
    printf("%-10s %-s: %3.5f %%\n", "|- UDP", "(%)", udpcnt*100/(float)pktcnt);
    printf("%-10s %-s: %3.5f %%\n", "|- ICMP", "(%)", icmpcnt*100/(float)pktcnt);
    printf("%-10s %-s: %3.5f %%\n", "IPv6", "(%)", ipv6cnt*100/(float)pktcnt);
    printf("%-10s %-s: %3.5f %%\n", "Other", "(%)", (pktcnt-arpcnt-ipv4cnt-ipv6cnt)*100/(float)pktcnt);
    cout << "=====================================================" << endl;
    
    // after collecting all packet information, start the shell
    sh_loop(flow_stats);

    return 0;
}

void pkt_process(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    // inc pktcnt
    pktcnt++;
    /* ========================================== */
    /* Ethernet */
    /* ========================================== */
    ethernet=(struct sniff_ethernet*)(packet);
    size_existed+=SIZE_ETHER;

    // base on EtherType to parse next header (L3)
    if(ntohs(ethernet->etherType)==0x0800){
        ipv4cnt++;
        /* ========================================== */
        /* IPv4 */
        /* ========================================== */
        ipv4=(struct sniff_ipv4*)(packet + size_existed);
        int size_ip = IP_HL(ipv4)*4;
        size_existed += size_ip;
        
        // using srcAddr as key of flow_stats, then use flowID 
        // to store into specific flow entry own by flow_stats[srcAddr]
        if(flow_stats.find(string(inet_ntoa(ipv4->srcAddr)))==flow_stats.end()){ 
            // not found, need to init
            if(flow_stats[string(inet_ntoa(ipv4->srcAddr))].pktcnt.find(string(inet_ntoa(ipv4->dstAddr)))==flow_stats[string(inet_ntoa(ipv4->srcAddr))].pktcnt.end()){ 
                // not found, need to init
                flow_stats[string(inet_ntoa(ipv4->srcAddr))].pktcnt[string(inet_ntoa(ipv4->dstAddr))].srcIP=string(inet_ntoa(ipv4->srcAddr));
                flow_stats[string(inet_ntoa(ipv4->srcAddr))].pktcnt[string(inet_ntoa(ipv4->dstAddr))].dstIP=string(inet_ntoa(ipv4->dstAddr));
                flow_stats[string(inet_ntoa(ipv4->srcAddr))].pktcnt[string(inet_ntoa(ipv4->dstAddr))].cnt=1;
            } else { 
                // exist
                flow_stats[string(inet_ntoa(ipv4->srcAddr))].pktcnt[string(inet_ntoa(ipv4->dstAddr))].cnt++;
            }
        } else {
            // exist
            if(flow_stats[string(inet_ntoa(ipv4->srcAddr))].pktcnt.find(string(inet_ntoa(ipv4->dstAddr)))==flow_stats[string(inet_ntoa(ipv4->srcAddr))].pktcnt.end()){ 
                // not found, need to init
                flow_stats[string(inet_ntoa(ipv4->srcAddr))].pktcnt[string(inet_ntoa(ipv4->dstAddr))].srcIP=string(inet_ntoa(ipv4->srcAddr));
                flow_stats[string(inet_ntoa(ipv4->srcAddr))].pktcnt[string(inet_ntoa(ipv4->dstAddr))].dstIP=string(inet_ntoa(ipv4->dstAddr));
                flow_stats[string(inet_ntoa(ipv4->srcAddr))].pktcnt[string(inet_ntoa(ipv4->dstAddr))].cnt=1;
            } else { 
                // exist
                flow_stats[string(inet_ntoa(ipv4->srcAddr))].pktcnt[string(inet_ntoa(ipv4->dstAddr))].cnt++;
            }
        } 

        // save for bi-direction (rev)
        if(flow_stats.find(string(inet_ntoa(ipv4->dstAddr)))==flow_stats.end()){
            // not found, need to init
            if(flow_stats[string(inet_ntoa(ipv4->dstAddr))].pktcnt.find(string(inet_ntoa(ipv4->srcAddr)))==flow_stats[string(inet_ntoa(ipv4->dstAddr))].pktcnt.end()){ 
                // not found, need to init
                flow_stats[string(inet_ntoa(ipv4->dstAddr))].pktcnt[string(inet_ntoa(ipv4->srcAddr))].srcIP=string(inet_ntoa(ipv4->dstAddr));
                flow_stats[string(inet_ntoa(ipv4->dstAddr))].pktcnt[string(inet_ntoa(ipv4->srcAddr))].dstIP=string(inet_ntoa(ipv4->srcAddr));
                flow_stats[string(inet_ntoa(ipv4->dstAddr))].pktcnt[string(inet_ntoa(ipv4->srcAddr))].cnt=1;
            } else { 
                // exist
                flow_stats[string(inet_ntoa(ipv4->dstAddr))].pktcnt[string(inet_ntoa(ipv4->srcAddr))].cnt++;
            }
        }

        if(size_ip < 20){
            fprintf(stderr, "Invalid IPv4 header length: %u bytes\n", size_ip);
        } else {
            // base on Protocol number to parse next header (L4)
            if(ipv4->protocol==(u_char)1){
                // ICMP
                icmpcnt++;
                icmp=(struct sniff_icmp*)(packet + size_existed);
                size_existed+=4; // 4 bytes 

                // TODO
            }
            else if(ipv4->protocol==(u_char)6){
                // TCP 
                tcpcnt++;
                tcp=(struct sniff_tcp*)(packet + size_existed);
                size_existed+=TH_OFF(tcp)*4;

                // cout << string(inet_ntoa(ipv4->srcAddr)) << "-> " << string(inet_ntoa(ipv4->dstAddr)) << endl; 

            } else if(ipv4->protocol==(u_char)17){
                // UDP
                udpcnt++;
                udp=(struct sniff_udp*)(packet + size_existed);
                size_existed += 8;
            }
        }

        /* ========================================== */
        /* TODO: Other L3 protocol ... */
        /* ========================================== */
    } else if(ntohs(ethernet->etherType)==0x0806){
        // ARP
        arpcnt++;
        // TODO
    } else if(ntohs(ethernet->etherType)==0x86DD){
        // IPv6
        ipv6cnt++;
        // TODO
    }

    /* ========================================== */
    /* TODO: Other L2 protocol ... */
    /* ========================================== */
    // rest part (payload)
    payload=(char*)(packet+size_existed);
    size_existed=0; // reset
}