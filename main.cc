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
#include <unistd.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>

#include "header.h"
#include "stats.h"

extern "C"
{
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
// And let user check out those information via shell.
map<string, flow_stats_t> flow_stats; 

int main(int argc, char **argv){
    // control flags
    int ch,type=0,debug=0;
    vector<string> inputfile;
    while((ch=getopt(argc, argv, "e:df:"))!=-1)
    {
        switch(ch)
        {
            case 'd':
                debug=1;
                break;
            case 'f':
                type=1; // denote as "read from file"
                optind--;
                for(;optind<argc && *argv[optind]!='-';optind++){
                    // push new file 
                    inputfile.push_back(argv[optind]);
                }
                break;
            case 'e':
                // TODO:
                type=1; // denote as "read from device", need to get the device name
                break;
        }
    }

    struct pcap_pkthdr *header; 
    const u_char *packet;
    pcap_t *handle; 
    char errbuf[PCAP_ERRBUF_SIZE];

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
        while(1){
            int ret = pcap_next_ex(handle, &header, &packet);
            if(ret==1){
                // success, then measurement apply on pcap
                
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

                    // get flow ID
                    string flowID;
                    flowID = string(inet_ntoa(ipv4->srcAddr))+string(inet_ntoa(ipv4->dstAddr));
                    unsigned int flowIndex = crc32((unsigned char *)flowID.c_str());
                    // using srcAddr as key of flow_stats, then use flowID 
                    // to store into specific flow entry own by flow_stats[srcAddr]
                    if(flow_stats.find(string(inet_ntoa(ipv4->srcAddr)))==flow_stats.end()){ 
                        // not found, need to init
                        if(flow_stats[string(inet_ntoa(ipv4->srcAddr))].pktcnt.find(flowIndex)==flow_stats[string(inet_ntoa(ipv4->srcAddr))].pktcnt.end()){ 
                            // not found, need to init
                            flow_stats[string(inet_ntoa(ipv4->srcAddr))].pktcnt[flowIndex]=1;
                        } else { 
                            // exist
                            flow_stats[string(inet_ntoa(ipv4->srcAddr))].pktcnt[flowIndex]++;
                        }
                    } else {
                        // exist
                        if(flow_stats[string(inet_ntoa(ipv4->srcAddr))].pktcnt.find(flowIndex)==flow_stats[string(inet_ntoa(ipv4->srcAddr))].pktcnt.end()){ 
                            // not found, need to init
                            flow_stats[string(inet_ntoa(ipv4->srcAddr))].pktcnt[flowIndex]=1;
                        } else { 
                            // exist
                            flow_stats[string(inet_ntoa(ipv4->srcAddr))].pktcnt[flowIndex]++;
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

            } else if(ret==0){
                fprintf(stderr, "Timeout (by libpcap)\n"); 
            } else if(ret==-1){ // end if fail
                fprintf(stderr, "pcap_next_ex(): %s\n", pcap_geterr(handle));
            } else if(ret==-2){ // end if no more packet
                cout << "No more packet from file." << endl;
                break;
            }
        }
    }

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
}