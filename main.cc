/**
 * FlowImpaler: 
 * Provide a CLI to let user inspect the traffic 
 * information in flow-level, e.g. inspect the number of packets
 * by specify "srcIP" + "dstIP".
 * 
 * Author: Kevin Cyu (kevinbird61@gmail.com)
 */
#include <iostream>
#include <iomanip> 
#include <chrono>
#include <ctime>  
#include <cmath>

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

#define VERSION "1.0.0"
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

chrono::time_point<std::chrono::system_clock> t_start, t_end;

// All packet information will be extracted and store in here.
pcap_t *handle; 
// And let user check out those information via shell.
map<string, flow_stats_t> flow_stats; 
traffic_t traffic_stats;

// packet processing for live capturing
void pkt_process(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void alarm_handler(int sig){ pcap_breakloop(handle); }
void print_help_msg();

int main(int argc, char **argv){
    // start computing ts
    t_start = chrono::system_clock::now();
    // control flags
    int ch,type=0,debug=0,timeout=0,npkts=100;
    vector<string> inputfile;
    // init for traffic_stats
    traffic_stats.flowlet_timeout=0.1;
    traffic_stats.filename="";
    traffic_stats.flen_threshold=1000;
    traffic_stats.port_threshold=1000;
    traffic_stats.rst_threshold=100;
    traffic_stats.icmp3_threshold=100;
    traffic_stats.sr_threshold=10000;
    // argparse 
    while((ch=getopt(argc, argv, "vhdc:f:t:p:"))!=-1)
    {
        switch(ch)
        {
            case 'c':
                // set number of packet
                cout << "Set number of capturing packets: " << optarg << "." << endl;
                npkts = atoi(optarg);
                break;
            case 'd':
                // TODO:
                type=1; // denote as "read from device", need to get the device name
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
                print_help_msg();
                exit(1);
            case 'p':
                // set port threshold
                traffic_stats.port_threshold=atoi(optarg);
                break;
            case 't':
                // set timeout 
                cout << "Set timeout value: " << optarg << " (s)." << endl;
                timeout = atoi(optarg);
                break;
            case 'v':
                // print version
                cout << "flowimpaler version: " << VERSION << endl;
                cout << "Author: Kevin Cyu (2019)" << endl;
                exit(1);
            default:
                print_help_msg();
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
            // store filename 
            traffic_stats.filename+=inputfile.at(i);
            // open 
            handle=pcap_open_offline(inputfile.at(i).c_str(), errbuf);
            if(handle==NULL){
                fprintf(stderr, "Couldn't open pcap file: %s\n", inputfile.at(i).c_str()); 
                fprintf(stderr, "%s\n", errbuf);
                return(2); 
            }
            // success, read pcap file and store into pre-defined data structure
            cout << "Reading all packets from pcap: " << inputfile.at(i) << endl;
            pcap_loop(handle, 0, pkt_process, NULL);
            cout << "Reading process finished, enter CLI & data preprocessing ..." << endl;
        }    
    }

    // free
    pcap_close(handle);
    // end 
    t_end = chrono::system_clock::now();
    chrono::duration<double> elapsed_seconds = t_end-t_start;
    time_t end_time = chrono::system_clock::to_time_t(t_end);

    cout << "=====================================================" << endl;
    cout << "Finished at " << ctime(&end_time)
              << "Elapsed time: " << elapsed_seconds.count() << " (sec)\n";
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
    
    traffic_stats.pktcnt=pktcnt;
    traffic_stats.arpcnt=arpcnt;
    traffic_stats.ipv4cnt=ipv4cnt;
    traffic_stats.ipv6cnt=ipv6cnt;
    traffic_stats.tcpcnt=tcpcnt;
    traffic_stats.udpcnt=udpcnt;
    traffic_stats.icmpcnt=icmpcnt;

    // after collecting all packet information, start the shell
    traffic_stats.flow_stats=flow_stats;
    sh_loop(traffic_stats);

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

    double curr_ts = (header->ts.tv_sec + header->ts.tv_usec/1000.0);
    string srcIP,dstIP;
    u_short sport,dport;

    // base on EtherType to parse next header (L3)
    if(ntohs(ethernet->etherType)==0x0800){
        ipv4cnt++;
        /* ========================================== */
        /* IPv4 */
        /* ========================================== */
        ipv4=(struct sniff_ipv4*)(packet + size_existed);
        int size_ip = IP_HL(ipv4)*4;
        size_existed += size_ip;

        srcIP=string(inet_ntoa(ipv4->srcAddr));
        dstIP=string(inet_ntoa(ipv4->dstAddr));
        
        // using srcAddr as key of flow_stats, then use flowID 
        // to store into specific flow entry own by flow_stats[srcAddr]
        if(flow_stats.find(srcIP)==flow_stats.end()){
            // not found, need to init
            flow_stats[srcIP].pktcnt[dstIP].srcIP=srcIP;
            flow_stats[srcIP].pktcnt[dstIP].dstIP=dstIP;
            flow_stats[srcIP].pktcnt[dstIP].cnt=1;
        } else {
            if(flow_stats[srcIP].pktcnt.find(dstIP)==flow_stats[srcIP].pktcnt.end()){ 
                // not found, need to init
                flow_stats[srcIP].pktcnt[dstIP].srcIP=srcIP;
                flow_stats[srcIP].pktcnt[dstIP].dstIP=dstIP;
                flow_stats[srcIP].pktcnt[dstIP].cnt=1;
            } else { 
                // exist
                flow_stats[srcIP].pktcnt[dstIP].cnt++;
            }
        }

        // bidirection
        if(flow_stats.find(dstIP)==flow_stats.end()){
            flow_stats[dstIP].pktcnt[srcIP].srcIP=dstIP;
            flow_stats[dstIP].pktcnt[srcIP].dstIP=srcIP;
            flow_stats[dstIP].pktcnt[srcIP].cnt=1;
        } else {
            if(flow_stats[dstIP].pktcnt.find(srcIP)==flow_stats[dstIP].pktcnt.end()){ 
                // not found, need to init
                flow_stats[dstIP].pktcnt[srcIP].srcIP=dstIP;
                flow_stats[dstIP].pktcnt[srcIP].dstIP=srcIP;
                flow_stats[dstIP].pktcnt[srcIP].cnt=1;
            } else { 
                // exist
                flow_stats[dstIP].pktcnt[srcIP].cnt++;
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

                // ICMP network unreachable
                if(icmp->type==(u_char)3 || icmp->type==(u_char)11 || icmp->type==(u_char)12){
                    flow_stats[srcIP].pktcnt[dstIP].unreachable_cnt++;
                }
            }
            else if(ipv4->protocol==(u_char)6){
                // TCP 
                tcpcnt++;
                tcp=(struct sniff_tcp*)(packet + size_existed);
                size_existed+=TH_OFF(tcp)*4;

                // port record
                sport=tcp->sport;
                dport=tcp->dport;

                // Calculate TCP control flags
                if(tcp->flags&TH_SYN && tcp->flags&TH_ACK){
                    // SYN+ACK
                } else if(tcp->flags&TH_SYN && ((tcp->flags&TH_ACK)!=TH_ACK) ){
                    // SYN
                    flow_stats[srcIP].pktcnt[dstIP].sent_syn++;
                    flow_stats[dstIP].pktcnt[srcIP].recv_syn++;
                    // record ts 
                    flow_stats[srcIP].pktcnt[dstIP].ts_syn_sent = curr_ts;
                    flow_stats[dstIP].pktcnt[srcIP].ts_syn_received = curr_ts;
                    
                } else if(tcp->flags&TH_ACK && ((tcp->flags&TH_SYN)!=TH_SYN) ){
                    // ACK
                    flow_stats[srcIP].pktcnt[dstIP].sent_ack++;
                    flow_stats[dstIP].pktcnt[srcIP].recv_ack++;
                    // record timestamp 
                    flow_stats[srcIP].pktcnt[dstIP].lastseen_ts=curr_ts;
                    flow_stats[dstIP].pktcnt[srcIP].lastseen_ts=curr_ts;
                    // calculate pending duration in 3-way handshake (e.g. half-open)
                    if(flow_stats[dstIP].pktcnt[srcIP].ts_syn_received!=0){
                        double pending_duration = curr_ts - flow_stats[dstIP].pktcnt[srcIP].ts_syn_received;
                        if(pending_duration>0)
                            flow_stats[dstIP].pktcnt[srcIP].half_open_duration_q.push_back(pending_duration);
                    }
                    if(flow_stats[srcIP].pktcnt[dstIP].ts_syn_sent!=0){
                        // sent
                        double pending_duration = curr_ts - flow_stats[srcIP].pktcnt[dstIP].ts_syn_sent;
                        if(pending_duration>0)
                            flow_stats[srcIP].pktcnt[dstIP].half_open_duration_q.push_back(pending_duration);
                    }
                    
                } else if(tcp->flags&TH_FIN){
                    // FIN 
                    flow_stats[srcIP].pktcnt[dstIP].sent_fin++;
                    flow_stats[dstIP].pktcnt[srcIP].recv_fin++;
                } else if(tcp->flags&TH_RST){
                    // RST
                    flow_stats[srcIP].pktcnt[dstIP].sent_rst++;
                    flow_stats[dstIP].pktcnt[srcIP].recv_rst++;
                    // current time 
                    double duration_src = curr_ts - flow_stats[srcIP].pktcnt[dstIP].lastseen_ts;
                    double duration_dst = curr_ts - flow_stats[dstIP].pktcnt[srcIP].lastseen_ts;
                    // store into duration queue
                    if(duration_src > 0)
                        flow_stats[srcIP].pktcnt[dstIP].duration_q.push_back(duration_src);
                    if(duration_dst > 0)
                        flow_stats[dstIP].pktcnt[srcIP].duration_q.push_back(duration_dst);
                }

            } else if(ipv4->protocol==(u_char)17){
                // UDP
                udpcnt++;
                udp=(struct sniff_udp*)(packet + size_existed);
                size_existed += 8;

                // port record
                sport=udp->sport;
                dport=udp->dport;
            }

            // Store the port information into flow_stats
            flow_stats[srcIP].pktcnt[dstIP].sport_unique[sport]++;
            flow_stats[srcIP].pktcnt[dstIP].dport_unique[dport]++;
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

    // get interval
    if(flow_stats[srcIP].pktcnt[dstIP].lastseen_ts!=0){
        // exist, update timestamp
        double intr = std::abs(curr_ts - flow_stats[srcIP].pktcnt[dstIP].lastseen_ts);
        flow_stats[srcIP].pktcnt[dstIP].pkt_interval.push_back(intr);
        flow_stats[srcIP].pktcnt[dstIP].lastseen_ts=curr_ts;
        // interval > flowlet_timeout or not
        if(intr > traffic_stats.flowlet_timeout){
            // push current flowlet_pktcnt into flowlet_queue
            flow_stats[srcIP].pktcnt[dstIP].flowlet_q.push_back(flow_stats[srcIP].pktcnt[dstIP].flowlet_pktcnt);
            flow_stats[srcIP].pktcnt[dstIP].flowlet_pktcnt=1;
            flow_stats[srcIP].pktcnt[dstIP].flowlet_duration_q.push_back(flow_stats[srcIP].pktcnt[dstIP].flowlet_duration);
            flow_stats[srcIP].pktcnt[dstIP].flowlet_duration=0;
        } else {
            // increment flowlet_pktcnt
            flow_stats[srcIP].pktcnt[dstIP].flowlet_pktcnt++;
            // increment duration
            flow_stats[srcIP].pktcnt[dstIP].flowlet_duration+=intr;
        }
    } else {
        // update timestamp
        flow_stats[srcIP].pktcnt[dstIP].lastseen_ts=curr_ts;
        // init for flowlet 
        flow_stats[srcIP].pktcnt[dstIP].flowlet_pktcnt=1;
        flow_stats[srcIP].pktcnt[dstIP].flowlet_duration=0;
    }

    // store packet length 
    flow_stats[srcIP].pktcnt[dstIP].pktlen_q.push_back(header->len);

    // rest part (payload)
    payload=(char*)(packet+size_existed);
    size_existed=0; // reset
}

void print_help_msg()
{
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
}