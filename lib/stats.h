#ifndef __STATS__
#define __STATS__
/**
 * Statistics we need to maintain after reading all pcap files.
 * 
 * - need to use key-value store
 * - enable using IP as key to search (via shell)
 * 
 */
#include <map>
#include <vector>

using namespace std;

typedef struct _flow_t {
    // basic
    int cnt;
    vector<double> pkt_interval;
    int flowlet_pktcnt;     // number of packet in current flowlet(-like)
    double flowlet_duration;
    vector<int> flowlet_q;
    vector<double> flowlet_duration_q;
    // L3
    string srcIP;
    string dstIP;
    // L4
    /* tcp */
    int recv_syn;
    int sent_syn;
    int recv_ack;
    int sent_ack;
    int recv_fin;
    int sent_fin;
    int recv_rst;
    int sent_rst;
    // # of unique ports
    map<int, int> sport_unique; // port id : occurance
    map<int, int> dport_unique; 
    // duration
    double ts_syn_received, ts_syn_sent;
    vector<double> half_open_duration_q;
    double lastseen_ts;
    vector<double> duration_q; // store all durations
    // double avg_duration; // sec (from ACK->FIN), EWMA
    /* icmp */
    int unreachable_cnt;
} flow_t;

typedef struct _flow_stats_t {
    map<string, flow_t> pktcnt;     // packet count 
} flow_stats_t;

typedef struct _dist_t {
    double max, min, mean, std;
    double pc1, pc2, pc3, pcmax;
    double nc1, nc2, nc3, ncmin;
    double user_defined;
} dist_t;

typedef struct _traffic_t {
    map<string, flow_stats_t> flow_stats;   // flow_stats
    // config/user setting, from config file or argparse
    double flowlet_timeout;                 // if the user reset/modify the FLOWLET_TIMEOUT, it will store in here.
    double flen_threshold;                  // flowlet len upperbound threshold set by user
    double port_threshold;                  // port upperbound threshold set by user
    double rst_threshold;                   // rst threshold
    double icmp3_threshold;                 // icmp type=3 (11,12) threshold
    double sr_threshold;                    // sent/recv diffcnt threshold
    vector<string> pt_q;                    // contain the flow that surpass port threshold
    vector<string> ft_q;                    // contain the flow that surpass flowlet threshold
    vector<string> rt_q;                    // same for rst
    vector<string> it_q;                    // same for icmp3
    // basic 
    long int total_flow_size;
    string filename;
    unsigned long int pktcnt, arpcnt, ipv4cnt, ipv6cnt, icmpcnt, tcpcnt, udpcnt;
    // sent/recv ratio
    dist_t sr_diff;
    // tcp control flag 
    dist_t rst_num;
    // icmp unreachable 
    dist_t icmp_ur_num;
    // flowlet length distribution
    dist_t flen;
    // dst port distribution 
    dist_t dport;
    // src port 
    dist_t sport;
} traffic_t;

#endif