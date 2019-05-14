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

typedef struct _traffic_t {
    map<string, flow_stats_t> flow_stats;   // flow_stats
    double flowlet_timeout;                 // if the user reset/modify the FLOWLET_TIMEOUT, it will store in here.
} traffic_t;

#endif