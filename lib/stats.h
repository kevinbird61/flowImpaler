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
    string srcIP;
    string dstIP;
    int cnt;
} flow_t;

typedef struct _flow_stats_t {
    map<string, flow_t> pktcnt; // packet count 
} flow_stats_t;

#endif