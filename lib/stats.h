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

typedef struct _flow_stats_t {
    map<unsigned int, int> pktcnt; // packet count 
} flow_stats_t;

#endif