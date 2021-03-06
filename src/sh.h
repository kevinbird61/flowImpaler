#ifndef __SH__
#define __SH__

#include "header.h"
#include "stats.h"

#include <pthread.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <string>
#include <vector>
#include <cmath>

using namespace std;

// methods
int sh_loop(traffic_t traffic_stats);
int sh_interpret(string filename);
vector<string> sh_readline(string raw);
int sh_execute(vector<string> args);

// support command
void ls();
// print msg
void related_flows(string target);
void target_flow(string srcIP, string dstIP);
// print by specify threshold
void ptop(double threshold);    // port threshold
void ftop(double threshold);    // flowlet length threshold
void rtop(double threshold);    // rst threshold
void i3top(double threshold);   // icmp3 threshold
// dump msg into file
void export_pktlen(int lb, int ub);
void export_rst(int lb, int ub);
void export_icmp(int lb, int ub);
void export_dport(int lb, int ub);

// computing block
void *get_port_dist(void* args);       // dealing with port distribution
void *get_flowlet_dist(void* args);    // dealing with flowlet length distribution
void *get_rst_dist(void* args);        // rst (TCP)
void *get_icmp_ur_dist(void* args);    // icmp unreachable
void *get_sent_recv_dist(void* args);  // diff cnt between sent and recv
void *get_pktlen_dist(void* args);     // pktlen 

// component (print helper message)
void print_basic();         // basic information about current pcap/traffic
void print_analytics();     // traffic analytics (percentage)
void print_port_dist();     // port distribution
void print_flen_dist();     // flowlet length distribution
void print_rst_dist();
void print_icmp_dist();
void print_sent_recv_dist();
void print_pktlen_dist();

void print_dist_table(double mean, double std, 
    double ncmin, double nc3, double nc2, double nc1,
    double pc1, double pc2, double pc3, double pcmax);

// log, helper function
void print_help();
 
#endif