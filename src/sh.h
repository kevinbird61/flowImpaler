#ifndef __SH__
#define __SH__

#include "header.h"
#include "stats.h"

#include <iostream>
#include <pthread.h>
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
void related_flows(string target);
void target_flow(string srcIP, string dstIP);
void ptop(double threshold);    // port threshold
void ftop(double threshold);    // flowlet length threshold
void rtop(double threshold);    // rst threshold
void i3top(double threshold);   // icmp3 threshold

// computing block
void *get_port_dist(void* args);       // dealing with port distribution
void *get_flowlet_dist(void* args);    // dealing with flowlet length distribution
void *get_rst_dist(void* args);        // rst (TCP)
void *get_icmp_ur_dist(void* args);    // icmp unreachable

// component (print helper message)
void print_basic();         // basic information about current pcap/traffic
void print_analytics();     // traffic analytics (percentage)
void print_port_dist();     // port distribution
void print_flen_dist();     // flowlet length distribution
void print_rst_dist();
void print_icmp_dist();

// log, helper function
void print_help();
 
#endif