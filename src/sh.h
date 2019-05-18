#ifndef __SH__
#define __SH__

#include "header.h"
#include "stats.h"

#include <iostream>
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

// log, helper function
void print_help();
void get_port_dist();
 
#endif