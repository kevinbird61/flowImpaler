#ifndef __SH__
#define __SH__

#include "header.h"
#include "stats.h"

#include <iostream>
#include <sstream>
#include <fstream>
#include <string>
#include <vector>

using namespace std;

// methods
int sh_loop(map<string, flow_stats_t> flow_stats);
int sh_interpret(string filename);
vector<string> sh_readline(string raw);
int sh_execute(vector<string> args);

// log, helper function
void print_help();
 
#endif