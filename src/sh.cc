/**
 * Shell for flowImpler.
 * 
 */
#include "sh.h"

map<string, flow_stats_t> sh_flow_stats; 

int sh_loop(map<string, flow_stats_t> flow_stats)
{
    // assign flow_stats from main program
    sh_flow_stats = flow_stats;
    // variables
    vector<string> args;
    int status=0;
    string raw;
    // loop first
    do {
        cout << "FlowImpaler@cyu> ";
        getline(std::cin, raw);
        args = sh_readline(raw);
        status = sh_execute(args);
    } while(status);
}

int sh_interpret(string filename)
{
    string raw;
    ifstream fin(filename);
    vector<string> args;
    int status=0;

    // read
    if(fin.is_open()) {
        while(getline(fin, raw)) {
            args = sh_readline(raw);
            status = sh_execute(args);
        }
    } else {
        cout << "Illegal input command file." << endl;
    }

    return 0;
}

vector<string> sh_readline(string raw)
{
    string tmp;
    vector<string> args_token;
    // split into several token
    stringstream ssin(raw);
    while(ssin.good()) {
        ssin >> tmp;
        args_token.push_back(tmp);
    }

    return args_token;
}

int sh_execute(vector<string> args)
{
    if(args.at(0)=="exit") {
        cout << "Bye, see you next time!" << endl;
        return 0;
    } else if(args.at(0)=="help") {
        print_help();
        return 1;
    } else if(args.at(0)=="ls") {
        cout << "---------------------------------------------------------------" << endl;
        cout << "Total # of flows: " << sh_flow_stats.size() << endl;
        cout << "---------------------------------------------------------------" << endl;
    } else if(args.size()==1 && args.at(0)!=""){
        // IP address
        cout << "---------------------------------------------------------------" << endl;
        cout << "Find all stats relate to IP address (source IP): " << args.at(0) << endl;
        // Comment: Too much flows to display
        for(map<string, flow_t>::iterator iter=sh_flow_stats[args.at(0)].pktcnt.begin(); 
            iter!=sh_flow_stats[args.at(0)].pktcnt.end(); iter++){
                cout << "\t" << iter->second.srcIP << "->" << iter->second.dstIP << " : " << iter->second.cnt << endl;
            }
        cout << "Related # of flows: " << sh_flow_stats[args.at(0)].pktcnt.size() << endl;
        cout << "---------------------------------------------------------------" << endl;
        return 1;
    } else if(args.size()==2){
        // IP address -> IP address 
        cout << "---------------------------------------------------------------" << endl;
        cout << "Find all stats relate to flow (srcIP dstIP): " << args.at(0) << "->" << args.at(1) << endl;
        cout << "Related # of flow: " << sh_flow_stats[args.at(0)].pktcnt[args.at(1)].cnt << endl;
        cout << "---------------------------------------------------------------" << endl;
    } else if(args.size()==1 && args.at(0)== "") {
        // nothing, just enter
        return 1;
    }
    /* New command add using "ELSE IF" */
    else {
        cout << "Not support yet, please using `help` to print helping message." << endl;
        return 1;
    }
}

void print_help()
{
    cout << "\nWelcome to use FlowImpaler!" << "\n"
         << "Support commands:" << "\n"
         << "-----------------------------------------------------------------------------------------" << "\n"
         << " \033[1;31m help \033[0m: print this helping message, to illustrate user how to use our service." << "\n"
         << " \033[1;31m exit \033[0m: close this CLI elegantly." << "\n"
         << "-----------------------------------------------------------------------------------------" << "\n"
         << " \033[1;36m <src IP>\033[0m : check all flow stats via specify srcIP." << "\n"
         << " \033[1;36m <src IP>\033[0m \033[92m<dst IP>\033[0m: check the flow stats via specify srcIP and dstIP." << "\n"
         << "-----------------------------------------------------------------------------------------" << "\n"
         << endl;

    cout << "If you have counter any problem, feel free to contact me: \n"
         << " Email: kevinbird61@gmail.com\n"
         << " Github: github.com/kevinbird61\n"
         << endl;
}
