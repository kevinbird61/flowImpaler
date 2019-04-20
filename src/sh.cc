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
    cout << "\nWelcome to use fakeCLI!" << "\n"
         << "Support commands:" << "\n"
         << "-----------------------------------------------------------------------------------------" << "\n"
         << " \033[1;31m help \033[0m: print this helping message, to illustrate user how to use our service." << "\n"
         << " \033[1;31m exit \033[0m: close this fake CLI elegantly." << "\n"
         << "-----------------------------------------------------------------------------------------" << "\n"
         << endl;

    cout << "If you have counter any problem, feel free to contact me: \n"
         << " Email: kevinbird61@gmail.com\n"
         << " Github: github.com/kevinbird61\n"
         << endl;
}