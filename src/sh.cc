/**
 * Shell for flowImpler.
 * 
 */
#include "sh.h"

traffic_t sh_traffic_stats;
map<string, flow_stats_t> sh_flow_stats; 

int sh_loop(traffic_t t_stats)
{
    // assign flow_stats from main program
    sh_traffic_stats=t_stats;
    sh_flow_stats=sh_traffic_stats.flow_stats;
    // get port distribution 
    get_port_dist();
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
        ls();
        return 1;
    } else if(args.size()==1 && args.at(0)!=""){
        // FIXME: Add format checking on input string, whether it is IP format or not
        related_flows(args.at(0));
        return 1;
    } else if(args.size()==2 && args.at(0)=="pt"){
        // pt = port threshold
        // print out all flows which # of unique dst port > than args.at(1). args.at(1) is the value of pt.
        pt(stod(args.at(1)));
        return 1;
    } else if(args.size()==2 && args.at(0)!="" && args.at(1)!=""){
        // FIXME: Same format checking needed
        target_flow(args.at(0), args.at(1));
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

void pt(double threshold)
{
    // check
    if(threshold==sh_traffic_stats.port_threshold)
        return;
    sh_traffic_stats.pt_q.clear();
    cout << "---------------------------------------------------------------" << endl;
    cout << "List # of flows that surpass port threshold: " << threshold << endl;
    int num_exceed_pt=0;
    // traversal all exist flow 
    for(map<string, flow_stats_t>::iterator src=sh_flow_stats.begin(); 
        src!=sh_flow_stats.end(); src++){
            // src->first (srcIP), src->second (pktcnt, related_flows)
            for(map<string, flow_t>::iterator dst=sh_flow_stats[src->first].pktcnt.begin(); 
                dst!=sh_flow_stats[src->first].pktcnt.end(); dst++){
                    if(dst->second.dport_unique.size() > threshold){
                        num_exceed_pt++;
                        sh_traffic_stats.pt_q.push_back(src->first+"->"+dst->first);
                    }
                }
        }
    // need to update the value in traffic_t ! (update the part of *_num_user_defined, and port_threshold)
    sh_traffic_stats.port_threshold=threshold;
    sh_traffic_stats.dp_num_user_defined=num_exceed_pt;
    // FIXME: also need to update src port distribution ? (does this necessary ?)

    cout << "# of flows:" << num_exceed_pt << endl;
    // print the flows that meet the condition
    for(auto i=0; i<sh_traffic_stats.pt_q.size(); i++){
        cout << sh_traffic_stats.pt_q.at(i) << endl;
    }
    cout << "---------------------------------------------------------------" << endl;
}

void get_port_dist()
{
    double num_dport=0, num_sport=0, var_num_dport=0, var_num_sport=0
        , std_num_dport=0, std_num_sport=0, max_num_dport=0,min_num_dport=65535
        , max_num_sport=0, min_num_sport=65535;
    vector<double> unique_dport_q, unique_sport_q;
    for(map<string, flow_stats_t>::iterator iter=sh_flow_stats.begin();
        iter!=sh_flow_stats.end(); iter++){
            // cout << "IP: " << iter->first << ", which has " << iter->second.pktcnt.size() << " related IP." << endl;
            sh_traffic_stats.total_flow_size+=iter->second.pktcnt.size();
            // get each flow 
            for(map<string, flow_t>::iterator pktcnt=iter->second.pktcnt.begin();
                pktcnt!=iter->second.pktcnt.end(); pktcnt++){
                    unique_dport_q.push_back(pktcnt->second.dport_unique.size());
                    unique_sport_q.push_back(pktcnt->second.sport_unique.size());
                }
        }
    // calculate - dst
    for(int i=0;i<unique_dport_q.size();i++){
        if(unique_dport_q.at(i)>max_num_dport){ max_num_dport=unique_dport_q.at(i); }
        if(unique_dport_q.at(i)<min_num_dport){ min_num_dport=unique_dport_q.at(i); }
        num_dport+=unique_dport_q.at(i);
        var_num_dport+=pow(unique_dport_q.at(i),2);
    }
    // src port
    for(int i=0;i<unique_sport_q.size();i++){
        if(unique_sport_q.at(i)>max_num_sport){ max_num_sport=unique_sport_q.at(i); }
        if(unique_sport_q.at(i)<min_num_sport){ min_num_sport=unique_sport_q.at(i); }
        num_sport+=unique_sport_q.at(i);
        var_num_sport+=pow(unique_sport_q.at(i),2);
    }
    // store into traffic_stats
    sh_traffic_stats.max_num_dport=max_num_dport;
    sh_traffic_stats.min_num_dport=min_num_dport;
    sh_traffic_stats.mean_dst_port=num_dport/unique_dport_q.size();
    var_num_dport = var_num_dport/unique_dport_q.size() - powf(num_dport/unique_dport_q.size(), 2);
    sh_traffic_stats.std_dst_port=sqrtf(var_num_dport);
    sh_traffic_stats.max_num_sport=max_num_sport;
    sh_traffic_stats.min_num_sport=min_num_sport;
    sh_traffic_stats.mean_src_port=num_sport/unique_sport_q.size();
    var_num_sport = var_num_sport/unique_sport_q.size() - powf(num_sport/unique_sport_q.size(), 2);
    sh_traffic_stats.std_src_port=sqrtf(var_num_sport);

    // find range of distribution (dst)
    for(int i=0;i<unique_dport_q.size();i++){
        if(unique_dport_q.at(i)<sh_traffic_stats.mean_dst_port-3*sh_traffic_stats.std_dst_port ){ sh_traffic_stats.dp_num_neg_ci_min++; }
        else if( 
            (unique_dport_q.at(i)>=sh_traffic_stats.mean_dst_port-3*sh_traffic_stats.std_dst_port) && 
            (unique_dport_q.at(i)<sh_traffic_stats.mean_dst_port-2*sh_traffic_stats.std_dst_port) ){ sh_traffic_stats.dp_num_neg_ci_3++; }
        else if(
            (unique_dport_q.at(i)>=sh_traffic_stats.mean_dst_port-2*sh_traffic_stats.std_dst_port) &&
            (unique_dport_q.at(i)<sh_traffic_stats.mean_dst_port-sh_traffic_stats.std_dst_port)){ sh_traffic_stats.dp_num_neg_ci_2++; }
        else if(
            (unique_dport_q.at(i)>=sh_traffic_stats.mean_dst_port-sh_traffic_stats.std_dst_port) &&
            (unique_dport_q.at(i)<sh_traffic_stats.mean_dst_port)){ sh_traffic_stats.dp_num_neg_ci_1++; }
        else if(
            (unique_dport_q.at(i)>=sh_traffic_stats.mean_dst_port) &&
            (unique_dport_q.at(i)<sh_traffic_stats.mean_dst_port+sh_traffic_stats.std_dst_port)){ sh_traffic_stats.dp_num_pos_ci_1++; }
        else if(
            (unique_dport_q.at(i)>=sh_traffic_stats.mean_dst_port+sh_traffic_stats.std_dst_port) &&
            (unique_dport_q.at(i)<sh_traffic_stats.mean_dst_port+2*sh_traffic_stats.std_dst_port)){ sh_traffic_stats.dp_num_pos_ci_2++; }
        else if(
            (unique_dport_q.at(i)>=sh_traffic_stats.mean_dst_port+2*sh_traffic_stats.std_dst_port) &&
            (unique_dport_q.at(i)<sh_traffic_stats.mean_dst_port+3*sh_traffic_stats.std_dst_port)){ sh_traffic_stats.dp_num_pos_ci_3++; }
        else if(
            (unique_dport_q.at(i)>=sh_traffic_stats.mean_dst_port+3*sh_traffic_stats.std_dst_port)){ sh_traffic_stats.dp_num_pos_ci_max++; }
        // for user-defined threshold (dst)
        if(unique_dport_q.at(i)>sh_traffic_stats.port_threshold){ sh_traffic_stats.dp_num_user_defined++; }
    }
    // find range of distribution (src)
    for(int i=0;i<unique_sport_q.size();i++){
        if(unique_sport_q.at(i)<sh_traffic_stats.mean_src_port-3*sh_traffic_stats.std_src_port ){ sh_traffic_stats.sp_num_neg_ci_min++; }
        else if( 
            (unique_sport_q.at(i)>=sh_traffic_stats.mean_src_port-3*sh_traffic_stats.std_src_port) && 
            (unique_sport_q.at(i)<sh_traffic_stats.mean_src_port-2*sh_traffic_stats.std_src_port) ){ sh_traffic_stats.sp_num_neg_ci_3++; }
        else if(
            (unique_sport_q.at(i)>=sh_traffic_stats.mean_src_port-2*sh_traffic_stats.std_src_port) &&
            (unique_sport_q.at(i)<sh_traffic_stats.mean_src_port-sh_traffic_stats.std_src_port)){ sh_traffic_stats.sp_num_neg_ci_2++; }
        else if(
            (unique_sport_q.at(i)>=sh_traffic_stats.mean_src_port-sh_traffic_stats.std_src_port) &&
            (unique_sport_q.at(i)<sh_traffic_stats.mean_src_port)){ sh_traffic_stats.sp_num_neg_ci_1++; }
        else if(
            (unique_sport_q.at(i)>=sh_traffic_stats.mean_src_port) &&
            (unique_sport_q.at(i)<sh_traffic_stats.mean_src_port+sh_traffic_stats.std_src_port)){ sh_traffic_stats.sp_num_pos_ci_1++; }
        else if(
            (unique_sport_q.at(i)>=sh_traffic_stats.mean_src_port+sh_traffic_stats.std_src_port) &&
            (unique_sport_q.at(i)<sh_traffic_stats.mean_src_port+2*sh_traffic_stats.std_src_port)){ sh_traffic_stats.sp_num_pos_ci_2++; }
        else if(
            (unique_sport_q.at(i)>=sh_traffic_stats.mean_src_port+2*sh_traffic_stats.std_src_port) &&
            (unique_sport_q.at(i)<sh_traffic_stats.mean_src_port+3*sh_traffic_stats.std_src_port)){ sh_traffic_stats.sp_num_pos_ci_3++; }
        else if(
            (unique_sport_q.at(i)>=sh_traffic_stats.mean_src_port+3*sh_traffic_stats.std_src_port)){ sh_traffic_stats.sp_num_pos_ci_max++; }
        // for user-defined threshold (src)
        if(unique_sport_q.at(i)>sh_traffic_stats.port_threshold){ sh_traffic_stats.sp_num_user_defined++; }
    }
    
}

void related_flows(string target)
{
    // IP address
    cout << "---------------------------------------------------------------" << endl;
    cout << "Find all stats relate to IP address (source IP): " << target << endl;
    // Comment: Too much flows to display
    unsigned long int total_pktcnt=0;
    for(map<string, flow_t>::iterator iter=sh_flow_stats[target].pktcnt.begin(); 
        iter!=sh_flow_stats[target].pktcnt.end(); iter++){
            cout << "\t" << iter->second.srcIP << "->" << iter->second.dstIP << " : " << iter->second.cnt << endl;
            // total pktcnt
            total_pktcnt+=iter->second.cnt;
        }
    cout << "Related # of flows: " << sh_flow_stats[target].pktcnt.size() << endl;
    cout << "Related packet count: " << total_pktcnt << endl;
    cout << "---------------------------------------------------------------" << endl;
}

void target_flow(string srcIP, string dstIP)
{
    // IP address -> IP address 
    cout << "---------------------------------------------------------------" << endl;
    cout << "Find all stats relate to flow (srcIP dstIP): " << srcIP << "->" << dstIP << endl;
    cout << "Basic----------------------------------------------------------" << endl;
    cout << "# of packets in this flow: " << sh_flow_stats[srcIP].pktcnt[dstIP].cnt << endl;
    double total_interval=0;
    for(int i=0;i<sh_flow_stats[srcIP].pktcnt[dstIP].pkt_interval.size(); i++){
        total_interval+=sh_flow_stats[srcIP].pktcnt[dstIP].pkt_interval.at(i);
    }
    cout << "Total time used by this flow: " << total_interval << " (sec)" << endl;
    cout << "Avg. time interval between sequential packets: " << total_interval/(sh_flow_stats[srcIP].pktcnt[dstIP].pkt_interval.size()) << " (sec)" << endl;
    // flowlet count & duration
    double avg_flowlet_pktcnt=0, avg_flowlet_duration=0;
    for(int i=0;i<sh_flow_stats[srcIP].pktcnt[dstIP].flowlet_q.size(); i++){
        avg_flowlet_pktcnt+=sh_flow_stats[srcIP].pktcnt[dstIP].flowlet_q.at(i);
    }
    for(int i=0;i<sh_flow_stats[srcIP].pktcnt[dstIP].flowlet_duration_q.size(); i++){
        avg_flowlet_duration+=sh_flow_stats[srcIP].pktcnt[dstIP].flowlet_duration_q.at(i);
    }
    cout << "Total amount of flowlets in current flow: " << sh_flow_stats[srcIP].pktcnt[dstIP].flowlet_q.size() << endl;        
    cout << "Avg. packet count for each flowlet: " << avg_flowlet_pktcnt/sh_flow_stats[srcIP].pktcnt[dstIP].flowlet_q.size() << endl;
    cout << "Avg. duration for each flowlet: " << avg_flowlet_duration/sh_flow_stats[srcIP].pktcnt[dstIP].flowlet_duration_q.size() << endl;
    // basic TCP status
    cout << "TCP control flags----------------------------------------------" << endl;
    cout << "# of Sent SYN: " << sh_flow_stats[srcIP].pktcnt[dstIP].sent_syn << endl;
    cout << "# of Recv SYN: " << sh_flow_stats[srcIP].pktcnt[dstIP].recv_syn << endl;
    cout << "# of Sent ACK: " << sh_flow_stats[srcIP].pktcnt[dstIP].sent_ack << endl;
    cout << "# of Recv ACK: " << sh_flow_stats[srcIP].pktcnt[dstIP].recv_ack << endl;
    cout << "# of Sent FIN: " << sh_flow_stats[srcIP].pktcnt[dstIP].sent_fin << endl;
    cout << "# of Recv FIN: " << sh_flow_stats[srcIP].pktcnt[dstIP].recv_fin << endl;
    cout << "# of Sent RST: " << sh_flow_stats[srcIP].pktcnt[dstIP].sent_rst << endl;
    cout << "# of Recv RST: " << sh_flow_stats[srcIP].pktcnt[dstIP].recv_rst << endl;
    cout << "TCP connection duration----------------------------------------" << endl;
    double total_duration=0;
    for(int i=0;i<sh_flow_stats[srcIP].pktcnt[dstIP].duration_q.size(); i++){
        total_duration+=sh_flow_stats[srcIP].pktcnt[dstIP].duration_q.at(i);
    }
    cout << "Avg. duration of each connection: " << total_duration/(sh_flow_stats[srcIP].pktcnt[dstIP].duration_q.size()) << " (sec)" << endl;
    total_duration=0; // reset
    for(int i=0;i<sh_flow_stats[srcIP].pktcnt[dstIP].half_open_duration_q.size(); i++){
        total_duration+=sh_flow_stats[srcIP].pktcnt[dstIP].half_open_duration_q.at(i);
    }
    cout << "Avg. duration of half-open connection: " << total_duration/(sh_flow_stats[srcIP].pktcnt[dstIP].half_open_duration_q.size()) << " (sec)" << endl;
    cout << "TCP/UDP port distribution---------------------------------------" << endl;
    cout << "# of unique source ports: " <<sh_flow_stats[srcIP].pktcnt[dstIP].sport_unique.size() << endl;
    cout << "# of unique destination ports: " << sh_flow_stats[srcIP].pktcnt[dstIP].dport_unique.size() << endl;
    cout << "---------------------------------------------------------------" << endl;
}

void print_basic()
{
    cout << "Basic----------------------------------------------------------" << endl;
    cout << "Name of dataset: " << sh_traffic_stats.filename << endl;
    cout << "Total unique flows: " << sh_traffic_stats.total_flow_size/2 << endl; // need to divide by 2 (because we maintain bi-direction via each IP)
    cout << "Total amount of packets: " << sh_traffic_stats.pktcnt << endl;
    cout << "Unique hosts (IP): " << sh_traffic_stats.flow_stats.size() << endl;
    cout << "Settings(config/argparse)--------------------------------------" << endl;
    cout << "Flowlet timeout (sec): " << sh_traffic_stats.flowlet_timeout << endl;
    cout << "Port threshold: " << sh_traffic_stats.port_threshold << endl;
    cout << "---------------------------------------------------------------" << endl;
}

void print_analytics()
{
    cout << "Traffic Analytics----------------------------------------------" << endl;
    printf("%-10s %-s: %3.5f %%\n", "ARP", "(%)", sh_traffic_stats.arpcnt*100/(float)sh_traffic_stats.pktcnt);
    printf("%-10s %-s: %3.5f %%\n", "IPv4", "(%)", sh_traffic_stats.ipv4cnt*100/(float)sh_traffic_stats.pktcnt);
    printf("%-10s %-s: %3.5f %%\n", "|- TCP", "(%)", sh_traffic_stats.tcpcnt*100/(float)sh_traffic_stats.pktcnt);
    printf("%-10s %-s: %3.5f %%\n", "|- UDP", "(%)", sh_traffic_stats.udpcnt*100/(float)sh_traffic_stats.pktcnt);
    printf("%-10s %-s: %3.5f %%\n", "|- ICMP", "(%)", sh_traffic_stats.icmpcnt*100/(float)sh_traffic_stats.pktcnt);
    printf("%-10s %-s: %3.5f %%\n", "IPv6", "(%)", sh_traffic_stats.ipv6cnt*100/(float)sh_traffic_stats.pktcnt);
    printf("%-10s %-s: %3.5f %%\n", "Other", "(%)", 
        (sh_traffic_stats.pktcnt-sh_traffic_stats.arpcnt
        -sh_traffic_stats.ipv4cnt-sh_traffic_stats.ipv6cnt)*100
        /(float)sh_traffic_stats.pktcnt);
    cout << "---------------------------------------------------------------" << endl;
}

void print_port_dist()
{
    // src port - statistics
    cout << "Avg. # of src port used by one flow: " << sh_traffic_stats.mean_src_port << endl;
    cout << "Std. # of src port used by one flow: " << sh_traffic_stats.std_src_port << endl;
    cout << "Max. # of src port used by one flow: " << sh_traffic_stats.max_num_sport << endl;
    cout << "Min. # of src port used by one flow: " << sh_traffic_stats.min_num_sport << endl;
    cout << "# of src port used: -------------------------------------------" << endl;
    cout << "0 ~ " << sh_traffic_stats.mean_src_port-3*sh_traffic_stats.std_src_port << "(mean-3*std): " << sh_traffic_stats.sp_num_neg_ci_min << endl;
    cout << "(mean-3*std) ~ " << sh_traffic_stats.mean_src_port-2*sh_traffic_stats.std_src_port << "(mean-2*std): " << sh_traffic_stats.sp_num_neg_ci_3 << endl;
    cout << "(mean-2*std) ~ " << sh_traffic_stats.mean_src_port-sh_traffic_stats.std_src_port <<  "(mean-std): " << sh_traffic_stats.sp_num_neg_ci_2 << endl;
    cout << "(mean-std) ~ mean: " << sh_traffic_stats.sp_num_neg_ci_1 << endl;
    cout << "mean ~ " << sh_traffic_stats.mean_src_port+sh_traffic_stats.std_src_port << "(mean+std): " << sh_traffic_stats.sp_num_pos_ci_1 << endl;
    cout << "(mean+std) ~ " << sh_traffic_stats.mean_src_port+2*sh_traffic_stats.std_src_port << "(mean+2*std): " << sh_traffic_stats.sp_num_pos_ci_2 << endl;
    cout << "(mean+2*std) ~ " << sh_traffic_stats.mean_src_port+3*sh_traffic_stats.std_src_port << "(mean+3*std): " << sh_traffic_stats.sp_num_pos_ci_3 << endl;
    cout << "> mean+3*std: " << sh_traffic_stats.sp_num_pos_ci_max << endl; 
    cout << "(> User-defined threshold- " << sh_traffic_stats.port_threshold << "): " << sh_traffic_stats.sp_num_user_defined << endl;
    cout << "---------------------------------------------------------------" << endl;
    // dst port - statistics
    cout << "Avg. # of dst port used by one flow: " << sh_traffic_stats.mean_dst_port << endl;
    cout << "Std. # of dst port used by one flow: " << sh_traffic_stats.std_dst_port << endl;
    cout << "Max. # of dst port used by one flow: " << sh_traffic_stats.max_num_dport << endl;
    cout << "Min. # of dst port used by one flow: " << sh_traffic_stats.min_num_dport << endl;
    cout << "# of dst port used: -------------------------------------------" << endl;
    cout << "0 ~ " << sh_traffic_stats.mean_dst_port-3*sh_traffic_stats.std_dst_port << "(mean-3*std): " << sh_traffic_stats.dp_num_neg_ci_min << endl;
    cout << "(mean-3*std) ~ " << sh_traffic_stats.mean_dst_port-2*sh_traffic_stats.std_dst_port << "(mean-2*std): " << sh_traffic_stats.dp_num_neg_ci_3 << endl;
    cout << "(mean-2*std) ~ " << sh_traffic_stats.mean_dst_port-sh_traffic_stats.std_dst_port <<  "(mean-std): " << sh_traffic_stats.dp_num_neg_ci_2 << endl;
    cout << "(mean-std) ~ mean: " << sh_traffic_stats.dp_num_neg_ci_1 << endl;
    cout << "mean ~ " << sh_traffic_stats.mean_dst_port+sh_traffic_stats.std_dst_port << "(mean+std): " << sh_traffic_stats.dp_num_pos_ci_1 << endl;
    cout << "(mean+std) ~ " << sh_traffic_stats.mean_dst_port+2*sh_traffic_stats.std_dst_port << "(mean+2*std): " << sh_traffic_stats.dp_num_pos_ci_2 << endl;
    cout << "(mean+2*std) ~ " << sh_traffic_stats.mean_dst_port+3*sh_traffic_stats.std_dst_port << "(mean+3*std): " << sh_traffic_stats.dp_num_pos_ci_3 << endl;
    cout << "> mean+3*std: " << sh_traffic_stats.dp_num_pos_ci_max << endl; 
    cout << "(> User-defined threshold- " << sh_traffic_stats.port_threshold << "): " << sh_traffic_stats.dp_num_user_defined << endl;
    cout << "---------------------------------------------------------------" << endl;
}

void ls()
{
    print_basic();
    print_analytics();
    print_port_dist();
}

void print_help()
{
    cout << "\nWelcome to use FlowImpaler!" << "\n"
         << "Support commands:" << "\n"
         << "[Operation]------------------------------------------------------------------------------" << "\n"
         << " \033[1;31m help \033[0m: print this helping message, to illustrate user how to use our service." << "\n"
         << " \033[1;31m exit \033[0m: close this CLI elegantly." << "\n"
         << "[Flow]-----------------------------------------------------------------------------------" << "\n"
         << " \033[1;36m <src IP>\033[0m : check all flow stats via specify srcIP." << "\n"
         << " \033[1;36m <src IP>\033[0m \033[92m<dst IP>\033[0m: check the flow stats via specify srcIP and dstIP." << "\n"
         << "-----------------------------------------------------------------------------------------" << "\n"
         << endl;

    cout << "If you have counter any problem, feel free to contact me: \n"
         << " Email: kevinbird61@gmail.com\n"
         << " Github: github.com/kevinbird61\n"
         << endl;
}