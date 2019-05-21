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
    cout << "Preprocess traffic information, please wait a second ..." << endl;
    // using pthread to optimize
    int ret;
    pthread_t tids[5];
    ret=pthread_create(&tids[0], NULL, get_port_dist, NULL);
    if(ret!=0){ cout << "get_port_dist(): pthread_create error! error code: " << ret << endl;}
    ret=pthread_create(&tids[1], NULL, get_flowlet_dist, NULL);
    if(ret!=0){ cout << "get_flowlet_dist(): pthread_create error! error code: " << ret << endl;}
    ret=pthread_create(&tids[2], NULL, get_rst_dist, NULL);
    if(ret!=0){ cout << "get_rst_dist(): pthread_create error! error code: " << ret << endl;}
    ret=pthread_create(&tids[3], NULL, get_icmp_ur_dist, NULL);
    if(ret!=0){ cout << "get_icmp_ur_dist(): pthread_create error! error code: " << ret << endl;}
    ret=pthread_create(&tids[4], NULL, get_sent_recv_dist, NULL);
    if(ret!=0){ cout << "get_sent_recv_dist(): pthread_create error! error code: " << ret << endl;}
    
    cout << "Done." << endl;
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

    pthread_exit(NULL);
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
    } else if(args.size()==2 && args.at(0)=="ptop"){
        // ptop = port threshold
        // print out all flows which # of unique dst port > than args.at(1). args.at(1) is the value of pt.
        ptop(stod(args.at(1)));
        return 1;
    } else if(args.size()==2 && args.at(0)=="ftop"){
        // ftop = flowlet threshold
        ftop(stod(args.at(1)));
        return 1;
    } else if(args.size()==2 && args.at(0)=="rtop"){
        // rtop = rst threshold
        rtop(stod(args.at(1)));
        return 1;
    } else if(args.size()==2 && args.at(0)=="i3top"){
        // i3top = icmp type3 threshold
        i3top(stod(args.at(1)));
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

void ptop(double threshold)
{
    cout << "---------------------------------------------------------------" << endl;
    // check
    if(threshold!=sh_traffic_stats.port_threshold){
        sh_traffic_stats.pt_q.clear();
        // traversal all exist flow 
        for(map<string, flow_stats_t>::iterator src=sh_flow_stats.begin(); 
            src!=sh_flow_stats.end(); src++){
                // src->first (srcIP), src->second (pktcnt, related_flows)
                for(map<string, flow_t>::iterator dst=sh_flow_stats[src->first].pktcnt.begin(); 
                    dst!=sh_flow_stats[src->first].pktcnt.end(); dst++){
                        if(dst->second.dport_unique.size() > threshold){
                            sh_traffic_stats.pt_q.push_back(src->first+"->"+dst->first);
                        }
                    }
            }
        // need to update the value in traffic_t ! (update the part of *_num_user_defined, and port_threshold)
        sh_traffic_stats.port_threshold=threshold;
        sh_traffic_stats.dport.user_defined=sh_traffic_stats.pt_q.size();
        // FIXME: also need to update src port distribution ? (does this necessary ?)

    }
    // print the flows that meet the condition
    for(auto i=0; i<sh_traffic_stats.pt_q.size(); i++){
        cout << sh_traffic_stats.pt_q.at(i) << endl;
    }
    cout << "# of flows:" << sh_traffic_stats.pt_q.size() << endl;
    cout << "List # of flows that surpass port threshold: " << threshold << endl;
    cout << "---------------------------------------------------------------" << endl;
}

void ftop(double threshold)
{
    cout << "---------------------------------------------------------------" << endl;
    // check
    if(threshold!=sh_traffic_stats.flen_threshold){
        sh_traffic_stats.ft_q.clear();
        // traversal all exist flow 
        for(map<string, flow_stats_t>::iterator src=sh_flow_stats.begin(); 
            src!=sh_flow_stats.end(); src++){
                // src->first (srcIP), src->second (pktcnt, related_flows)
                for(map<string, flow_t>::iterator dst=sh_flow_stats[src->first].pktcnt.begin(); 
                    dst!=sh_flow_stats[src->first].pktcnt.end(); dst++){
                        for(int i=0; i<dst->second.flowlet_q.size(); i++){
                            if(dst->second.flowlet_q.at(i)>threshold){
                                sh_traffic_stats.ft_q.push_back(src->first+"->"+dst->first);
                                break; // we only need to check which flow has flowlet length > threshold
                            }
                        }
                    }
            }
        // need to update the value in traffic_t ! (update the part of *_num_user_defined, and port_threshold)
        sh_traffic_stats.flen_threshold=threshold;
        sh_traffic_stats.flen.user_defined=sh_traffic_stats.ft_q.size();

    }
    
    // print the flows that meet the condition
    for(auto i=0; i<sh_traffic_stats.ft_q.size(); i++){
        cout << sh_traffic_stats.ft_q.at(i) << endl;
    }
    cout << "# of flows:" << sh_traffic_stats.ft_q.size() << endl;
    cout << "List # of flows that surpass flowlet length threshold: " << threshold << endl;
    cout << "---------------------------------------------------------------" << endl;
}

void rtop(double threshold)
{
    cout << "---------------------------------------------------------------" << endl;
    // check
    if(threshold!=sh_traffic_stats.rst_threshold){
        sh_traffic_stats.rt_q.clear();
        // traversal all exist flow 
        for(map<string, flow_stats_t>::iterator src=sh_flow_stats.begin(); 
            src!=sh_flow_stats.end(); src++){
                // src->first (srcIP), src->second (pktcnt, related_flows)
                for(map<string, flow_t>::iterator dst=sh_flow_stats[src->first].pktcnt.begin(); 
                    dst!=sh_flow_stats[src->first].pktcnt.end(); dst++){
                        if(dst->second.recv_rst>threshold){
                            sh_traffic_stats.rt_q.push_back(src->first+"->"+dst->first);
                        }
                    }
            }
        // need to update the value in traffic_t ! (update the part of *_num_user_defined, and port_threshold)
        sh_traffic_stats.rst_threshold=threshold;
        sh_traffic_stats.rst_num.user_defined=sh_traffic_stats.rt_q.size();
    }

    // print the flows that meet the condition
    for(auto i=0; i<sh_traffic_stats.rt_q.size(); i++){
        cout << sh_traffic_stats.rt_q.at(i) << endl;
    }
    cout << "# of flows:" << sh_traffic_stats.rt_q.size() << endl;
    cout << "List # of flows that surpass rst threshold: " << threshold << endl;
    cout << "---------------------------------------------------------------" << endl;
}

void i3top(double threshold)
{
    cout << "---------------------------------------------------------------" << endl;
    // check
    if(threshold!=sh_traffic_stats.icmp3_threshold){
        sh_traffic_stats.it_q.clear();
        // traversal all exist flow 
        for(map<string, flow_stats_t>::iterator src=sh_flow_stats.begin(); 
            src!=sh_flow_stats.end(); src++){
                // src->first (srcIP), src->second (pktcnt, related_flows)
                for(map<string, flow_t>::iterator dst=sh_flow_stats[src->first].pktcnt.begin(); 
                    dst!=sh_flow_stats[src->first].pktcnt.end(); dst++){
                        if(dst->second.unreachable_cnt>threshold){
                            sh_traffic_stats.it_q.push_back(src->first+"->"+dst->first);
                        }
                    }
            }
        // need to update the value in traffic_t ! (update the part of *_num_user_defined, and port_threshold)
        sh_traffic_stats.icmp3_threshold=threshold;
        sh_traffic_stats.icmp_ur_num.user_defined=sh_traffic_stats.it_q.size();
    }

    // print the flows that meet the condition
    for(auto i=0; i<sh_traffic_stats.it_q.size(); i++){
        cout << sh_traffic_stats.it_q.at(i) << endl;
    }
    cout << "# of flows:" << sh_traffic_stats.it_q.size() << endl;
    cout << "List # of flows that surpass icmp3 threshold: " << threshold << endl;
    cout << "---------------------------------------------------------------" << endl;
}

void *get_rst_dist(void* args)
{
    double total=0, var=0;
    double max=0, min=1000000;
    vector<int> rst_q;
    for(map<string, flow_stats_t>::iterator iter=sh_flow_stats.begin();
        iter!=sh_flow_stats.end(); iter++){
            // cout << "IP: " << iter->first << ", which has " << iter->second.pktcnt.size() << " related IP." << endl;
            // get each flow 
            for(map<string, flow_t>::iterator pktcnt=iter->second.pktcnt.begin();
                pktcnt!=iter->second.pktcnt.end(); pktcnt++){
                    // pktcnt->second->flowlet_q, insert into the main queue
                    if(pktcnt->second.recv_rst > 0)
                        rst_q.push_back(pktcnt->second.recv_rst);
                }
        }
    for(int i=0;i<rst_q.size();i++){
        if(rst_q.at(i)>max){max=rst_q.at(i);}
        if(rst_q.at(i)<min){min=rst_q.at(i);}
        total+=rst_q.at(i);
        var+=pow(rst_q.at(i),2);
    }
    // store 
    sh_traffic_stats.rst_num.max=max;
    sh_traffic_stats.rst_num.min=min;
    sh_traffic_stats.rst_num.mean=total/rst_q.size();
    sh_traffic_stats.rst_num.std=sqrtf(var);
    // range of dist
    for(int i=0;i<rst_q.size();i++){
        if(rst_q.at(i)<sh_traffic_stats.rst_num.mean-3*sh_traffic_stats.rst_num.std)
            {sh_traffic_stats.rst_num.ncmin++;}
        else if(
            (rst_q.at(i)>=sh_traffic_stats.rst_num.mean-3*sh_traffic_stats.rst_num.std)&&
            (rst_q.at(i)<sh_traffic_stats.rst_num.mean-2*sh_traffic_stats.rst_num.std)
        ){ sh_traffic_stats.rst_num.nc3++; }
        else if(
            (rst_q.at(i)>=sh_traffic_stats.rst_num.mean-2*sh_traffic_stats.rst_num.std)&&
            (rst_q.at(i)<sh_traffic_stats.rst_num.mean-sh_traffic_stats.rst_num.std)
        ){ sh_traffic_stats.rst_num.nc2++; }
        else if(
            (rst_q.at(i)>=sh_traffic_stats.rst_num.mean-sh_traffic_stats.rst_num.std)&&
            (rst_q.at(i)<sh_traffic_stats.rst_num.mean)
        ){ sh_traffic_stats.rst_num.nc1++; }
        else if(
            (rst_q.at(i)>=sh_traffic_stats.rst_num.mean)&&
            (rst_q.at(i)<sh_traffic_stats.rst_num.mean+sh_traffic_stats.rst_num.std)
        ){ sh_traffic_stats.rst_num.pc1++; }
        else if(
            (rst_q.at(i)>=sh_traffic_stats.rst_num.mean+sh_traffic_stats.rst_num.std)&&
            (rst_q.at(i)<sh_traffic_stats.rst_num.mean+2*sh_traffic_stats.rst_num.std)
        ){ sh_traffic_stats.rst_num.pc2++; }
        else if(
            (rst_q.at(i)>=sh_traffic_stats.rst_num.mean+2*sh_traffic_stats.rst_num.std)&&
            (rst_q.at(i)<sh_traffic_stats.rst_num.mean+3*sh_traffic_stats.rst_num.std)
        ){ sh_traffic_stats.rst_num.pc3++; }
        else if(
            (rst_q.at(i)>=sh_traffic_stats.rst_num.mean+3*sh_traffic_stats.rst_num.std)
        ){ sh_traffic_stats.rst_num.pcmax++; }
        if(rst_q.at(i)>sh_traffic_stats.rst_threshold){ sh_traffic_stats.rst_num.user_defined++; }
    }
}

void *get_icmp_ur_dist(void* args)
{
    double total=0, var=0;
    double max=0, min=1000000;
    vector<int> icmp_q;
    for(map<string, flow_stats_t>::iterator iter=sh_flow_stats.begin();
        iter!=sh_flow_stats.end(); iter++){
            // cout << "IP: " << iter->first << ", which has " << iter->second.pktcnt.size() << " related IP." << endl;
            // get each flow 
            for(map<string, flow_t>::iterator pktcnt=iter->second.pktcnt.begin();
                pktcnt!=iter->second.pktcnt.end(); pktcnt++){
                    // pktcnt->second->flowlet_q, insert into the main queue
                    if(pktcnt->second.unreachable_cnt > 0)
                        icmp_q.push_back(pktcnt->second.unreachable_cnt);
                }
        }
    for(int i=0;i<icmp_q.size();i++){
        if(icmp_q.at(i)>max){max=icmp_q.at(i);}
        if(icmp_q.at(i)<min){min=icmp_q.at(i);}
        total+=icmp_q.at(i);
        var+=pow(icmp_q.at(i),2);
    }
    // store 
    sh_traffic_stats.icmp_ur_num.max=max;
    sh_traffic_stats.icmp_ur_num.min=min;
    sh_traffic_stats.icmp_ur_num.mean=total/icmp_q.size();
    sh_traffic_stats.icmp_ur_num.std=sqrtf(var);
    // range of dist
    for(int i=0;i<icmp_q.size();i++){
        if(icmp_q.at(i)<sh_traffic_stats.icmp_ur_num.mean-3*sh_traffic_stats.icmp_ur_num.std)
            {sh_traffic_stats.icmp_ur_num.ncmin++;}
        else if(
            (icmp_q.at(i)>=sh_traffic_stats.icmp_ur_num.mean-3*sh_traffic_stats.icmp_ur_num.std)&&
            (icmp_q.at(i)<sh_traffic_stats.icmp_ur_num.mean-2*sh_traffic_stats.icmp_ur_num.std)
        ){ sh_traffic_stats.icmp_ur_num.nc3++; }
        else if(
            (icmp_q.at(i)>=sh_traffic_stats.icmp_ur_num.mean-2*sh_traffic_stats.icmp_ur_num.std)&&
            (icmp_q.at(i)<sh_traffic_stats.icmp_ur_num.mean-sh_traffic_stats.icmp_ur_num.std)
        ){ sh_traffic_stats.icmp_ur_num.nc2++; }
        else if(
            (icmp_q.at(i)>=sh_traffic_stats.icmp_ur_num.mean-sh_traffic_stats.icmp_ur_num.std)&&
            (icmp_q.at(i)<sh_traffic_stats.icmp_ur_num.mean)
        ){ sh_traffic_stats.icmp_ur_num.nc1++; }
        else if(
            (icmp_q.at(i)>=sh_traffic_stats.icmp_ur_num.mean)&&
            (icmp_q.at(i)<sh_traffic_stats.icmp_ur_num.mean+sh_traffic_stats.icmp_ur_num.std)
        ){ sh_traffic_stats.icmp_ur_num.pc1++; }
        else if(
            (icmp_q.at(i)>=sh_traffic_stats.icmp_ur_num.mean+sh_traffic_stats.icmp_ur_num.std)&&
            (icmp_q.at(i)<sh_traffic_stats.icmp_ur_num.mean+2*sh_traffic_stats.icmp_ur_num.std)
        ){ sh_traffic_stats.icmp_ur_num.pc2++; }
        else if(
            (icmp_q.at(i)>=sh_traffic_stats.icmp_ur_num.mean+2*sh_traffic_stats.icmp_ur_num.std)&&
            (icmp_q.at(i)<sh_traffic_stats.icmp_ur_num.mean+3*sh_traffic_stats.icmp_ur_num.std)
        ){ sh_traffic_stats.icmp_ur_num.pc3++; }
        else if(
            (icmp_q.at(i)>=sh_traffic_stats.icmp_ur_num.mean+3*sh_traffic_stats.icmp_ur_num.std)
        ){ sh_traffic_stats.icmp_ur_num.pcmax++; }
        if(icmp_q.at(i)>sh_traffic_stats.icmp3_threshold){ sh_traffic_stats.icmp_ur_num.user_defined++; }
    }
}

void *get_flowlet_dist(void* args)
{
    long double total_len=0, var_len=0;
    double max_len=0, min_len=65535;
    vector<int> flowlet_len_q;
    for(map<string, flow_stats_t>::iterator iter=sh_flow_stats.begin();
        iter!=sh_flow_stats.end(); iter++){
            // cout << "IP: " << iter->first << ", which has " << iter->second.pktcnt.size() << " related IP." << endl;
            sh_traffic_stats.total_flow_size+=iter->second.pktcnt.size();
            // get each flow 
            for(map<string, flow_t>::iterator pktcnt=iter->second.pktcnt.begin();
                pktcnt!=iter->second.pktcnt.end(); pktcnt++){
                    // pktcnt->second->flowlet_q, insert into the main queue
                    flowlet_len_q.insert(flowlet_len_q.end(), pktcnt->second.flowlet_q.begin(), pktcnt->second.flowlet_q.end());
                }
        }
    // calculate - flowlet length
    for(int i=0;i<flowlet_len_q.size();i++){
        if(flowlet_len_q.at(i) > max_len){ max_len=flowlet_len_q.at(i); }
        if(flowlet_len_q.at(i) < min_len){ min_len=flowlet_len_q.at(i); }
        total_len+=(long double)flowlet_len_q.at(i);
        var_len+=((long double)pow(flowlet_len_q.at(i),2));
    }
    // store into traffic_stats
    sh_traffic_stats.flen.max=max_len;
    sh_traffic_stats.flen.min=min_len;
    sh_traffic_stats.flen.mean=total_len/flowlet_len_q.size();
    var_len = var_len/flowlet_len_q.size() - powf(max_len/flowlet_len_q.size(), 2);
    sh_traffic_stats.flen.std=sqrtf(var_len);

    // find range of distribution
    for(int i=0;i<flowlet_len_q.size();i++){
        if(flowlet_len_q.at(i)<sh_traffic_stats.flen.mean-3*sh_traffic_stats.flen.std){ 
            sh_traffic_stats.flen.ncmin++; 
        }else if(
            (flowlet_len_q.at(i)>=sh_traffic_stats.flen.mean-3*sh_traffic_stats.flen.std) &&
            (flowlet_len_q.at(i)<sh_traffic_stats.flen.mean-2*sh_traffic_stats.flen.std)
        ){ sh_traffic_stats.flen.nc3++; }
        else if(
            (flowlet_len_q.at(i)>=sh_traffic_stats.flen.mean-2*sh_traffic_stats.flen.std) &&
            (flowlet_len_q.at(i)<sh_traffic_stats.flen.mean-sh_traffic_stats.flen.std)
        ){ sh_traffic_stats.flen.nc2++; }
        else if(
            (flowlet_len_q.at(i)>=sh_traffic_stats.flen.mean-sh_traffic_stats.flen.std) &&
            (flowlet_len_q.at(i)<sh_traffic_stats.flen.mean)
        ){ sh_traffic_stats.flen.nc1++; }
        else if(
            (flowlet_len_q.at(i)>=sh_traffic_stats.flen.mean) &&
            (flowlet_len_q.at(i)<sh_traffic_stats.flen.mean+sh_traffic_stats.flen.std) 
        ){ sh_traffic_stats.flen.pc1++; }
        else if(
            (flowlet_len_q.at(i)>=sh_traffic_stats.flen.mean+sh_traffic_stats.flen.std) &&
            (flowlet_len_q.at(i)<sh_traffic_stats.flen.mean+2*sh_traffic_stats.flen.std)
        ){ sh_traffic_stats.flen.pc2++; }
        else if(
            (flowlet_len_q.at(i)>=sh_traffic_stats.flen.mean+2*sh_traffic_stats.flen.std) &&
            (flowlet_len_q.at(i)<sh_traffic_stats.flen.mean+3*sh_traffic_stats.flen.std)
        ){ sh_traffic_stats.flen.pc3++; }
        else if(
            (flowlet_len_q.at(i)>=sh_traffic_stats.flen.mean+3*sh_traffic_stats.flen.std)
        ){ sh_traffic_stats.flen.pcmax++; }
        if(flowlet_len_q.at(i)>sh_traffic_stats.flen_threshold){ sh_traffic_stats.flen.user_defined++; }        
    }
}

void *get_sent_recv_dist(void* args)
{
    long double total=0, var=0;
    double max=0, min=65535;
    vector<int> diff_q;
    for(map<string, flow_stats_t>::iterator iter=sh_flow_stats.begin();
        iter!=sh_flow_stats.end(); iter++){
            // cout << "IP: " << iter->first << ", which has " << iter->second.pktcnt.size() << " related IP." << endl;
            sh_traffic_stats.total_flow_size+=iter->second.pktcnt.size();
            // get each flow 
            for(map<string, flow_t>::iterator pktcnt=iter->second.pktcnt.begin();
                pktcnt!=iter->second.pktcnt.end(); pktcnt++){
                    // pktcnt->second->flowlet_q, insert into the main queue
                    int sent=0, recv=0;
                    for(int i=0;i<pktcnt->second.flowlet_q.size();i++){
                        sent+=pktcnt->second.flowlet_q.at(i);
                    }
                    for(int i=0;i<sh_flow_stats[pktcnt->first].pktcnt[iter->first].flowlet_q.size();i++){
                        recv+=sh_flow_stats[pktcnt->first].pktcnt[iter->first].flowlet_q.at(i);
                    }
                    // if sent<recv, then it will be negative
                    diff_q.push_back(sent-recv);
                }
        }
    for(int i=0;i<diff_q.size();i++){
        if(diff_q.at(i)>max){max=diff_q.at(i);}
        if(diff_q.at(i)<min){min=diff_q.at(i);}
        total+=diff_q.at(i);
        var+=pow(diff_q.at(i),2);
    }
    // store
    sh_traffic_stats.sr_diff.max=max;
    sh_traffic_stats.sr_diff.min=min;
    sh_traffic_stats.sr_diff.mean=total/diff_q.size();
    sh_traffic_stats.sr_diff.std=sqrtf(var);
    // range of dist
    for(int i=0;i<diff_q.size();i++){
        if(diff_q.at(i)<sh_traffic_stats.sr_diff.mean-3*sh_traffic_stats.sr_diff.std)
            {sh_traffic_stats.sr_diff.ncmin++;}
        else if(
            (diff_q.at(i)>=sh_traffic_stats.sr_diff.mean-3*sh_traffic_stats.sr_diff.std) &&
            (diff_q.at(i)<sh_traffic_stats.sr_diff.mean-2*sh_traffic_stats.sr_diff.std)
        ){ sh_traffic_stats.sr_diff.nc3++; }
        else if(
            (diff_q.at(i)>=sh_traffic_stats.sr_diff.mean-2*sh_traffic_stats.sr_diff.std) &&
            (diff_q.at(i)<sh_traffic_stats.sr_diff.mean-sh_traffic_stats.sr_diff.std)
        ){ sh_traffic_stats.sr_diff.nc2++; }
        else if(
            (diff_q.at(i)>=sh_traffic_stats.sr_diff.mean-sh_traffic_stats.sr_diff.std) &&
            (diff_q.at(i)<sh_traffic_stats.sr_diff.mean)
        ){ sh_traffic_stats.sr_diff.nc1++; }
        else if(
            (diff_q.at(i)>=sh_traffic_stats.sr_diff.mean) &&
            (diff_q.at(i)<sh_traffic_stats.sr_diff.mean+sh_traffic_stats.sr_diff.std)
        ){ sh_traffic_stats.sr_diff.pc1++; }
        else if(
            (diff_q.at(i)>=sh_traffic_stats.sr_diff.mean+sh_traffic_stats.sr_diff.std) &&
            (diff_q.at(i)<sh_traffic_stats.sr_diff.mean+2*sh_traffic_stats.sr_diff.std)
        ){ sh_traffic_stats.sr_diff.pc2++; }
        else if(
            (diff_q.at(i)>=sh_traffic_stats.sr_diff.mean+2*sh_traffic_stats.sr_diff.std) &&
            (diff_q.at(i)<sh_traffic_stats.sr_diff.mean+3*sh_traffic_stats.sr_diff.std)
        ){ sh_traffic_stats.sr_diff.pc3++; }
        else if(
            (diff_q.at(i)>=sh_traffic_stats.sr_diff.mean+3*sh_traffic_stats.sr_diff.std)
        ){ sh_traffic_stats.sr_diff.pcmax++; }
        if(diff_q.at(i)>sh_traffic_stats.sr_threshold){ sh_traffic_stats.sr_diff.user_defined++; }
    }
}

void *get_port_dist(void* args)
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
                    if(pktcnt->second.dport_unique.size()>0)
                        unique_dport_q.push_back(pktcnt->second.dport_unique.size());
                    if(pktcnt->second.sport_unique.size()>0)
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
    sh_traffic_stats.dport.max=max_num_dport;
    sh_traffic_stats.dport.min=min_num_dport;
    sh_traffic_stats.dport.mean=num_dport/unique_dport_q.size();
    var_num_dport = var_num_dport/unique_dport_q.size() - powf(num_dport/unique_dport_q.size(), 2);
    sh_traffic_stats.dport.std=sqrtf(var_num_dport);
    sh_traffic_stats.sport.max=max_num_sport;
    sh_traffic_stats.sport.min=min_num_sport;
    sh_traffic_stats.sport.mean=num_sport/unique_sport_q.size();
    var_num_sport = var_num_sport/unique_sport_q.size() - powf(num_sport/unique_sport_q.size(), 2);
    sh_traffic_stats.sport.std=sqrtf(var_num_sport);

    // find range of distribution (dst)
    for(int i=0;i<unique_dport_q.size();i++){
        if(unique_dport_q.at(i)<sh_traffic_stats.dport.mean-3*sh_traffic_stats.dport.std ){
            sh_traffic_stats.dport.ncmin++; 
        }else if( 
            (unique_dport_q.at(i)>=sh_traffic_stats.dport.mean-3*sh_traffic_stats.dport.std) && 
            (unique_dport_q.at(i)<sh_traffic_stats.dport.mean-2*sh_traffic_stats.dport.std) ){ 
                sh_traffic_stats.dport.nc3++; }
        else if(
            (unique_dport_q.at(i)>=sh_traffic_stats.dport.mean-2*sh_traffic_stats.dport.std) &&
            (unique_dport_q.at(i)<sh_traffic_stats.dport.mean-sh_traffic_stats.dport.std)){ 
                sh_traffic_stats.dport.nc2++; }
        else if(
            (unique_dport_q.at(i)>=sh_traffic_stats.dport.mean-sh_traffic_stats.dport.std) &&
            (unique_dport_q.at(i)<sh_traffic_stats.dport.mean)){ 
                sh_traffic_stats.dport.nc1++; }
        else if(
            (unique_dport_q.at(i)>=sh_traffic_stats.dport.mean) &&
            (unique_dport_q.at(i)<sh_traffic_stats.dport.mean+sh_traffic_stats.dport.std)){ 
                sh_traffic_stats.dport.pc1++; }
        else if(
            (unique_dport_q.at(i)>=sh_traffic_stats.dport.mean+sh_traffic_stats.dport.std) &&
            (unique_dport_q.at(i)<sh_traffic_stats.dport.mean+2*sh_traffic_stats.dport.std)){ 
                sh_traffic_stats.dport.pc2++; }
        else if(
            (unique_dport_q.at(i)>=sh_traffic_stats.dport.mean+2*sh_traffic_stats.dport.std) &&
            (unique_dport_q.at(i)<sh_traffic_stats.dport.mean+3*sh_traffic_stats.dport.std)){ 
                sh_traffic_stats.dport.pc3++; }
        else if(
            (unique_dport_q.at(i)>=sh_traffic_stats.dport.mean+3*sh_traffic_stats.dport.std)){ 
                sh_traffic_stats.dport.pcmax++; }
        // for user-defined threshold (dst)
        if(unique_dport_q.at(i)>sh_traffic_stats.port_threshold){ sh_traffic_stats.dport.user_defined++; }
    }
    // find range of distribution (src)
    for(int i=0;i<unique_sport_q.size();i++){
        if(unique_sport_q.at(i)<sh_traffic_stats.sport.mean-3*sh_traffic_stats.sport.std ){ 
            sh_traffic_stats.sport.ncmin++; }
        else if( 
            (unique_sport_q.at(i)>=sh_traffic_stats.sport.mean-3*sh_traffic_stats.sport.std) && 
            (unique_sport_q.at(i)<sh_traffic_stats.sport.mean-2*sh_traffic_stats.sport.std) ){ 
                sh_traffic_stats.sport.nc3++; }
        else if(
            (unique_sport_q.at(i)>=sh_traffic_stats.sport.mean-2*sh_traffic_stats.sport.std) &&
            (unique_sport_q.at(i)<sh_traffic_stats.sport.mean-sh_traffic_stats.sport.std)){ 
                sh_traffic_stats.sport.nc2++; }
        else if(
            (unique_sport_q.at(i)>=sh_traffic_stats.sport.mean-sh_traffic_stats.sport.std) &&
            (unique_sport_q.at(i)<sh_traffic_stats.sport.mean)){ 
                sh_traffic_stats.sport.nc1++; }
        else if(
            (unique_sport_q.at(i)>=sh_traffic_stats.sport.mean) &&
            (unique_sport_q.at(i)<sh_traffic_stats.sport.mean+sh_traffic_stats.sport.std)){ 
                sh_traffic_stats.sport.pc1++; }
        else if(
            (unique_sport_q.at(i)>=sh_traffic_stats.sport.mean+sh_traffic_stats.sport.std) &&
            (unique_sport_q.at(i)<sh_traffic_stats.sport.mean+2*sh_traffic_stats.sport.std)){ 
                sh_traffic_stats.sport.pc2++; }
        else if(
            (unique_sport_q.at(i)>=sh_traffic_stats.sport.mean+2*sh_traffic_stats.sport.std) &&
            (unique_sport_q.at(i)<sh_traffic_stats.sport.mean+3*sh_traffic_stats.sport.std)){ 
                sh_traffic_stats.sport.pc3++; }
        else if(
            (unique_sport_q.at(i)>=sh_traffic_stats.sport.mean+3*sh_traffic_stats.sport.std)){ 
                sh_traffic_stats.sport.pcmax++; }
        // for user-defined threshold (src)
        if(unique_sport_q.at(i)>sh_traffic_stats.port_threshold){ sh_traffic_stats.sport.user_defined++; }
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
    cout << "---------------------------------------------------------------" << endl;
    cout << "Avg. # of src port used by one flow: " << sh_traffic_stats.sport.mean << endl;
    cout << "Std. # of src port used by one flow: " << sh_traffic_stats.sport.std << endl;
    cout << "Max. # of src port used by one flow: " << sh_traffic_stats.sport.max << endl;
    cout << "Min. # of src port used by one flow: " << sh_traffic_stats.sport.min << endl;
    cout << "# of src port used: -------------------------------------------" << endl;

    print_dist_table(sh_traffic_stats.sport.mean, sh_traffic_stats.sport.std,
        sh_traffic_stats.sport.ncmin, sh_traffic_stats.sport.nc3, sh_traffic_stats.sport.nc2, sh_traffic_stats.sport.nc1,
        sh_traffic_stats.sport.pc1, sh_traffic_stats.sport.pc2, sh_traffic_stats.sport.pc3, sh_traffic_stats.sport.pcmax);  

    cout << "(> User-defined threshold- " << sh_traffic_stats.port_threshold << "): " << sh_traffic_stats.sport.user_defined << endl;
    cout << "---------------------------------------------------------------" << endl;
    // dst port - statistics
    cout << "Avg. # of dst port used by one flow: " << sh_traffic_stats.dport.mean << endl;
    cout << "Std. # of dst port used by one flow: " << sh_traffic_stats.dport.std << endl;
    cout << "Max. # of dst port used by one flow: " << sh_traffic_stats.dport.max << endl;
    cout << "Min. # of dst port used by one flow: " << sh_traffic_stats.dport.min << endl;
    cout << "# of dst port used: -------------------------------------------" << endl;

    print_dist_table(sh_traffic_stats.dport.mean, sh_traffic_stats.dport.std,
        sh_traffic_stats.dport.ncmin, sh_traffic_stats.dport.nc3, sh_traffic_stats.dport.nc2, sh_traffic_stats.dport.nc1,
        sh_traffic_stats.dport.pc1, sh_traffic_stats.dport.pc2, sh_traffic_stats.dport.pc3, sh_traffic_stats.dport.pcmax);    

    cout << "(> User-defined threshold- " << sh_traffic_stats.port_threshold << "): " << sh_traffic_stats.dport.user_defined << endl;
    cout << "---------------------------------------------------------------" << endl;
}

void print_flen_dist()
{
    cout << "---------------------------------------------------------------" << endl;
    cout << "Avg. length of flowlet: " << sh_traffic_stats.flen.mean << endl;
    cout << "Std. length of flowlet: " << sh_traffic_stats.flen.std << endl;
    cout << "Max. length of flowlet: " << sh_traffic_stats.flen.max << endl;
    cout << "Min. length of flowlet: " << sh_traffic_stats.flen.min << endl;
    cout << "Length distribution -------------------------------------------" << endl;

    print_dist_table(sh_traffic_stats.flen.mean, sh_traffic_stats.flen.std,
        sh_traffic_stats.flen.ncmin, sh_traffic_stats.flen.nc3, sh_traffic_stats.flen.nc2, sh_traffic_stats.flen.nc1,
        sh_traffic_stats.flen.pc1, sh_traffic_stats.flen.pc2, sh_traffic_stats.flen.pc3, sh_traffic_stats.flen.pcmax);    

    cout << "(> User-defined threshold- " << sh_traffic_stats.flen_threshold << "): " << sh_traffic_stats.flen.user_defined << endl;
    cout << "---------------------------------------------------------------" << endl;
}

void print_rst_dist()
{
    cout << "---------------------------------------------------------------" << endl;
    cout << "Avg. num of rst (per flow): " << sh_traffic_stats.rst_num.mean << endl;
    cout << "Std. num of rst (per flow): " << sh_traffic_stats.rst_num.std << endl;
    cout << "Max. num of rst (per flow): " << sh_traffic_stats.rst_num.max << endl;
    cout << "Min. num of rst (per flow): " << sh_traffic_stats.rst_num.min << endl;
    cout << "# of RST dist -------------------------------------------------" << endl;

    print_dist_table(sh_traffic_stats.rst_num.mean, sh_traffic_stats.rst_num.std,
        sh_traffic_stats.rst_num.ncmin, sh_traffic_stats.rst_num.nc3, sh_traffic_stats.rst_num.nc2, sh_traffic_stats.rst_num.nc1,
        sh_traffic_stats.rst_num.pc1, sh_traffic_stats.rst_num.pc2, sh_traffic_stats.rst_num.pc3, sh_traffic_stats.rst_num.pcmax);    
    
    cout << "(> User-defined threshold- " << sh_traffic_stats.rst_threshold << "): " << sh_traffic_stats.rst_num.user_defined << endl;
    cout << "---------------------------------------------------------------" << endl;
}

void print_icmp_dist()
{
    cout << "---------------------------------------------------------------" << endl;
    cout << "Avg. num of icmp (per flow): " << sh_traffic_stats.icmp_ur_num.mean << endl;
    cout << "Std. num of icmp (per flow): " << sh_traffic_stats.icmp_ur_num.std << endl;
    cout << "Max. num of icmp (per flow): " << sh_traffic_stats.icmp_ur_num.max << endl;
    cout << "Min. num of icmp (per flow): " << sh_traffic_stats.icmp_ur_num.min << endl;
    cout << "# of ICMP dist ------------------------------------------------" << endl;

    print_dist_table(sh_traffic_stats.icmp_ur_num.mean, sh_traffic_stats.icmp_ur_num.std,
        sh_traffic_stats.icmp_ur_num.ncmin, sh_traffic_stats.icmp_ur_num.nc3, sh_traffic_stats.icmp_ur_num.nc2, sh_traffic_stats.icmp_ur_num.nc1,
        sh_traffic_stats.icmp_ur_num.pc1, sh_traffic_stats.icmp_ur_num.pc2, sh_traffic_stats.icmp_ur_num.pc3, sh_traffic_stats.icmp_ur_num.pcmax);    
    
    cout << "(> User-defined threshold- " << sh_traffic_stats.icmp3_threshold << "): " << sh_traffic_stats.icmp_ur_num.user_defined << endl;
    cout << "---------------------------------------------------------------" << endl;
}

void print_sent_recv_dist()
{
    cout << "---------------------------------------------------------------" << endl;
    cout << "Avg. diff cnt of sent/recv (per flow): " << sh_traffic_stats.sr_diff.mean << endl;
    cout << "Std. diff cnt of sent/recv (per flow): " << sh_traffic_stats.sr_diff.std << endl;
    cout << "Max. diff cnt of sent/recv (per flow): " << sh_traffic_stats.sr_diff.max << endl;
    cout << "Min. diff cnt of sent/recv (per flow): " << sh_traffic_stats.sr_diff.min << endl;
    cout << "Diffcnt of S/R dist. -------------------------------------------" << endl;

    print_dist_table(sh_traffic_stats.sr_diff.mean, sh_traffic_stats.sr_diff.std,
        sh_traffic_stats.sr_diff.ncmin, sh_traffic_stats.sr_diff.nc3, sh_traffic_stats.sr_diff.nc2, sh_traffic_stats.sr_diff.nc1,
        sh_traffic_stats.sr_diff.pc1, sh_traffic_stats.sr_diff.pc2, sh_traffic_stats.sr_diff.pc3, sh_traffic_stats.sr_diff.pcmax);    
    
    cout << "(> User-defined threshold- " << sh_traffic_stats.sr_threshold << "): " << sh_traffic_stats.sr_diff.user_defined << endl;
    cout << "---------------------------------------------------------------" << endl;
}

void print_dist_table(double mean, double std, 
    double ncmin, double nc3, double nc2, double nc1,
    double pc1, double pc2, double pc3, double pcmax)
{
    cout << "| " << setw(25) << "0 ~ mean-3*std"  << " | " << setw(25) << "mean-3*std ~ mean-2*std" << " | "
        << setw(25) << "mean-2*std ~ mean-std" << " | " << setw(25) << "mean-std ~ mean" << " | " 
        << setw(25) << "mean ~ mean+std" << " | " << setw(25) << "mean+std ~ mean+2*std" << " | "
        << setw(25) << "mean+2*std ~ mean+3*std" << " | " << setw(25) << " > mean+3*std" << " | " << endl;
    cout << "| " << setw(25) << mean-3*std << " | " 
        << setw(25) << mean-2*std << " | "
        << setw(25) << mean-std << " | " 
        << setw(25) << mean << " | " 
        << setw(25) << mean+std << " | " 
        << setw(25) << mean+2*std << " | "
        << setw(25) << mean+3*std << " | " 
        << setw(25) << " > prev" << " | " << endl;
    cout << "| " << setw(25) << "----------------------" << " | " << setw(25) << "----------------------" << " | "
        << setw(25) << "----------------------" << " | " << setw(25) << "----------------------" << " | " 
        << setw(25) << "----------------------" << " | " << setw(25) << "----------------------" << " | "
        << setw(25) << "----------------------" << " | " << setw(25) << "----------------------" << " | " << endl;
    cout << "| " << setw(25) << ncmin << " | " << setw(25) << nc3 << " | "
        << setw(25) << nc2 << " | " << setw(25) << nc1 << " | " 
        << setw(25) << pc1 << " | " << setw(25) << pc2 << " | "
        << setw(25) << pc3 << " | " << setw(25) << pcmax << " | " << endl;
}

void ls()
{
    print_basic();
    print_analytics();
    print_port_dist();
    print_flen_dist();
    print_rst_dist();
    print_icmp_dist();
    print_sent_recv_dist();
}

void print_help()
{
    cout << "\nWelcome to use FlowImpaler!" << "\n"
         << "Support commands:" << "\n"
         << "[Operation]------------------------------------------------------------------------------" << "\n"
         << " \033[1;31m help \033[0m: print this helping message, to illustrate user how to use our service." << "\n"
         << " \033[1;31m exit \033[0m: close this CLI elegantly." << "\n"
         << "[Attributes]-----------------------------------------------------------------------------" << "\n"
         << " \033[1;31m ls\033[0m: Print distribution on each attributes. \n" 
         << " \033[1;31m ptop\033[0m \033[92m<threshold>\033[0m: List all flows that surpass threshold on number of unique dst port." << "\n"
         << " \033[1;31m ftop\033[0m \033[92m<threshold>\033[0m: List all flows that surpass threshold on length of flowlet." << "\n"
         << " \033[1;31m rtop\033[0m \033[92m<threshold>\033[0m: List all flows that surpass threshold on number of RST flags(TCP)." << "\n"
         << " \033[1;31m i3top\033[0m \033[92m<threshold>\033[0m: List all flows that surpass threshold on number of ICMP type=3(UDP)." << "\n"
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