# flowImpaler
Read and analysis from the network traffic in flow-level.

## Build 

> Currently only support Linux/Ubuntu.
> 

* Dependencies
```sh
sudo apt install build-essential libpcap-dev
```

* Build the executable file
```sh
make
```

## Usage

### Read from pcap

* First, you can run the executable file with command down below:
```sh
./flowimpaler -f <a valid pcap file>
```

* Waiting until flowImpaler finish reading process, it will enter a CLI look like this:
```sh
Input pcap filename: ../ncku_csie_imslab_1941058.pcap
No more packet from file.
=====================================================
Unique hosts (IP): 10422
Total amount of packets: 1941058
ARP        (%): 1.48821 %
IPv4       (%): 90.15274 %
|- TCP     (%): 66.21157 %
|- UDP     (%): 22.70545 %
|- ICMP    (%): 1.08467 %
IPv6       (%): 2.89512 %
Other      (%): 5.46393 %
=====================================================
FlowImpaler@cyu> 
```

* And now you can type `help` to see the support by flowImpaler!
```sh
FlowImpaler@cyu> help

Welcome to use FlowImpaler!
Support commands:
-----------------------------------------------------------------------------------------
  help : print this helping message, to illustrate user how to use our service.
  exit : close this CLI elegantly.
-----------------------------------------------------------------------------------------
  <src IP> : check all flow stats via specify srcIP.
  <src IP> <dst IP>: check the flow stats via specify srcIP and dstIP.
-----------------------------------------------------------------------------------------

If you have counter any problem, feel free to contact me: 
 Email: kevinbird61@gmail.com
 Github: github.com/kevinbird61
```

### Live Capturing

* Run directly (flowImpaler will listen on your default network interface). Without any option, default will be terminated until capture `100` packets.
```sh
(sudo) ./flowimpaler -d 
```

* Run with specified timeout (For example down below, it will listen for `20` second)
```sh
(sudo) ./flowimpaler -d -t 20
```

* Run with specified packet counts (For example down below, it will terminate until capture `20` packets)
```
(sudo) ./flowimpaler -d -c 20
```

> Notice! `-t` has higher priority than `-c`. 

## Author

Kevin Cyu, kevinbird61@gmail.com