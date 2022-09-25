# macpcap
Pcap Analysis Tool

# Description
Macpcap is used to analyze pcap and pcapng files on OSX systems. This version writes all output to the standard out using fmt::print. The library
tabylate is used to create the statistics tables.
Program is designed for Apple OSX and may not run other platforms
<br>
<br>
#Examples
- macpcap --help
  - Displays the help message and all the valid options
  - macpcap --filename pcapfile.pcap
        - Displays all statistics table for the trace file pcapfile.pcap
  - nacpcap --filename file.pcap --report tcp --sorttcp packcount
        - Displays just the statistics table for TCP conversations and sorts it based on the table header packetcount
  - macpcap --filename file.pcap --list 192.168.42.4:58018-54.144.73.197:443
        - filters the capture on the supplied socket and then does the following:
            - Display a list of the packets on the trace file
            - displays the stgit push
            atistics for the filtered packets, that is the TCP conversation specified
        - Note: the filter options is ignored of the list options is used.
   - mackpcap --filename file.pcap --filter bpf:tcp
        - Filters out all packets that do not have a TCP header. The text after the : in bpf: can be any Berkley Packet Filter syntax.

 # Author Experience
 I retired from a large retailer as a lead network engineer five years ago. I have worked in the network troubleshooting business for 45 years.
 I started out working with IBM SNA on IBM and Tandem systems. Wrote many scripts and programs to help troubleshoot issues. Later in my
 career I started working on TCP/IP protocols and network gear from Bay Networks and Cisco. I have a strong background in the TCP/IP protocol suite.

 # History
 ## History of Macpcap
 1. First version was called CDF and was written in TAL (Tandem Application Language)
 2. next - Python version of CDF when we moved to TCP/IP
 3. next - Ruby/sinatra version created to integrate web front end and add live Cisco troubleshooting tools.
 4. retired
 5. five years later decided to crete this tool to keep my sanity and mind sharp. I decided to use c++ to
    avoid any issues with the previous versions that are corporate owned. Note: I am novice with C++.

# Libraries
 - Boost Program Options
 - PcapPlusPlus
 - FMT Format
 - Tabulate
 - SPDLog

