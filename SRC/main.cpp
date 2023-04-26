/*! \file main.cpp
 *  Mac Pcap Analyzer (macpcap)
 *  ---------------------------
 * @author Scott Roberts
 * @version 1.0.0
 * \mainpage macpcap
 *
 * \section macpcap
 *  Macpcap is used to analyze pcap and pcapng files on OSX systems. This version writes all output to the standard out using fmt::print. The library
 *  tabylate is used to create the statistics tables.
 *  Program is designed for Apple OSX and may not run other platforms
 *
 *  \section Examples
 *  - macpcap --help
 *        - Displays the help message and all the valid options
 *  - macpcap --filename pcapfile.pcap
 *        - Displays all statistics table for the trace file pcapfile.pcap
 *  - nacpcap --filename file.pcap --report tcp --sorttcp packcount
 *        - Displays just the statistics table for TCP conversations and sorts it based on the table header packetcount
 *  - macpcap --filename file.pcap --list 192.168.42.4:58018-54.144.73.197:443
 *        - filters the capture on the supplied socket and then does the following:
 *            - Display a list of the packets on the trace file
 *            - displays the stgit push
 *            atistics for the filtered packets, that is the TCP conversation specified
 *        - Note: the filter options is ignored of the list options is used.
 *   - mackpcap --filename file.pcap --filter bpf:tcp
 *        - Filters out all packets that do not have a TCP header. The text after the : in bpf: can be any Berkley Packet Filter syntax.
 *
 * \section Author Experience
 * I retired from a large retailer as a lead network engineer five years ago. I have worked in the network troubleshooting business for 45 years.
 * I started out working with IBM SNA on IBM and Tandem systems. Wrote many scripts and programs to help troubleshoot issues. Later in my
 * career I started working on TCP/IP protocols and network gear from Bay Networks and Cisco. I have a strong background in the TCP/IP protocol suite.
 *
 * \section History
 * History of Macpcap
 * 1. First version was called CDF and was written in TAL (Tandem Application Language)
 * 2. next - Python version of CDF when we moved to TCP/IP
 * 3. next - Ruby/sinatra version created to integrate web front end and add live Cisco troubleshooting tools.
 * 4. retired
 * 5. five years later decided to crete this tool to keep my sanity and mind sharp. I decided to use c++ to
 *    avoid any issues with the previous versions that are corporate owned. Note: I am novice with C++.
 *
 * \section Libraries
 * - Boost Program Options
 * - PcapPlusPlus
 * - FMT Format
 * - Tabulate
 * - SPDLog
 *
 * \section Cmakelist
 *
 *CMakeLists.txt</font>
 *</center></td></tr></table>
 *<pre><span class="s0">#</span>
 *<span class="s0"># Cmake file for the application macpcap</span>
 *<span class="s0"># Author: Scott Roberts</span>
 *<span class="s0"># Date: 07/25/2022</span>
 *<span class="s0">#</span>

 *<span class="s0">#</span>
 *<span class="s0"># Global Definitions</span>
 *<span class="s0">#</span>

 *<span class="s2">cmake_minimum_required</span><span class="s1">(</span><span class="s3">VERSION 3.23</span><span class="s1">)</span>
 *<span class="s2">set</span><span class="s1">(</span><span class="s3">CMAKE_CXX_STANDARD 23</span><span class="s1">)</span>

 *<span class="s2">project</span><span class="s1">(</span><span class="s3">macpcap VERSION 1.0.0.0</span><span class="s1">)</span>
 *<span class="s2">set</span><span class="s1">(</span><span class="s3">CMAKE_MODULE_PATH </span><span class="s4">${</span><span class="s3">CMAKE_MODULE_PATH</span><span class="s4">} </span><span class="s1">&quot;</span><span class="s4">${</span><span class="s3">CMAKE_SOURCE_DIR</span><span class="s4">}</span><span class="s3">/</span><span class="s1">&quot; </span><span class="s3">/Users/scottroberts/CLionProjects/module</span><span class="s1">)</span>

 *<span class="s2">include</span><span class="s1">(</span><span class="s3">cmake/include/GetDateTime.cmake</span><span class="s1">)</span>
 *<span class="s2">include</span><span class="s1">(</span><span class="s3">cmake/include/misc.cmake</span><span class="s1">)</span>
 *<span class="s2">include_directories</span><span class="s1">(</span><span class="s3">/usr/local/include/pcapplusplus</span><span class="s1">)</span>
 *<span class="s2">include_directories</span><span class="s1">(</span><span class="s3">/usr/local/opt/libpcap/include</span><span class="s1">)</span>
 *<span class="s2">include_directories</span><span class="s1">(</span><span class="s3">/usr/local/include/concurrencpp-0.1.4 /usr/local/Cellar/boost/1.79.0_1/include/</span><span class="s1">)</span>

 *<span class="s2">getdatetime</span><span class="s1">()  </span><span class="s0"># sets dt</span>
 *<span class="s2">message</span><span class="s1">(&quot;</span><span class="s3">\nStarting at </span><span class="s4">${</span><span class="s3">dt</span><span class="s4">} </span><span class="s3">- Version </span><span class="s4">${</span><span class="s3">PROJECT_VERSION</span><span class="s4">}</span><span class="s1">&quot;)</span>
 *<span class="s2">systeminfo</span><span class="s1">()</span>
 *<span class="s2">checkipo</span><span class="s1">() </span><span class="s0"># will set IPO True if supported</span>

 *<span class="s0">#</span>
 *<span class="s0"># Target for macpcap</span>
 *<span class="s0">#</span>
 *<span class="s2">message</span><span class="s1">(&quot;</span><span class="s3">\nTarget: macpcap</span><span class="s1">&quot;)</span>
 *<span class="s2">add_executable</span><span class="s1">(</span><span class="s3">macpcap SRC/main.cpp SRC/Protocols/parser.cpp SRC/Protocols/HostPair.h SRC/Protocols/TCPConversation.h</span>
 *        <span class="s3">SRC/Protocols/HostPair.cpp SRC/Protocols/HostPair.h SRC/Protocols/TCPConversation.cpp myColor.h SRC/Protocols/EthernetStats.cpp SRC/Protocols/EthernetStats.h SRC/Protocols/ProtocolStats.cpp SRC/Protocols/ProtocolStats.h</span><span class="s1">)</span>

 *<span class="s2">message</span><span class="s1">(&quot;</span><span class="s3">macpcap: FMT package</span><span class="s1">&quot;)</span>
 *<span class="s2">find_package</span><span class="s1">(</span><span class="s3">fmt</span><span class="s1">)</span>
 *<span class="s2">target_link_libraries</span><span class="s1">(</span><span class="s3">macpcap fmt::fmt</span><span class="s1">)</span>

 *<span class="s2">message</span><span class="s1">(&quot;</span><span class="s3">macpcap: concurrencpp library</span><span class="s1">&quot;)</span>
 *<span class="s2">target_link_libraries</span><span class="s1">(</span><span class="s3">macpcap /usr/local/lib/libconcurrencpp.a</span><span class="s1">)</span>

 *<span class="s2">message</span><span class="s1">(&quot;</span><span class="s3">macpcap: Loading PCAP</span><span class="s1">&quot;)</span>
 *<span class="s2">find_package</span><span class="s1">(</span><span class="s3">PCAP</span><span class="s1">)</span>
 *<span class="s2">target_link_libraries</span><span class="s1">(</span><span class="s4">${</span><span class="s3">PROJECT_NAME</span><span class="s4">} ${</span><span class="s3">PCAP_LIBRARY</span><span class="s4">}</span><span class="s1">)</span>

 *<span class="s2">message</span><span class="s1">(&quot;</span><span class="s3">macpcap: Loading PCAP++</span><span class="s1">&quot;)</span>
 *<span class="s2">find_package</span><span class="s1">(</span><span class="s3">PcapPlusPlus REQUIRED</span><span class="s1">)</span>
 *<span class="s2">target_link_libraries</span><span class="s1">(</span><span class="s4">${</span><span class="s3">PROJECT_NAME</span><span class="s4">} ${</span><span class="s3">PcapPlusPlus_LIBRARIES</span><span class="s4">}</span><span class="s1">)</span>

<span class="s2">find_package</span><span class="s1">(</span><span class="s3">glog</span><span class="s1">)</span>
<span class="s2">target_link_libraries</span><span class="s1">(</span><span class="s4">${</span><span class="s3">PROJECT_NAME</span><span class="s4">} </span><span class="s3">glog::glog</span><span class="s1">)</span>

 *<span class="s2">FIND_PACKAGE</span><span class="s1">(</span><span class="s3">Boost 1.79 COMPONENTS program_options REQUIRED</span><span class="s1">)</span>
 *<span class="s2">INCLUDE_DIRECTORIES</span><span class="s1">(</span><span class="s4">${</span><span class="s3">Boost_INCLUDE_DIR</span><span class="s4">}</span><span class="s1">)</span>

 *<span class="s2">TARGET_LINK_LIBRARIES</span><span class="s1">(</span><span class="s4">${</span><span class="s3">PROJECT_NAME</span><span class="s4">} ${</span><span class="s3">Boost_LIBRARIES</span><span class="s4">}</span><span class="s1">)</span>
 *<span class="s0">#</span>
 *<span class="s0"># End oc CMake file</span>
 *<span class="s0">#</span>
 *<span class="s2">getdatetime</span><span class="s1">()</span>
 *<span class="s2">message</span><span class="s1">(&quot;</span><span class="s3">\nStopping at </span><span class="s4">${</span><span class="s3">dt</span><span class="s4">}</span><span class="s1">&quot;)</span>

 *</pre>
 */

#include <IPv4Layer.h>
#include <Packet.h>
#include <PcapFileDevice.h>
#include <chrono>
#include <fmt/format.h>
#include <iostream>
#include <regex>
#include <string>
#include "Protocols/parser.h"
#include "Protocols/EthernetStats.h"
#include <spdlog/spdlog.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <filesystem>
#include <boost/program_options.hpp>
#include "../myColor.h"
#include "Protocols/ProtocolStats.h"
#include <PcapFilter.h>
#include <PcapPlusPlusVersion.h>
#include "SystemUtils.h"
#include <time.h>


namespace fs = std::filesystem;
namespace po = boost::program_options;

std::string softwareVersion = "1.1.0";

/**
 * @callergraph
 * @callgraph
 * @brief hexdump
 * Function to dump out a raw packet in hex and ascii formats
 * @param data         - This is a uint8_t pointer ti the raw packets data
 * @param dataLength   - This is the length of the buffer
 * @return             - string containing the hex dump output
 */
std::string hexdump(const uint8_t *data, int dataLength) {
    std::string line{};
    std::string al{};
    std::string results{};
    uint8_t c;

    for (size_t i = 0; i < dataLength; ++i) {
        if ((i % 16) == 0) {
            al.append("\n");
            results.append(line.append("  " + al));
            line = fmt::format("     {:>5d}: ", i);
            al = {};
        }
        c = data[i];
        line.append(fmt::format("{:02x} ", c));
        if (std::isprint(c)) {
            al.append(fmt::format("{:1c}", c));
        } else {
            al.append(".");
        }
    }
    return results;
}

/**
 * @callgraph
 * @callergraph
 * \brief Print packets
 * Function to print packets and there headers to the log file.
 * @param pkt    - Parsed packet
 * @param ipHdr  - Pointer to IP Header.
 */
void print(const pcpp::Packet &p, int pc, bool debug) {
    if (debug) {
        SPDLOG_INFO("*********************************{}****************************************", pc);
        std::vector<std::string> v{};
        std::string s{};
        for (pcpp::Layer *curLayer = p.getFirstLayer(); curLayer != nullptr; curLayer = curLayer->getNextLayer()) {
            switch (curLayer->getProtocol()) {
                case pcpp::Ethernet: {
                    auto *ethLayer = dynamic_cast<pcpp::EthLayer *>(p.getLayerOfType(pcpp::Ethernet));
                    s = fmt::format("{}     Protocol {}  Payload Length {}",
                                    curLayer->toString(),
                                    std::to_string(ethLayer->getProtocol()),
                                    std::to_string(ethLayer->getLayerPayloadSize())
                    );
                    v.push_back(s);
                }
                    break;
                case pcpp::IPv4: {
                    auto *ipLayer = dynamic_cast<pcpp::IPv4Layer *>(p.getLayerOfType(pcpp::IPv4));
                    auto *ipHdr = ipLayer->getIPv4Header();
                    s = curLayer->toString() + fmt::format("     Protocol {}   PL {}   IPID {}   TTL {}",
                                                           std::to_string(ipLayer->getProtocol()),
                                                           std::to_string(ipLayer->getLayerPayloadSize()),
                                                           std::to_string(pcpp::hostToNet16(ipHdr->ipId)),
                                                           std::to_string(ipHdr->timeToLive)
                    );
                    v.push_back(s);
                }
                    break;

                case pcpp::TCP: {
                    auto *tcpL = dynamic_cast<pcpp::TcpLayer *>(p.getLayerOfType(pcpp::TCP));
                    auto *tcpHdr = tcpL->getTcpHeader();
                    s = curLayer->toString() + fmt::format("     Protocol {}   PL {}  seq {}   Ack {}    ws {}",
                                                           std::to_string(tcpL->getProtocol()),
                                                           std::to_string(tcpL->getLayerPayloadSize()),
                                                           std::to_string(pcpp::netToHost32(tcpHdr->sequenceNumber)),
                                                           std::to_string(pcpp::netToHost32(tcpHdr->ackNumber)),
                                                           std::to_string(pcpp::netToHost16(tcpHdr->windowSize))
                    );
                    v.push_back(s);
                }
                    break;

                default:
                    v.push_back(curLayer->toString());
            }
        }

        for (auto &l: v) {
            SPDLOG_INFO(l);
        }
        SPDLOG_INFO("==================================================================================");
    }
}

/**
 * @callgraph
 * @callergraph
 * @brief Print formatted packet for list option
 * @param p             - Parsed packet
 * @param ipIdList      - Map used to track IpId for the purpose of checking for retransmitted packets
 * @param pc            - Packet number
 * @param sendSeqList   - Map of send sequence numbers. Key is the sequence number and the value is a vector containing
 *                        packet number, ack flag ( 1 indicates ack processed),timestamp of packet
 * @param recvSeqList   - Map of receive sequence numbers. Key is the sequence number and the value is a vector containing
 *                        packet number, ack flag ( 1 indicates ack processed),timestamp of packet
 * @param ls            - Socket string used to determine first sender for response time calculations
 */
void pp(pcpp::Packet &p, int pc,
        std::map<uint16_t, int> &ipIdList,
        std::map<uint32_t, std::vector<long>> &sendSeqList,
        std::map<uint32_t, std::vector<long>> &recvSeqList,
        std::string &ls
) {
    /*
     * Use raw packet to get timestamp and convert to a local time string
     */
    pcpp::RawPacket *rawPkt = p.getRawPacketReadOnly();
    timespec ts = rawPkt->getPacketTimeStamp();
    std::tm *t = std::localtime(&ts.tv_sec);
    char mbstr[100];
    std::strftime(mbstr, sizeof(mbstr), "%c", t);
    std::string m{mbstr};
    m = m + "." + std::to_string(ts.tv_nsec);

    /*
     * Loop through and process each layer of the packet
     */
    std::string s{fmt::format("Packet: {}    {}\n", pc, m)};
    std::vector<std::string> v{s};
    std::string sip{};
    std::string dip{};
    for (pcpp::Layer *curLayer = p.getFirstLayer(); curLayer != nullptr; curLayer = curLayer->getNextLayer()) {
        switch (curLayer->getProtocol()) {

            /*
             * Process ethernet layer
             */
            case pcpp::Ethernet: {
                auto *ethLayer = dynamic_cast<pcpp::EthLayer *>(p.getLayerOfType(pcpp::Ethernet));
                s = fmt::format("{}     Protocol {}  Payload Length {}\n",
                                curLayer->toString(),
                                std::to_string(ethLayer->getProtocol()),
                                std::to_string(ethLayer->getLayerPayloadSize())
                );
                v.push_back(s);
            }
                break;

                /*
                 * Process IP Layer. Will use this layer to check for retransmitted packets. This is done by looking for
                 * data packets with duplicate IPId.
                 */
            case pcpp::IPv4: {
                auto *ipLayer = dynamic_cast<pcpp::IPv4Layer *>(p.getLayerOfType(pcpp::IPv4));
                auto *ipHdr = ipLayer->getIPv4Header();
                uint16_t ipIdNum{pcpp::hostToNet16(ipHdr->ipId)};
                //uint16_t payloadLength(pcpp::hostToNet16(ipLayer->getNextLayer()->getLayerPayloadSize()));
                uint16_t payloadLength(ipLayer->getNextLayer()->getLayerPayloadSize());

                /*  determine if this is a retransmitted packet. The idea here is that if this is a data packet
                 *  and we have already seen the IPId then it is a retransmission. The only problem with this technique
                 *  is that in a very large packet capture file the IpId can wrap.
                 *  TODO add code to check for this wrapping situation
                 */

                std::string retran{};
                std::map<uint16_t, int>::iterator i1;
                i1 = ipIdList.find(ipIdNum);
                if (i1 == ipIdList.end()) {
                    if (ipIdNum > 0 && payloadLength > 0) ipIdList[ipIdNum] = pc;
                } else {
                    retran = fmt::format("Retransmitted packet. Original {}}", ipIdList[ipIdNum]);
                }

                sip = ipLayer->getSrcIPAddress().toString();
                dip = ipLayer->getDstIPAddress().toString();
                s = curLayer->toString() + fmt::format("     Protocol {}   PL {}   IPID {}   TTL {}  {}\n",
                                                       std::to_string(ipLayer->getProtocol()),
                                                       std::to_string(ipLayer->getLayerPayloadSize()),
                                                       std::to_string(ipIdNum),
                                                       std::to_string(ipHdr->timeToLive),
                                                       retran
                );
                v.push_back(s);
            }
                break;

                /*
                 * Process TCP Layer. This layer will be used to track responses to a request packet by using
                 * sequence and ack numbers. Will also calculate response time and ack time.
                 */
            case pcpp::TCP: {
                auto *tcpL = dynamic_cast<pcpp::TcpLayer *>(p.getLayerOfType(pcpp::TCP));
                auto *tcpHdr = tcpL->getTcpHeader();

                uint32_t sn{pcpp::netToHost32(tcpHdr->sequenceNumber)};
                uint32_t an{pcpp::netToHost32(tcpHdr->ackNumber)};
                uint16_t ws{pcpp::netToHost16(tcpHdr->windowSize)};
                size_t pl{tcpL->getLayerPayloadSize()};
                std::string skt =
                        sip + ":" + std::to_string(tcpL->getSrcPort()) + "-" + dip + ":" +
                        std::to_string(tcpL->getDstPort());
                std::string reqrsp{};
                std::string dir{">>>"};
                std::string acks{};

                //
                if (ls == skt) {
                    /*
                     * Process send packet as determined by the socket passed on the list option
                     */
                    dir = ">>>";
                    if (pl > 0) {
                        long sec{static_cast<long>(ts.tv_sec) * 1000000000 + static_cast<long>(ts.tv_nsec)};
                        sendSeqList[sn] = {pc, 0, sec};
                    }
                    if (!recvSeqList.empty()) {
                        for (auto [k, v]: recvSeqList) {
                            long r = static_cast<long>(ts.tv_sec) * 1000000000 + static_cast<long>(ts.tv_nsec);
                            if (an >= k && pl > 0 && v[1] == 0) {
                                v[1] = 1;
                                double rt{(r - v[2]) / 1000000000.0};
                                reqrsp = fmt::format("RSP to {}   RspTime {}", v[0], rt);
                            } else {
                                if (tcpHdr->ackFlag && pl == 0 && an >= k) {
                                    double ackTime = (r - v[2]) / 1000000000.0;
                                    acks = fmt::format("ACK for {}  Ack Time {}", v[0], ackTime);
                                }
                            }
                        }
                    }
                } else {
                    /*
                     * Process a receive packet
                     */
                    dir = "<<<";
                    if (pl > 0) {
                        long sec{static_cast<long>(ts.tv_sec) * 1000000000 + static_cast<long>(ts.tv_nsec)};
                        recvSeqList[sn] = {pc, 0, sec};
                    }
                    if (!sendSeqList.empty()) {
                        for (auto [k, v]: sendSeqList) {
                            long r = static_cast<long>(ts.tv_sec) * 1000000000 + static_cast<long>(ts.tv_nsec);
                            if (an >= k && pl > 0 && v[1] == 0) {
                                v[1] = 1;
                                double rt{(r - v[2]) / 1000000000.0};
                                reqrsp = fmt::format("RSP to {}   RspTime {}", v[0], rt);
                            } else {
                                if (tcpHdr->ackFlag && pl == 0 && an >= k) {
                                    double ackTime = (r - v[2]) / 1000000000.0;
                                    acks = fmt::format("ACK for {}  Ack Time {}", v[0], ackTime);
                                }
                            }
                        }
                    }
                }

                s = dir + curLayer->toString() +
                    fmt::format("     Protocol {}   PL {}  seq {}   Ack {}    ws {}     {} {}\n",
                                std::to_string(tcpL->getProtocol()),
                                std::to_string(pl),
                                std::to_string(sn),
                                std::to_string(an),
                                std::to_string(ws),
                                reqrsp, acks
                    );
                v.push_back(s);
            }
                break;

            default:
                v.push_back((curLayer->toString() + "\n"));
        }
    }
    v.push_back(hexdump(rawPkt->getRawData(), rawPkt->getRawDataLen()));

    /*
     * The above processing stuffs the results into a vector of strings. Now it's time to display the results
     */
    for (auto &l: v) {
        fmt::print("{}", l);
    }
    fmt::print("\n");
}

/**
 * @callgraph
 * @callergraph
 * @brief Report Generator
 * Function to generate reports on the HostPair and TCP conversation tables in the following format: <br>
 *      -   Formatted text
 *
 * @param hpl        - Host pair list
 * @param tcl        - List of sockets seen in the capture
 * @param debug      - Used to tell functions to display log messages
 * @param pl         - List of protocol seen in the capture
 * @param el         - List of ethernet mac address pairs
 * @param reportType - Used to display a specific report and skip the others
 * @param ss         - sortstring used to sort stats based on a column heading
 */
void report(std::map<std::string, HostPair> hpl,
            std::map<std::string, TCPConversation> tcl,
            std::map<std::string, std::string> ss,
            std::map<std::string, EthernetStats> el,
            std::map<std::string, ProtocolStats> pl,
            bool debug,
            const std::string &reportType
) {

    if ((reportType == "all" || reportType == "prot") && !pl.empty()) {
        ProtocolStats::printTable(pl, ss["prot"], debug);
    }
    if ((reportType == "all" || reportType == "eth") && !el.empty()) {
        EthernetStats::printTable(el, ss["eth"], debug);
    }
    if ((reportType == "all" || reportType == "hp") && !hpl.empty()) {
        HostPair::printTable(hpl, ss["hp"], debug);
    }
    if ((reportType == "all" || reportType == "tcp") && !tcl.empty()) {
        TCPConversation::printTable(tcl, ss["tcp"], debug);
    }
}

/**
 * @callgraph
 * @callergraph
 * @brief Create CSV file
 *
 * @param hpl        - Host pair list
 * @param tcl        - List of sockets seen in the capture
 * @param debug      - Used to tell functions to display log messages
 * @param pl         - List of protocol seen in the capture
 * @param el         - List of ethernet mac address pairs
 * @param reportType - Used to display a specific report and skip the others
 * @param ss         - sortstring used to sort stats based on a column heading
 */
void writeCsv(std::map<std::string, HostPair> hpl,
              std::map<std::string, TCPConversation> tcl,
              std::map<std::string, std::string> ss,
              std::map<std::string, EthernetStats> el,
              std::map<std::string, ProtocolStats> pl,
              bool debug,
              const std::string &reportType
) {

    std::filesystem::path cwd = std::filesystem::current_path();
    fmt::print("Creating CSV files to directory {}\n", cwd.string());

    if ((reportType == "all" || reportType == "prot") && !pl.empty()) {
        ProtocolStats::writeCsvTable(pl, ss["prot"], debug);
    }
    if ((reportType == "all" || reportType == "eth") && !el.empty()) {
        EthernetStats::writeCsvTable(el, ss["eth"], debug);
    }
    if ((reportType == "all" || reportType == "hp") && !hpl.empty()) {
        HostPair::writeCsvTable(hpl, ss["hp"], debug);
    }
    if ((reportType == "all" || reportType == "tcp") && !tcl.empty()) {
        TCPConversation::writeCsvTable(tcl, ss["tcp"], debug);
    }
}


/*!
 * @callergraph
 * @callgraph
 * @param argc contains number of arguments passed to main
 * @param argv array of char arrays contain the parameters. ARGV[1] is a pcap file name
 * @return 0 - No errors
 *         1 - Errors occurred
 */

int main(int argc, char **argv) {

    auto t_start = std::chrono::high_resolution_clock::now();

    /**
    *  ## Main Processing Overview
    */
    /**
     * ### Remove old log file and initialize logger
     */
    std::string logfilename = argv[0] + (std::string) ".log";
    fs::remove(logfilename);
    auto logger = spdlog::basic_logger_mt("basic_logger", logfilename);
    spdlog::set_pattern("[%c] %l [%s-%!-%#] %v");
    spdlog::set_default_logger(logger);
    std::string v{pcpp::getPcapPlusPlusVersionFull()};
    SPDLOG_INFO("MacPcap {}  Starting. Using PCPP {}", softwareVersion, v);

    /**
     *  ###  Get time of day
     */
    auto now = std::chrono::system_clock::now();
    std::time_t end_time = std::chrono::system_clock::to_time_t(now);
    std::string dt = std::ctime(&end_time);

    /**
     * ### Use regex to remove new line character from date and time string.
     * - Print startup message with a list of arguments passed
     */
    std::regex newlines_re("\n+");
    auto dateTime = std::regex_replace(dt, newlines_re, "");
    auto startTime = dateTime;

    fmt::print("Starting macpcap{}{}{} at {}{}{}. Argc={}\n", red, softwareVersion, reset, blue, dateTime, reset,
               argc);
    SPDLOG_INFO("Arguments passed. ARGC={}", argc);
    for (int i = 0; i < argc; i++) {
        SPDLOG_INFO("\tArgument {}: {}\n", i, argv[i]);
    }

    /**
     * ### validate arguments:
     *    -# Filename of the pcap trace. Make sure it exists and is in a pcap format
    */
    po::options_description desc("Allowed options");
    desc.add_options()
            ("help", "produce help message")
            ("reportType", po::value<std::string>(), "Report type"
                                                     "text - Output goes to screen and is default"
                                                     "csv  - CSV file is created"
            )
            ("filename", po::value<std::string>(), "PCAP file name")
            ("log", "Turn on logging")
            ("list", po::value<std::string>(), "packet list: --list socket-id\n"
                                               "socket-id is sip:sport-dip:dport\n"
                                               "sip   - Source IP\n"
                                               "dip   - Destination IP\n"
                                               "sport - Source TCP port\n"
                                               "dport - Destination TCP Port")
            ("filter", po::value<std::string>(), "Filter packets from capture file\n\n"
                                                 "ip:x.x.x.x         - filter on IPaddress\n"
                                                 "hp:x.x.x.x-y.y.y.y - filter oon a host pair\n"
                                                 "port:p              - filter on TCP port\n"
                                                 "socket: x.x.x.x:srcport-y.y.y.y:dstport\n"
                                                 "mac:hh-hh-hh-hh-hh-hh\n"
                                                 "prot:protocol\n"
                                                 "bpf:create your own raw bpf filter\n"
            )
            ("report", po::value<std::string>(), "Report Option: One of\n\n"
                                                 "prot  - Protocol Report\n"
                                                 "eth   - Ethernet Report\n"
                                                 "tcp   - TCP Conversation Report\n"
                                                 "hp    - Host Pair Report\n"
                                                 "all   - All Reports (Default)\n"
            )
            ("sorteth", po::value<std::string>(), "Sort Option: One of\n\n"
                                                  "Ethernet Stats Table\n\n"
                                                  "\tUse column header name for sorting\n"
            )
            ("sortprot", po::value<std::string>(), "Sort Option: One of\n\n"
                                                   "\tUse column header name for sorting\n"
            )
            ("sorthp", po::value<std::string>(), "Sort Option: One of\n\n"
                                                 "HostPair\n\n"
                                                 "\tUse column header name for sorting\n"
            )
            ("sorttcp", po::value<std::string>(), "\n\nTCP Conversation Table\n\n"
                                                  "\tUse column header name for sorting\n"

            );
    po::variables_map vm;
    po::store(po::command_line_parser(argc, argv).
            options(desc).allow_unregistered().run(), vm);
    po::notify(vm);

    bool debug{false};
    if (vm.count("log")) {
        debug = true;
    }

    enum reportType {
        text, csv, pdf
    };
    int rt = text;
    if (vm.count("reportType")) {
        std::string s{vm["reportType"].as<std::string>()};
        if (s == "csv") rt = csv;
    }

    if (vm.count("help")) {
        std::cout << desc << "\n";
        return 1;
    }

    if (!vm.count("filename")) {
        fmt::print("{}No filename passed. Must provide a name of a pcap file{}\n", red, reset);
        return 1;
    }


    std::map<std::string, std::string> sortString;
    sortString["hp"] = "id";
    sortString["tcp"] = "id";
    sortString["eth"] = "id";
    sortString["prot"] = "id";

    if (vm.count("sortprot")) {
        std::string s{vm["sortprot"].as<std::string>()};
        std::locale loc;
        std::string s2;
        for (auto elem: s)
            s2 += std::tolower(elem, loc);
        sortString["prot"] = s2;
    }
    if (vm.count("sorteth")) {
        std::string s{vm["sorteth"].as<std::string>()};
        std::locale loc;
        std::string s2;
        for (auto elem: s)
            s2 += std::tolower(elem, loc);
        sortString["eth"] = s2;
    }
    if (vm.count("sorthp")) {
        std::string s{vm["sorthp"].as<std::string>()};
        std::locale loc;
        std::string s2;
        for (auto elem: s)
            s2 += std::tolower(elem, loc);
        sortString["hp"] = s2;
    }
    if (vm.count("sorttcp")) {
        std::string s{vm["sorttcp"].as<std::string>()};
        std::locale loc;
        std::string s2;
        for (auto elem: s)
            s2 += std::tolower(elem, loc);
        sortString["tcp"] = s2;
    }
    std::string reportType{"all"};
    if (vm.count("report")) {
        reportType = vm["report"].as<std::string>();
    }
    std::string listSocket;
    std::string bpf{};
    if (vm.count("list")) {
        std::string list{vm["list"].as<std::string>()};
        std::string sip{}, dip{};
        std::string sport{}, dport{};
        const std::string &s{list};
        std::regex rgx(R"(^(\d+\.\d+\.\d+\.\d+):(\d+)\-(\d+\.\d+\.\d+\.\d+):(\d+))");
        std::smatch match;
        if (std::regex_search(s.begin(), s.end(), match, rgx)) {
            sip = match[1];
            sport = match[2];
            dip = match[3];
            dport = match[4];
            listSocket = fmt::format("{}:{}-{}:{}", sip, sport, dip, dport);
            bpf = fmt::format("port {} and port {} and host {} and host {}", sport, dport, sip, dip);
        }
    }
    if (debug) SPDLOG_INFO("Sort options: Host Pair={}   TCP Conversation={}", sortString["hp"], sortString["tcp"]);

    std::string filename{vm["filename"].as<std::string>()};
    fmt::print("\nProcessing file name:{}{}{}.\n\n", green, filename, reset);
    if (debug) SPDLOG_INFO("Processing file name:{}.", filename);

    /**
     * ### Open passed pcap file for reading packets
     */

    pcpp::IFileReaderDevice *reader = pcpp::IFileReaderDevice::getReader(filename);
    if (!reader->open()) {
        std::cerr << "Error opening the pcap file\n" << std::endl;
        if (debug) SPDLOG_INFO("PCPP Reader failed to open file");
        return 1;
    }

    /**
     * process filter if supplied
     *  ip:x.x.x.x         - filter on IPaddress
     *  hp:x.x.x.x-y.y.y.y - filter oon a host pair
     *  port:p              - filter on TCP port
     *  socket: x.x.x.x:srcport-y.y.y.y:dstport
     *  mac:hh-hh-hh-hh-hh-hh
     *  prot:tcp|udp...
     *  bpf: BOF string - use any of the BPF commands. Put filter at end of command line or enclose in quotes
     */
    if (listSocket.empty()) {
        if (vm.count("filter")) {
            std::string filter{vm["filter"].as<std::string>()};

            if (filter.starts_with("ip:")) {
                size_t pos{};
                std::string s1{}, s2{};
                std::string delimiter = ":";
                pos = filter.find(delimiter);
                s2 = filter.substr(pos + delimiter.length());
                pcpp::IPFilter gf(s2, pcpp::SRC_OR_DST);
                gf.parseToString(bpf);
            }

            if (filter.starts_with("socket:")) {
                std::string sip{}, dip{};
                std::string sport{}, dport{};
                const std::string &s{filter};
                std::regex rgx(R"(^.*:(\d+\.\d+\.\d+\.\d+):(\d+)\-(\d+\.\d+\.\d+\.\d+):(\d+))");
                std::smatch match;
                if (std::regex_search(s.begin(), s.end(), match, rgx)) {
                    sip = match[1];
                    sport = match[2];
                    dip = match[3];
                    dport = match[4];
                    bpf = fmt::format("port {} and port {} and host {} and host {}", sport, dport, sip, dip);
                }
            }

            if (filter.starts_with("hp:")) {
                std::string sip{}, dip{};
                const std::string &shp{filter};
                std::regex rgxhp(R"(^.*:(\d+\.\d+\.\d+\.\d+)\-(\d+\.\d+\.\d+\.\d+))");
                std::smatch match;
                if (std::regex_search(shp.begin(), shp.end(), match, rgxhp)) {
                    sip = match[1];
                    dip = match[2];
                    bpf = fmt::format("(host {}) and (host {})", sip, dip);
                }
            }

            if (filter.starts_with("port:")) {
                std::string port{};
                const std::string &s{filter};
                std::regex rgxhp(R"(^.*:(\d+))");
                std::smatch match;
                if (std::regex_search(s.begin(), s.end(), match, rgxhp)) {
                    port = match[1];
                    bpf = fmt::format("port {}", port);
                }
            }

            if (filter.starts_with("prot:")) {
                std::string prot{};
                const std::string &s{filter};
                std::regex rgxhp(R"(^.*:(.*))");
                std::smatch match;
                if (std::regex_search(s.begin(), s.end(), match, rgxhp)) {
                    prot = match[1];
                    bpf = fmt::format("{}", prot);
                }
            }

            if (filter.starts_with("mac:")) {
                std::string mac{};
                const std::string &s{filter};
                std::regex rgxhp(R"(^.*:(..:..:..:..:..:..))");
                std::smatch match;
                if (std::regex_search(s.begin(), s.end(), match, rgxhp)) {
                    mac = match[1];
                    bpf = fmt::format("ether host {}", mac);
                }
            }

            if (filter.starts_with("bpf:")) {
                const std::string &s{filter};
                std::regex rgxhp(R"(^.*:(.*)$)");
                std::smatch match;
                if (std::regex_search(s.begin(), s.end(), match, rgxhp)) {
                    bpf = match[1];
                }
            }
        }
    }
    if (debug) SPDLOG_INFO(bpf);
    if (!reader->setFilter(bpf)) {
        fmt::print("Could not set up filter on file");
    }

    /**
     * ### Loop over file reading a packet, sending it to the parser, until EOF
     */

    std::map<std::string, HostPair> hostPairList;
    std::map<std::string, TCPConversation> tcpConversationList;
    std::map<std::string, EthernetStats> ethernetStatsList;
    std::map<std::string, ProtocolStats> protocolStatsList;

    std::map<uint16_t, int> ipIdList{};
    std::map<uint32_t, std::vector<long>> ssl{};
    std::map<uint32_t, std::vector<long>> rsl{};

    pcpp::RawPacket rawPacket;
    int packetCount{0};
    if (debug) SPDLOG_INFO("processing pckets");
    while (reader->getNextPacket(rawPacket)) {
        packetCount++;
        pcpp::Packet parsedPacket(&rawPacket);
        print(parsedPacket, packetCount, debug);
        if (!listSocket.empty()) pp(parsedPacket, packetCount, ipIdList, ssl, rsl, listSocket);
        parser(parsedPacket,
               hostPairList,
               tcpConversationList,
               ethernetStatsList,
               protocolStatsList,
               packetCount, debug);
    }

    /**
     * ### Generate reports
     */

    if (debug) SPDLOG_INFO("Processing report");

    switch (rt) {
        case text :
            report(hostPairList, tcpConversationList, sortString, ethernetStatsList, protocolStatsList, debug,
                   reportType);
            break;
        case csv :
            writeCsv(hostPairList, tcpConversationList, sortString, ethernetStatsList, protocolStatsList, debug,
                     reportType);
            break;
    }

    // close the packet reader

    reader->close();

    // closing stats

    auto t_end = std::chrono::high_resolution_clock::now();

    double elapsed_time_ms = std::chrono::duration<double, std::milli>(t_end - t_start).count();

    SPDLOG_INFO("Packets processed: {} in {} ms", packetCount, elapsed_time_ms);
    fmt::print("\n\nPackets processed: {} in {} ms {} seconds\n\n", packetCount, elapsed_time_ms,
               elapsed_time_ms / 1000.0);
    SPDLOG_INFO("Complete...Exiting");
    return 0;

}
