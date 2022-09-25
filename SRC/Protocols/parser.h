//
// Created by Scott Roberts on 7/27/22.
//
/**
 * @file
 */

#ifndef MACPCAP_PARSER_H
#define MACPCAP_PARSER_H


#include <IPv4Layer.h>
#include <Packet.h>
#include <fmt/format.h>
#include <spdlog/spdlog.h>
#include <Layer.h>
#include <EthLayer.h>
#include "TCPConversation.h"
#include "HostPair.h"
#include "EthernetStats.h"
#include "ProtocolStats.h"

void parser(pcpp::Packet &pkt, std::map<std::string, HostPair> &hostPairList,
            std::map<std::string, TCPConversation> &tcpConversationList,
            std::map<std::string, EthernetStats> &ethernetStatsList,
            std::map<std::string, ProtocolStats> &pl,
            int pc,
            bool debug
);

static std::string getIPMapInstance(const pcpp::Packet &pkt,
                                    std::map<std::string,
                                            HostPair> &hostPairList,
                                    bool debug);

static int processTcpPacket(const pcpp::Packet &pkt,
                            pcpp::IPv4Layer *ipHdr,
                            std::map<std::string, TCPConversation> &tcpl,
                            std::map<std::string, HostPair> &hostPairList,
                            bool debug,
                            int pc
);

static void processIpPacket(const pcpp::Packet &pkt,
                            pcpp::Layer *ipHdr,
                            std::map<std::string, HostPair> &hostPairList,
                            std::map<std::string, TCPConversation> &tcpl,
                            int pc,
                            bool debug
);

static std::vector<std::string> getMacAddress(pcpp::Packet &pkt, bool debug);

void
processProtocol(const pcpp::Packet &pkt, pcpp::ProtocolType p, std::map<std::string, ProtocolStats> &pl, bool debug);

void processEthernet(pcpp::Packet &pkt, std::map<std::string, EthernetStats> &ethernetStatsList, bool debug);


#endif //MACPCAP_PARSER_H
