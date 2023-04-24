//
// Created by Scott Roberts on 8/6/22.
//
/**
 * @file
 * @class
 */

#ifndef MACPCAP_HOSTPAIR_H
#define MACPCAP_HOSTPAIR_H

#include <map>
#include <IPv4Layer.h>
#include <Packet.h>
#include <Layer.h>
#include <IPv4Layer.h>
#include <fmt/format.h>
#include <fmt/format.h>
#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <spdlog/spdlog.h>
#include <typeinfo>
#include <spdlog/spdlog.h>
#include "../include/tabulate.hpp"
#include "../include/csvfile.h"


class HostPair {
public:
    bool debug{false};

    void setFirstSpeaker(std::string);

    std::string getFirstSpeaker();

    void
    updateCounters(const pcpp::Packet &pkt, pcpp::Layer &ipHd, std::string &currentIpAddress);

    static void printTable(std::map<std::string, HostPair> &hpl, const std::string &ss, bool debug);

    static std::vector<std::string> sortMap(const std::map<std::string, HostPair> &hpl, const std::string &colId);

    static std::vector<std::string> sortInt(std::vector<std::pair<std::string, int >> vint);

    static std::vector<std::string> sortDbl(std::vector<std::pair<std::string, double >> v);

    static std::vector<std::string> sortStr(std::vector<std::pair<std::string, std::string >> v);

    static std::vector<std::string> getIpPair(const pcpp::Packet &pkt, bool debug);

    static long double tsConSec(timespec ts) {
        return ((ts.tv_sec) * 1e9 + (ts.tv_nsec)) / 1e9L;
    }

    static void writeCsvTable(std::map<std::string, HostPair> &hpl, const std::string &ss, bool debug);

    /**
 * @callergraph
 * @callgraph
 * @param pkt
 * @return
 */
    static std::string getIpAddress(pcpp::Packet pkt, bool debug) {
        std::string s1{};
        if (pcpp::Layer *ipv4 = pkt.getLayerOfType(pcpp::IPv4); ipv4 != nullptr) {
            auto *ipv4hdr = dynamic_cast<pcpp::IPv4Layer *>(ipv4);
            std::string src = ipv4hdr->getSrcIPAddress().toString();
            std::string dst = ipv4hdr->getDstIPAddress().toString();
            s1 = src + "<-->" + dst;
        }
        if (debug) SPDLOG_INFO("s1 {}", s1);
        return s1;
    }

private:
    std::string firstSpeaker{};
    timespec firstTimeStamp{0, 0};
    bool firstTS{false};
    int packetCount{0};
    int inputPacketCount{0};
    int outputPacketCount{0};
    int byteCount{0};
    int inputByteCount{0};
    int outputByteCount{0};
    double packetRate{0.0};
    double inputPacketRate{0.0};
    double outputPacketRate{0.0};
    long double duration{0.0};

};


#endif //MACPCAP_HOSTPAIR_H
