//
// Created by Scott Roberts on 8/22/22.
//

/**
 * @file
 * @brief Ethernet Class Header File
 *
 * Header file for use with EthernetStats.cpp
 * @class
 *
 * Ethernet Class for collection of statistics
 */

#ifndef MACPCAP_ETHERNETSTATS_H
#define MACPCAP_ETHERNETSTATS_H

#include <map>
#include <IPv4Layer.h>
#include <Packet.h>
#include <Layer.h>
#include <IPv4Layer.h>
#include <fmt/format.h>
//#include "../Master.h"
#include <fmt/format.h>
#include <iostream>
#include <string>
#include <utility>
#include <vector>
#include <map>
#include <spdlog/spdlog.h>
#include <typeinfo>
#include <EthLayer.h>
#include "../include/tabulate.hpp"


class EthernetStats {
public:
    bool debug{false};

    void updateCounters(const pcpp::Packet &pkt);

    static void printTable(std::map<std::string, EthernetStats> &el, const std::string &ss, bool debug);

    static std::vector<std::string>
    sortMap(const std::map<std::string, EthernetStats> &el, const std::string &colId, bool debug);

    static std::vector<std::string> sortInt(std::vector<std::pair<std::string, int >> vint, bool debug);

    static std::vector<std::string> sortDbl(std::vector<std::pair<std::string, double >> v, bool debug);

    static std::vector<std::string> sortStr(std::vector<std::pair<std::string, std::string >> v, bool debug);

    static long double tsConSec(timespec ts) {
        return ((ts.tv_sec) * 1e9 + (ts.tv_nsec)) / 1e9L;
    }

    void setFs(std::string fs) {
        firstSpeaker = fs;
    }

private:
    timespec firstTimeStamp{NULL};
    std::string firstSpeaker{};
    uint32_t packets{0};
    uint32_t sendPkt{0};
    uint32_t recvPkt{0};
    uint32_t byteCount{0};
    uint32_t sendByteCount{0};
    uint32_t recvByteCount{0};
    double packetRate{0.0};
    double recvPacketRate{0.0};
    double sendPacketRate{0.0};
    long double duration{0.0};


};


#endif //MACPCAP_ETHERNETSTATS_H
