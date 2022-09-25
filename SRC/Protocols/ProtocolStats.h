//
// Created by Scott Roberts on 8/23/22.
//
/**
 * @file
 * @breif Protocol Statistics Header
 */
#ifndef MACPCAP_PROTOCOLSTATS_H
#define MACPCAP_PROTOCOLSTATS_H

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


class ProtocolStats {
public:
    bool debug{false};

    static void printTable(std::map<std::string, ProtocolStats> &pl, const std::string &ss, bool debug);

    static std::vector<std::string> sortMap(const std::map<std::string, ProtocolStats> &pl, const std::string &colId);

    static std::vector<std::string> sortInt(std::vector<std::pair<std::string, int >> vint);

    static std::vector<std::string> sortDbl(std::vector<std::pair<std::string, double >> v);

    static std::vector<std::string> sortStr(std::vector<std::pair<std::string, std::string >> v);

    void updateCounters(const pcpp::Packet &pkt);

    static long double tsConSec(timespec ts) {
        return ((ts.tv_sec) * 1e9 + (ts.tv_nsec)) / 1e9L;
    }


private:
    timespec firstTimeStamp{0, 0};
    long packets{0};
    uint32_t byteCount{0};
    double packetRate{0.0};
    long double duration{0.0L};
};


#endif //MACPCAP_PROTOCOLSTATS_H
