//
// Created by Scott Roberts on 8/23/22.
//

/**
 * @file
 * @brief Process protocol statistics for a packet
 *
 * Routine handles the collection and display of statistics for protocols seen in the packet,
 */

#include "ProtocolStats.h"


/**
 * \callgraph
 * @callergraph
 * @brief Routine to print out the protocol statistics table
 * @param pl    Map of protocol class objects for collecting statistics
 */
void
ProtocolStats::printTable(std::map<std::string, ProtocolStats> &pl, const std::string &ss, bool debug) {
    if (debug) SPDLOG_INFO("Printing Protocol Stats  Table. ss={}", ss);
    /**
     * ##Processing Overview
     *
     * ### Sort map
     */
    std::vector<std::string> sl{ProtocolStats::sortMap(pl, ss)};
    if (sl.empty() == 0) sl = ProtocolStats::sortMap(pl, "id");
    /**
     *
     * ### Print report header
     */
    using namespace tabulate;
    Table t;

    t.add_row({
                      "Protocol",
                      "PacketCount",
                      "ByteCount",
                      "PacketRate",
                      "Duration(sec)"
              });
    /**
     * ### Loop through ProtocolStats map and print each record
     */
    for (auto const &key: sl) {
        ProtocolStats value = pl[key];
        t.add_row({key,
                   std::to_string(value.packets),
                   std::to_string(value.byteCount),
                   std::to_string(value.packetRate),
                   std::to_string(value.duration)
                  });
    }
    t.format()
            .font_style({FontStyle::bold})
            .hide_border()
            .border_top(" ")
            .border_left(" ")
            .border_right(" ")
            .corner("");
    for (auto &cell: t[0]) {
        cell.format()
                .border_bottom("")
                .border_top("")
                .font_color(Color::green)
                .font_style({FontStyle::bold});

    }

    t.print(std::cout);
}

/**
 * @callgraph
 * @callergraph
 * @brief  sort a list of pairs by second element, in this case int
 * @param vint      - Vector of pairs in the format <string,int>
 * @return          - string of HostPair keys in sorted order
 *
 * sort a list of pairs by second element, in this case int
 */
std::vector<std::string> ProtocolStats::sortInt(std::vector<std::pair<std::string, int >> vint) {
    std::vector<std::string> results{};
    std::sort(vint.begin(), vint.end(), [](auto &left, auto &right) {
        return left.second > right.second;
    });
    for (auto const &p: vint) {
        results.emplace_back(p.first);
    }
    return results;
}

/**
 * @callgraph
 * @callergraph
 * @brief  Sort a list of pairs by the second element, in this case doubles.
 * @param v     Vector of pairs. Each pair is of string,double
 * @return      string of HostPair keys in sort order
 *
 * Sort a list of pairs by the second element, in this case doubles.
 */
std::vector<std::string> ProtocolStats::sortDbl(std::vector<std::pair<std::string, double >> v) {
    std::vector<std::string> results{};
    std::sort(v.begin(), v.end(), [](auto &left, auto &right) {
        return left.second > right.second;
    });
    for (auto const &p: v) {
        results.emplace_back(p.first);
    }
    return results;
}

/**
 * @callgraph
 * @callergraph
 * @brief  Sort a list of pairs by the second element, in this case strings.
 * @param v     Vector of pairs. Each pair is of string,double
 * @return      string of HostPair keys in sort order
 *
 * Sort a list of pairs by the second element, in this case strings.
 */
std::vector<std::string> ProtocolStats::sortStr(std::vector<std::pair<std::string, std::string >> v) {
    std::vector<std::string> results{};
    std::sort(v.begin(), v.end(), [](auto &left, auto &right) {
        return left.second > right.second;
    });
    for (auto const &p: v) {
        results.emplace_back(p.first);
    }
    return results;
}

/**
 * @callergraph
 * @callgraph
 * @param hpl       HostPair map
 * @param colId     Column to sort
 * @return          Vector of HostPair keys in sorted order
 *
 * Routine will take a map of HostPair instances and sort it in descending order based on the column ID. The returned
 * string will be used index the HostPair list to print the list in sorted order.
 */
std::vector<std::string>
ProtocolStats::sortMap(const std::map<std::string, ProtocolStats> &hpl, const std::string &colId) {
    std::vector<std::pair<std::string, int >> vint{};
    std::vector<std::pair<std::string, double >> vdouble{};
    std::vector<std::pair<std::string, std::string >> vstring{};

    // process int variables
    for (auto const &[key, value]: hpl) {
        if (colId == "id" || colId.starts_with("prot")) vstring.emplace_back(key, key);
        if (colId == "pc" || colId.starts_with("packetc")) vint.emplace_back(key, value.packets);
        if (colId == "bc" || colId.starts_with("byte")) vint.emplace_back(key, value.byteCount);
        if (colId == "pr" || colId.starts_with("packetr")) vdouble.emplace_back(key, value.packetRate);
        if (colId == "dur" || colId.starts_with("du")) vdouble.emplace_back(key, value.duration);
    }
    std::vector<std::string> r{};
    if (!vint.empty()) return sortInt(vint);
    if (!vdouble.empty()) return sortDbl(vdouble);
    if (!vstring.empty()) return sortStr(vstring);
    return r;
}


/**
 * @callgraph
 * @callergraph
 * @brief Update Statistics Counters
 * Routine will update the protocol statistics for an instance if the protocol class
 * @param pkt
 * @param debugOption
 */
void ProtocolStats::updateCounters(const pcpp::Packet &pkt) {
    if (debug) SPDLOG_INFO("Starting");
    auto *ipLayer = dynamic_cast<pcpp::IPv4Layer *>(pkt.getLayerOfType(pcpp::IPv4));
    if (ipLayer != nullptr) {
        pcpp::ProtocolType pt = ipLayer->getProtocol();
        uint32_t payLoad = ipLayer->getLayerPayloadSize();
        if (debug) SPDLOG_INFO("pt {}   PL {}", pt, payLoad);

        // get raw packet so we can get timestamp
        pcpp::RawPacket *rawPkt = pkt.getRawPacketReadOnly();
        timespec ts = rawPkt->getPacketTimeStamp();
        if (firstTimeStamp.tv_sec == 0) firstTimeStamp = ts;
        duration = tsConSec(ts) - tsConSec(firstTimeStamp);
        packetRate = (duration == 0.0L) ? 0.0 : packets / duration;

        packets++;
        byteCount += payLoad;
    }
}
