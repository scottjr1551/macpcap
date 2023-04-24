//
// Created by Scott Roberts on 8/22/22.
//

/**
 * @file
 * @brief EtherNet Statistics
 *
 * This class file contains the code needed to collect Ethernet header layer statistics
 *
 * TODO: All the classes use the same sort algorithms. Find a way to combine into one file.
 */
#include "EthernetStats.h"

/**
 * @callgraph
 * @callergraph
 * @param pkt               Parsed PcapPlusPLus packet
 * @param debugOption       Turn on/off debug logging
 */
void EthernetStats::updateCounters(const pcpp::Packet &pkt) {
    auto *ethLayer = dynamic_cast<pcpp::EthLayer *>(pkt.getLayerOfType(pcpp::Ethernet));
    std::string sourceMac = ethLayer->getSourceMac().toString();
    std::string destMac = ethLayer->getDestMac().toString();
    std::string key = sourceMac + "<->" + destMac;
    uint32_t payLoad = ethLayer->getLayerPayloadSize();
    if (debug) SPDLOG_INFO("Payload Size {}", payLoad);

    // get raw packet so we can get timestamp
    pcpp::RawPacket *rawPkt = pkt.getRawPacketReadOnly();
    timespec ts = rawPkt->getPacketTimeStamp();
    if (firstTimeStamp.tv_sec == 0) firstTimeStamp = ts;
    duration = EthernetStats::tsConSec(ts) - EthernetStats::tsConSec(firstTimeStamp);
    packetRate = (duration == 0) ? 0.0 : packets / duration;

    packets++;
    byteCount += payLoad;
    if (key == firstSpeaker) {//send
        sendPkt++;
        sendByteCount += payLoad;
        sendPacketRate = (duration == 0) ? 0.0 : sendPkt / duration;
    } else { //recv
        recvPkt++;
        recvByteCount += payLoad;
        recvPacketRate = (duration == 0) ? 0.0 : recvPkt / duration;
    }
}

/**
 * \callgraph
 * @callergraph
 * @param el    - Ethernet Statistics List
 */
void
EthernetStats::writeCsvTable(std::map<std::string, EthernetStats> &el, const std::string &ss, bool debug) {
    /**
    * ##Processing Overview
    *
    * ### Sort map
    */
    std::vector<std::string> sl{EthernetStats::sortMap(el, ss, debug)};
    if (sl.empty()) sl = EthernetStats::sortMap(el, "id", debug);

    try {
        csvfile csv("EtherStatsTable.csv"); // throws exceptions!
        // Header
        csv << "MacPair" << "PacketCount" << "InPacketCount" << "OutPacketCount" << "ByteCount" << "InByteCnt" <<
            "OutByteCnt" << "PacketRate" << "InPacketRate" << "OutPacketRate" << "Duration(sec)" << endrow;
        // Data
        for (auto const &key: sl) {
            EthernetStats value = el[key];
            csv << key << std::to_string(value.packets) <<
                std::to_string(value.sendPkt) <<
                std::to_string(value.recvPkt) <<
                std::to_string(value.byteCount) <<
                std::to_string(value.sendByteCount) <<
                std::to_string(value.recvByteCount) <<
                std::to_string(value.packetRate) <<
                std::to_string(value.recvPacketRate) <<
                std::to_string(value.sendPacketRate) <<
                std::to_string(value.duration) << endrow;
        }
    }
    catch (const std::exception &e) {
        SPDLOG_INFO("Exception was thrown: {}", e.what());
    }

}

/**
 * \callgraph
 * @callergraph
 * @param el    - Ethernet Statistics List
 */
void
EthernetStats::printTable(std::map<std::string, EthernetStats> &el, const std::string &ss, bool debug) {
    if (debug) SPDLOG_INFO("Printing EthernetStats Table. ss={}", ss);
    /**
     * ##Processing Overview
     *
     * ### Sort map
     */
    fmt::print("\n\nEthernet Stats Table\n\n");
    std::vector<std::string> sl{EthernetStats::sortMap(el, ss, debug)};
    if (sl.size() == 0) sl = EthernetStats::sortMap(el, "id", debug);
    /**
     *
     * ### Print report header
     */
    using namespace tabulate;
    Table t;

    t.add_row({
                      "MacPair", "PacketCount", "InPacketCount", "OutPacketCount", "ByteCount", "InByteCnt",
                      "OutByteCnt", "PacketRate", "InPacketRate", "OutPacketRate", "Duration(sec)"});
    /**
     * ### Loop through EthernetStats map and print each record
     */
    for (auto const &key: sl) {
        EthernetStats value = el[key];
        t.add_row({key,
                   std::to_string(value.packets),
                   std::to_string(value.sendPkt),
                   std::to_string(value.recvPkt),
                   std::to_string(value.byteCount),
                   std::to_string(value.sendByteCount),
                   std::to_string(value.recvByteCount),
                   std::to_string(value.packetRate),
                   std::to_string(value.recvPacketRate),
                   std::to_string(value.sendPacketRate),
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
                .font_color(Color::blue)
                .font_style({FontStyle::bold});

    }

    t.print(std::cout);
}

/**
 * @callgraph
 * @callergraph
 * @param vint      - Vector of pairs in the format <string,int>
 * @return          - string of EthernetStats keys in sorted order
 *
 * sort a list of pairs by second element, in this case int
 */
std::vector<std::string> EthernetStats::sortInt(std::vector<std::pair<std::string, int >> vint, bool debug) {
    if (debug) SPDLOG_INFO("");
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
 * @param v     Vector of pairs. Each pair is of string,double
 * @return      string of EthernetStats keys in sort order
 *
 * Sort a list of pairs by the second element, in this case doubles.
 */
std::vector<std::string> EthernetStats::sortDbl(std::vector<std::pair<std::string, double >> v, bool debug) {
    if (debug) SPDLOG_INFO("");
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
 * @param v     Vector of pairs. Each pair is of string,double
 * @return      string of EthernetStats keys in sort order
 *
 * Sort a list of pairs by the second element, in this case strings.
 */
std::vector<std::string> EthernetStats::sortStr(std::vector<std::pair<std::string, std::string >> v, bool debug) {
    if (debug) SPDLOG_INFO("");
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
 * @param hpl       EthernetStats map
 * @param colId     Column to sort
 * @return          Vector of EthernetStats keys in sorted order
 *
 * Routine will take a map of EthernetStats instances and sort it in descending order based on the column ID. The returned
 * string will be used index the EthernetStats list to print the list in sorted order.
 */
std::vector<std::string>
EthernetStats::sortMap(const std::map<std::string, EthernetStats> &hpl, const std::string &colId, bool debug) {
    if (debug) SPDLOG_INFO("colId {}", colId);
    std::vector<std::pair<std::string, int >> vint{};
    std::vector<std::pair<std::string, double >> vdouble{};
    std::vector<std::pair<std::string, std::string >> vstring{};

    // process int variables
    for (auto const &[key, value]: hpl) {
        if (colId == "id" || colId.starts_with("macp")) vstring.emplace_back(key, key);
        if (colId == "pc" || colId.starts_with("packetc")) vint.emplace_back(key, value.packets);
        if (colId == "rpc" || colId.starts_with("inpacketc")) vint.emplace_back(key, value.recvPkt);
        if (colId == "spc" || colId.starts_with("outpacketc")) vint.emplace_back(key, value.sendPkt);
        if (colId == "bc" || colId.starts_with("bytec")) vint.emplace_back(key, value.byteCount);
        if (colId == "rbc" || colId.starts_with("inbytec")) vint.emplace_back(key, value.recvByteCount);
        if (colId == "sbc" || colId.starts_with("outbytec")) vint.emplace_back(key, value.sendByteCount);
        if (colId == "pr" || colId.starts_with("pscketr")) vdouble.emplace_back(key, value.packetRate);
        if (colId == "pir" || colId.starts_with("inpacketr")) vdouble.emplace_back(key, value.recvPacketRate);
        if (colId == "opr" || colId.starts_with("outpacketr")) vdouble.emplace_back(key, value.sendPacketRate);
        if (colId == "dur" || colId.starts_with("du")) vdouble.emplace_back(key, value.duration);
    }
    std::vector<std::string> r{};
    if (!vint.empty()) return sortInt(vint, debug);
    if (!vdouble.empty()) return sortDbl(vdouble, debug);
    if (!vstring.empty()) return sortStr(vstring, debug);
    return r;
}

