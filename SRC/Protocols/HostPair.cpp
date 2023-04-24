//
// Created by Scott Roberts on 8/6/22.
//
/**
 * @file
 * @brief HostPair Class Methods
 */
#include "HostPair.h"

/**
 * @callgraph
 * @callergraph
 * @param pkt                   PcapPlus Parsed Packet
 * @param ipHdr                 Address of the IP packet header
 * @param currentIPAddress      This is the HostPair IP addresses for the current packet. Used to determine first speaker.
 */
void HostPair::updateCounters(const pcpp::Packet &pkt, pcpp::Layer &ipHdr,
                              std::string &currentIPAddress) {
    if (debug) SPDLOG_INFO("");
    // get raw packet so we can get timestamp
    pcpp::RawPacket *rawPkt = pkt.getRawPacketReadOnly();
    timespec ts = rawPkt->getPacketTimeStamp();
    if (!firstTS) {
        firstTimeStamp = ts;
        firstTS = true;
    }
    // add statistics to HostPair class
    packetCount++;
    duration = tsConSec(ts) - tsConSec(firstTimeStamp);
    packetRate = (duration == 0) ? 0.0 : packetCount / duration;
    int dataLen = ipHdr.getLayerPayloadSize();
    byteCount += dataLen;
    if (firstSpeaker == currentIPAddress) {
        outputPacketCount++;
        outputByteCount += dataLen;
        outputPacketRate = (duration == 0) ? 0.0 : outputPacketCount / duration;
    } else {
        inputPacketCount++;
        inputByteCount += dataLen;
        inputPacketRate = (duration == 0) ? 0.0 : inputPacketCount / duration;
    }
}

/**
 * \callgraph
 * @callergraph
 * @param s
 */
void HostPair::setFirstSpeaker(std::string s) {
    HostPair::firstSpeaker = s;
}

/**
 * \callgraph
 * @callergraph
 * @return
 */
std::string HostPair::getFirstSpeaker() {
    return HostPair::firstSpeaker;
}

/**
 * \callgraph
 * @callergraph
 * @param hpl       Host Pair List. A map whose key is a string of IP pair (source and destination) addresses. The value
 *                  of the map is a HostPair class object.
 */
void HostPair::printTable(std::map<std::string, HostPair> &hpl, const std::string &ss, bool debug) {
    if (debug) SPDLOG_INFO("Printing HostPair Table. ss={}", ss);
    /**
     * ##Processing Overview
     *
     * ### Sort map
     */
    fmt::print("\n\nHost Pair List Report\n\n");
    std::vector<std::string> sl{HostPair::sortMap(hpl, ss)};
    if (sl.empty()) sl = HostPair::sortMap(hpl, "id");
    /**
     *
     * ### Print report header
     */
    using namespace tabulate;
    Table t;

    t.add_row({
                      "HostPair",
                      "PacketCount",
                      "InPacketCount",
                      "OutPacketCount",
                      "ByteCount",
                      "InByteCnt",
                      "OutByteCnt",
                      "PacketRate",
                      "InPacketRate",
                      "OutPacketRate",
                      "Duration(sec)"
              });
    /**
     * ### Loop through HostPair map and print each record
     */
    for (auto const &key: sl) {
        HostPair value = hpl[key];
        t.add_row({
                          key,
                          std::to_string(value.packetCount),
                          std::to_string(value.inputPacketCount),
                          std::to_string(value.outputPacketCount),
                          std::to_string(value.byteCount),
                          std::to_string(value.inputByteCount),
                          std::to_string(value.outputByteCount),
                          std::to_string(value.packetRate),
                          std::to_string(value.inputPacketRate),
                          std::to_string(value.outputPacketRate),
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
                .font_color(Color::red)
                .font_style({FontStyle::bold});

    }

    t.print(std::cout);
}

/**
 * @callgraph
 * @callergraph
 * @param vint      - Vector of pairs in the format <string,int>
 * @return          - string of HostPair keys in sorted order
 *
 * sort a list of pairs by second element, in this case int
 */
std::vector<std::string> HostPair::sortInt(std::vector<std::pair<std::string, int >> vint) {
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
 * @return      string of HostPair keys in sort order
 *
 * Sort a list of pairs by the second element, in this case doubles.
 */
std::vector<std::string> HostPair::sortDbl(std::vector<std::pair<std::string, double >> v) {
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
 * @return      string of HostPair keys in sort order
 *
 * Sort a list of pairs by the second element, in this case strings.
 */
std::vector<std::string> HostPair::sortStr(std::vector<std::pair<std::string, std::string >> v) {
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
 * @param hpl       Host Pair List. A map whose key is a string of IP pair (source and destination) addresses. The value
 *                  of the map is a HostPair class object.
 * @param colId     Column to sort
 * @return          Vector of HostPair keys in sorted order
 *
 * Routine will take a map of HostPair instances and sort it in descending order based on the column ID. The returned
 * string will be used index the HostPair list to print the list in sorted order.
 */
std::vector<std::string> HostPair::sortMap(const std::map<std::string, HostPair> &hpl, const std::string &colId) {
    std::vector<std::pair<std::string, int >> vint{};
    std::vector<std::pair<std::string, double >> vdouble{};
    std::vector<std::pair<std::string, std::string >> vstring{};

    // process int variables
    for (auto const &[key, value]: hpl) {
        if (colId == "id" || colId.starts_with("hostp")) vstring.emplace_back(key, key);
        if (colId == "pc" || colId.starts_with("packetc")) vint.emplace_back(key, value.packetCount);
        if (colId == "ipc" || colId.starts_with("inpacketc")) vint.emplace_back(key, value.inputPacketCount);
        if (colId == "opc" || colId.starts_with("outpacketc")) vint.emplace_back(key, value.outputPacketCount);
        if (colId == "bc" || colId.starts_with("bytec")) vint.emplace_back(key, value.byteCount);
        if (colId == "ibc" || colId.starts_with("inbytec")) vint.emplace_back(key, value.inputByteCount);
        if (colId == "obc" || colId.starts_with("outbytec")) vint.emplace_back(key, value.outputByteCount);
        if (colId == "pr" || colId.starts_with("packetr")) vdouble.emplace_back(key, value.packetRate);
        if (colId == "pir" || colId.starts_with("inpacketr")) vdouble.emplace_back(key, value.inputPacketRate);
        if (colId == "opr" || colId.starts_with("outpacketr")) vdouble.emplace_back(key, value.outputPacketRate);
        if (colId == "dur" || colId.starts_with("dur")) vdouble.emplace_back(key, value.duration);
    }
    std::vector<std::string> r{};
    if (!vint.empty()) return sortInt(vint);
    if (!vdouble.empty()) return sortDbl(vdouble);
    if (!vstring.empty()) return sortStr(vstring);
    return r;
}


/**
 * \callgraph
 * @callergraph
 * \brief Get IP Pair Key
 * This routine will create a ip source and destination key used to index the hostPairList map
 * The key is a two element vector that contains the following
 *  - Source Ip + "<-->" + Destination ip
 *  - Destination IP + <--> Source Ip
 *
 * @param pkt       PcapPlusPlus parsed packet
 * @return          String vector with a Source and Destination IP pair address string
 */
std::vector<std::string> HostPair::getIpPair(const pcpp::Packet &pkt, bool debug) {
    std::vector<std::string> ipkey{"", ""};
    if (pcpp::Layer *ipv4 = pkt.getLayerOfType(pcpp::IPv4); ipv4 != NULL) {
        auto *ipv4hdr = dynamic_cast<pcpp::IPv4Layer *>(ipv4);
        std::string src = ipv4hdr->getSrcIPAddress().toString();
        std::string dst = ipv4hdr->getDstIPAddress().toString();
        std::string s1 = src + "-" + dst;
        std::string s2 = dst + "-" + src;
        ipkey = {s1, s2};
    }
    if (debug) SPDLOG_INFO("key {} {}", ipkey[0], ipkey[1]);
    return ipkey;
}

/**
 * \callgraph
 * @callergraph
 * @param el    - Ethernet Statistics List
 */
void
HostPair::writeCsvTable(std::map<std::string, HostPair> &hpl, const std::string &ss, bool debug) {
    /**
    * ##Processing Overview
    *
    * ### Sort map
    */
    std::vector<std::string> sl{HostPair::sortMap(hpl, ss)};
    if (sl.empty()) sl = HostPair::sortMap(hpl, "id");

    try {
        csvfile csv("HostPairTable.csv"); // throws exceptions!
        // Header
        csv << "HostPair" <<
            "PacketCount" <<
            "InPacketCount" <<
            "OutPacketCount" <<
            "ByteCount" <<
            "InByteCnt" <<
            "OutByteCnt" <<
            "PacketRate" <<
            "InPacketRate" <<
            "OutPacketRate" <<
            "Duration(sec)" << endrow;
        // Data
        for (auto const &key: sl) {
            HostPair value = hpl[key];
            csv << key << std::to_string(value.packetCount) <<
                std::to_string(value.inputPacketCount) <<
                std::to_string(value.outputPacketCount) <<
                std::to_string(value.byteCount) <<
                std::to_string(value.inputByteCount) <<
                std::to_string(value.outputByteCount) <<
                std::to_string(value.packetRate) <<
                std::to_string(value.inputPacketRate) <<
                std::to_string(value.outputPacketRate) <<
                std::to_string(value.duration) << endrow;
        }
    }
    catch (const std::exception &e) {
        SPDLOG_INFO("Exception was thrown: {}", e.what());
    }

}
