//
// Created by Scott Roberts on 8/8/22.
//
/**
 * @file
 * @brief TCP Conversation Class for Collecting Statistics
 *
 * Routine to process the TCP header and collect statistics about the TCP conversation.
 */
#include "TCPConversation.h"

std::vector<variant<std::string, const char *, std::string_view, tabulate::Table>> headers{
        "TCPConversation",
        "SrcMac",
        "DestMac",
        "HandShake",
        "CTS->D(ms)",
        "CTD-S(ms)",
        "SendAckTime-RTT",
        "recvAckTime-RTT",
        "AvgRspTime",
        "Unackseq#",
        "SendDupAck",
        "RecvDupAck",
        "Resets",
        "ZeroWindow",
        "sendDataPkt",
        "RecvDataPkt",
        "Retrans",
        "RetransRate",
        "InRetrans",
        "OutRetrans",
        "InterGapTime",
        "PacketCount",
        "InPacketCount",
        "OutPacketCount",
        "ByteCount",
        "InByteCnt",
        "OutByteCnt",
        "PacketRate",
        "RecvPacketRate",
        "SendPacketRate",
        "recvWindowUpdate",
        "sendWindowUpdate",
        "Duration(sec)"};

/**
 * @callergraph
 * @callgraph
 * @brief Format the headers of a packet
 * @param p     Parsed PcapPlusPLus packet
 * @return      Return a vector of formatted strings of the packet headers ready for logging
 */
std::vector<std::string> packetFormat(const pcpp::Packet &p) {
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
    return v;
}

//Function for variance
/**
 * @callergraph
 * @callgraph
 * @brief Calculate Variance
 *
 * Routine to calculate the variance of doubles in a vector.
 * @param v
 * @param mean
 * @return
 */
double variance(std::vector<double> &v, double mean) {
    double sum = 0.0;
    double temp = 0.0;
    double var = 0.0;

    for (auto j: v) {
        temp = pow((j - mean), 2);
        sum += temp;
    }

    return var = sum / (v.size() - 2);
}


/**
 * @callgraph
 * @callergraph
 * @brief Calculate Statistics values for a vector of doubles
 * @param v         Vector of doubles
 * @return          results vector:
 *                      mean
 *                      Square Sum
 *                      Standard Deviation
 *                      Variance
 */
std::vector<double> calcStats(std::vector<double> &v) {

    if (v.empty()) return {0.0, 0.0, 0.0, 0.0};

    double sum = std::accumulate(v.begin(), v.end(), 0.0);
    double mean = sum / v.size();
    double var = variance(v, mean);

    std::vector<double> diff(v.size());
    std::transform(v.begin(), v.end(), diff.begin(), [mean](double x) { return x - mean; });
    double sq_sum = std::inner_product(diff.begin(), diff.end(), diff.begin(), 0.0);
    double stdev = std::sqrt(sq_sum / v.size());
    std::vector<double> results{mean, sq_sum, stdev, var};
    return results;
}

/**
 * @callgraph
 * @callergraph
 * @brief Display Statistics Table
 *
 * Routine to display the statistics collected for the TCP Conversations in a tabular format. The library Tabulate
 * is used to create the tables.
 * @param tcl   Map of TCP Conversation instances
 * @param ss    Column ID for sorting.
 */
void TCPConversation::printTable(std::map<std::string, TCPConversation> &tcl, const std::string &ss,
                                 bool debug
) {
    if (debug) SPDLOG_INFO("Printing TCP Conversation Table. ss={}", ss);

    long double x(0.0L);
    long index;

    for (auto &[key, value]: tcl) {
        if (debug) SPDLOG_INFO("Key {}", key);
        index = 0;
        x = 0.0L;
        value.sendAckTimeAvg = 0.0;
        value.recvAckTimeAvg = 0.0;
        TCPConversation::seqRec seq;
        for (std::pair<const unsigned int, seqRec> sr: value.sendSequenceNumbers) {
            seq = sr.second;
            if (seq.ack) {
                x += (TCPConversation::tsConSec(seq.ackTime) - TCPConversation::tsConSec(seq.ts));
                index++;
            } else {
                value.seqUnacknowledged++;
            }
        }
        if (index > 0 && x > 0)
            value.sendAckTimeAvg = (x / index);

        index = 0;
        x = 0.0L;
        for (std::pair<const unsigned int, seqRec> sr: value.recvSequenceNumbers) {
            seq = sr.second;
            if (seq.ack) {
                x += (TCPConversation::tsConSec(seq.ackTime) - TCPConversation::tsConSec(seq.ts));
                index++;
            } else {
                value.seqUnacknowledged++;
            }
        }
        if (index > 0 && x > 0) value.recvAckTimeAvg = (x / index);
    }

    std::vector<std::string> sl{TCPConversation::sortMap(tcl, ss)};
    if (sl.empty()) sl = TCPConversation::sortMap(tcl, "id");

    using namespace tabulate;
    Table t;

    t.add_row(headers);

    for (auto const &key: sl) {

        TCPConversation value = tcl[key];

        std::string handShake{"......"};
        if (value.syn) handShake[0] = 'S';
        if (value.ack) handShake[5] = 'A';
        if (value.synAck) {
            handShake[2] = 'S';
            handShake[3] = 'A';
        }
        if (value.syn && !value.synAck && value.RST) {
            handShake[2] = 'R';
            handShake[3] = '.';
        }

        if (value.syn && value.synAck && value.RST) handShake[5] = 'R';
        enum rindex {
            mean = 0,
            sum = 1,
            std = 2,
            var = 4
        };

        std::vector<double> r = calcStats(value.iglist);
        value.igAverageTime = fmt::format("{:.5f}", r[mean]);

        r = calcStats(value.rspTime);
        value.avgResponseTime = fmt::format("{:.5f}", r[mean]);

        t.add_row({
                          key, value.sourceMac, value.destMac, handShake,
                          std::to_string(value.synSynAckTime),
                          std::to_string(value.synAckAckTime),
                          std::to_string(value.sendAckTimeAvg),
                          std::to_string(value.recvAckTimeAvg),
                          value.avgResponseTime,
                          std::to_string(value.seqUnacknowledged),
                          std::to_string(value.sendDupAck),
                          std::to_string(value.recvDupAck),
                          std::to_string(value.resetCount),
                          std::to_string(value.zeroWindow),
                          std::to_string(value.sendDataPkt),
                          std::to_string(value.recvDataPkt),
                          std::to_string(value.totalRetrans),
                          std::to_string(value.totalRetransPercentage),
                          std::to_string(value.inRetranCount),
                          std::to_string(value.outRetransCount),
                          value.igAverageTime,
                          std::to_string(value.packetCount),
                          std::to_string(value.inputPacketCount),
                          std::to_string(value.outputPacketCount),
                          std::to_string(value.byteCount),
                          std::to_string(value.inputByteCount),
                          std::to_string(value.outputByteCount),
                          std::to_string(value.packetRate),
                          std::to_string(value.inputPacketRate),
                          std::to_string(value.outputPacketRate),
                          std::to_string(value.recvWindowUpdates),
                          std::to_string(value.sendWindowUpdates),
                          std::to_string(value.duration)});
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
                .font_color(Color::yellow)
                .font_style({FontStyle::bold});

    }

    t.print(std::cout);
}

/**
 * @callgraph
 * @callergraph
 * @brief Update statistics counters
 *
 * Routine to update the statistic counters for a given TCP conversation (socket).
 * @param pkt                   Parsed packet
 * @param key                   TCP Conversation Key
 * @param ipHdr                 IP Header Layer
 * @param tcpHdr                TCP Header Layer
 * @param tcpCurrentAddress     TCP Socket address from packet
 */
void TCPConversation::updateCounters(const pcpp::Packet &pkt, pcpp::Layer &ipHdr, pcpp::Layer &tcpLayer,
                                     const std::string &tcpCurrentAddress, int pc) {
    std::vector<std::string> v{packetFormat(pkt)};
    /**
     * ## Process Overview
     *
     * ### Use raw pcpp packet to get timestamp of the packet.
     * ### Set conversation start and stop time. <b>Note: start time will be set to timestamp of first packet</b>
     * ### Calculate and set duration
     */
    if (debug) SPDLOG_INFO("Starting packet {}", pc);
    auto *tcplayer = pkt.getLayerOfType<pcpp::TcpLayer>();
    auto *ipLayer = pkt.getLayerOfType<pcpp::IPv4Layer>();
    pcpp::tcphdr *tcpHdr = tcplayer->getTcpHeader();
    pcpp::RawPacket *rawPkt = pkt.getRawPacketReadOnly();
    timespec ts = rawPkt->getPacketTimeStamp();

    std::string socket = ipLayer->getSrcIPAddress().toString() + ":" +
                         std::to_string(tcpHdr->portSrc) + "<->" +
                         ipLayer->getDstIPAddress().toString() + ":" +
                         std::to_string(tcpHdr->portDst);
    if (debug) SPDLOG_INFO("Packet {} Socket {}", pc, socket);

    if (!firstTS) {
        firstTimeStamp = ts;
        firstTS = true;
    }
    duration = tsConSec(ts) - tsConSec(firstTimeStamp);

    /**
     * ### Construct handshake flags
     */
    if (!syn) {
        if ((tcpHdr->synFlag) != 0) {
            syn = true;
            synTime = ts;
        }
    }
    if (syn && synAck && !ack) {
        if ((tcpHdr->ackFlag) != 0) {
            ack = true;
            ackTime = ts;
            synAckAckTime = tsConSec(ackTime) - tsConSec(synAckTime);
        }
        RST = (tcpHdr->rstFlag) != 0;
    }
    if (syn && !synAck) {
        synAck = ((tcpHdr->synFlag) != 0 && (tcpHdr->ackFlag) != 0);
        if (synAck) {
            synAckTime = ts;
            synSynAckTime = tsConSec(synAckTime) - tsConSec(synTime);

            if (debug)
                SPDLOG_INFO("socket {} synAck {}  synAckTime {}  synSynAckTime {}",
                            socket, synAck, synAckTime.tv_nsec, synSynAckTime);
        }
        RST = (tcpHdr->rstFlag) != 0;
    }

    // check for zero window
    if (tcpHdr->synFlag == 0 && tcpHdr->rstFlag == 0 && pcpp::netToHost16(tcpHdr->windowSize) == 0) {
        zeroWindow++;
    }

    /**
     * ### Set packet Rate and packet counts
     */
    packetRate = (duration == 0.0) ? 0.0 : packetCount / duration;
    packetCount++;
    if (tcpHdr->rstFlag) resetCount++;

    /**
     * ###  Packet and Byte Counts
     */
    int payloadLength{static_cast<int>(tcpLayer.getLayerPayloadSize())};
    byteCount += payloadLength;

    if (tcpCurrentAddress == firstSpeaker) {
        outputPacketCount++;
        if (payloadLength > 0) {
            sendDataPkt++;
            if (dataPacketRecv) {
                firstDataPacketSent = false;
                rspTime.push_back(currentRspTime);
                iglist.push_back((tsConSec(ts) - tsConSec(igts)));
            }
            if (!firstDataPacketSent) {
                sendTime = ts;
                dataPacketRecv = false;
                firstDataPacketSent = true;
                if (debug)
                    SPDLOG_INFO("Data Packet Send {}  socket {} ns {}  pl {}", pc, socket, ts.tv_nsec, payloadLength);
            }
        }
        outputByteCount += payloadLength;
        outputPacketRate = (duration == 0) ? 0.0 : outputPacketCount / duration;

    } else {
        inputPacketCount++;
        if (payloadLength > 0) {
            recvDataPkt++;
            if (firstDataPacketSent) {
                if (debug)
                    SPDLOG_INFO("Data Recv: {}  socket {} rspTime {}  pl {} dpr {}",
                                pc, socket, (ts.tv_nsec - sendTime.tv_nsec), payloadLength, dataPacketRecv);
                currentRspTime = tsConSec(ts) - tsConSec(sendTime);
                dataPacketRecv = true;
                igts = ts;
            }
        }
        inputByteCount += payloadLength;
        inputPacketRate = (duration == 0) ? 0.0 : inputPacketCount / duration;
    }
}


/**
 * @callgraph
 * @callergraph
 * @param vint      - Vector of pairs in the format <string,int>
 * @return          - string of HostPair keys in sorted order
 * @brief Sort Integers
 * sort a list of pairs by second element, in this case int
 */
std::vector<std::string> TCPConversation::sortInt(std::vector<std::pair<std::string, int >> vint) {
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
std::vector<std::string> TCPConversation::sortDbl(std::vector<std::pair<std::string, double >> v) {
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
std::vector<std::string> TCPConversation::sortStr(std::vector<std::pair<std::string, std::string >> v) {
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
 * @param tcl       TCP Conversation  map
 * @param colId     Column to sort
 * @return          Vector of TCPConversation keys in sorted order
 *
 * Routine will take a map of TCPConversation instances and sort it in descending order based on the column ID. The returned
 * string will be used index the TCP Conversation list to print the list in sorted order.
 */
std::vector<std::string>
TCPConversation::sortMap(const std::map<std::string, TCPConversation> &tcl, const std::string &colId) {
    std::vector<std::pair<std::string, int >> vint{};
    std::vector<std::pair<std::string, double >> vdouble{};
    std::vector<std::pair<std::string, std::string >> vstring{};

    for (auto const &[key, value]: tcl) {
        if (colId == "id" || colId.starts_with("tcpc")) vstring.emplace_back(key, key);
        if (colId == "sm" || colId.starts_with("srcm")) vstring.emplace_back(key, value.sourceMac);
        if (colId == "dm" || colId.starts_with("dest")) vstring.emplace_back(key, value.destMac);

        if (colId == "pc" || colId.starts_with("packetc")) vint.emplace_back(key, value.packetCount);
        if (colId == "ipc" || colId.starts_with("inputpacketc")) vint.emplace_back(key, value.inputPacketCount);
        if (colId == "opc" || colId.starts_with("outputpacketc")) vint.emplace_back(key, value.outputPacketCount);
        if (colId == "bc" || colId.starts_with("bytec")) vint.emplace_back(key, value.byteCount);
        if (colId == "ibc" || colId.starts_with("inbytec")) vint.emplace_back(key, value.inputByteCount);
        if (colId == "obc" || colId.starts_with("outbytec")) vint.emplace_back(key, value.outputByteCount);
        if (colId == "rst" || colId.starts_with("reset")) vint.emplace_back(key, value.resetCount);
        if (colId == "ret" || colId.starts_with("retrans")) vint.emplace_back(key, value.totalRetrans);
        if (colId == "irt" || colId.starts_with("inretrans")) vint.emplace_back(key, value.inRetranCount);
        if (colId == "ort" || colId.starts_with("outretrans")) vint.emplace_back(key, value.outRetransCount);
        if (colId == "sak" || colId.starts_with("senddup")) vint.emplace_back(key, value.sendDupAck);
        if (colId == "rak" || colId.starts_with("recvdup")) vint.emplace_back(key, value.recvDupAck);
        if (colId.starts_with("unackseq")) vint.emplace_back(key, value.seqUnacknowledged);
        if (colId.starts_with("zero")) vint.emplace_back(key, value.zeroWindow);
        if (colId.starts_with("senddatap")) vint.emplace_back(key, value.sendDataPkt);
        if (colId.starts_with("recvdatap")) vint.emplace_back(key, value.recvDataPkt);
        if (colId.starts_with("recvwindow")) vint.emplace_back(key, value.recvWindowUpdates);
        if (colId.starts_with("sendwindow")) vint.emplace_back(key, value.sendWindowUpdates);

        if (colId == "pr" || colId.starts_with("packetrate")) vdouble.emplace_back(key, value.packetRate);
        if (colId == "pir" || colId.starts_with("recvpacketr")) vdouble.emplace_back(key, value.inputPacketRate);
        if (colId == "opr" || colId.starts_with("sendpacketr")) vdouble.emplace_back(key, value.outputPacketRate);
        if (colId == "dur" || colId.starts_with("dur")) vdouble.emplace_back(key, value.duration);
        if (colId == "cts" || colId.starts_with("cts")) vdouble.emplace_back(key, value.synSynAckTime);
        if (colId.starts_with("ctd")) vdouble.emplace_back(key, value.synAckAckTime);
        if (colId == "sat" || colId.starts_with("sendackt")) vdouble.emplace_back(key, value.sendAckTimeAvg);
        if (colId == "rat" || colId.starts_with("recvact")) vdouble.emplace_back(key, value.recvAckTimeAvg);
        if (colId == "art" || colId.starts_with("avgrsp")) vstring.emplace_back(key, value.avgResponseTime);
        if (colId.starts_with("intergaptime")) vstring.emplace_back(key, value.igAverageTime);

    }
    std::vector<std::string> r{};

    // Only one of the vector will have pairs. Figure out which one and sort it
    if (!vint.empty()) return sortInt(vint);
    if (!vdouble.empty()) return sortDbl(vdouble);
    if (!vstring.empty()) return sortStr(vstring);

    return r;
}

/**
 * @callgraph
 * @callergraph
 * processIdnum will track Idnum values and use them to count retransmissions. This is done because idnum is unique for each IP packet
 * being sent.
 * @param idnum     Ip Header Ip Id field
 * @return          Return true if this Id has been seen already, false otherwise.
 *
 * enhancement: Need a way to tell if id has wrapped. This routine will only be accurate if the id has not wrapped
 */
bool TCPConversation::processIdNum(uint16_t idnum, const pcpp::Packet &pkt) {
    if (debug) SPDLOG_INFO("IDNUM {}", idnum);
    if (idnum == 0) return false;
    auto itr = idnumList.find(idnum);

    // check if the packet has data. We only care about data packets for retransmission
    uint dl = pkt.getLayerOfType(pcpp::IPv4)->getDataLen();
    if (dl == 0) return false;

    // check to see if idnum is in the map.
    if (itr == idnumList.end()) {
        idnumList[idnum] = true;
        return false;
    } else {
        return true;
    }
}

/**
 * @callgraph
 * @callergraph
 * @param pkt           Parsed packet.
 * @return
 *
 *  * Track sequence numbers and use to check for retransmission
 */
bool TCPConversation::processSequenceNumber(pcpp::Packet &pkt) {
    if (debug) SPDLOG_INFO("Starting");
    // Get TCPHeader and Sequence Number
    auto *tcpLayer = pkt.getLayerOfType<pcpp::TcpLayer>();
    pcpp::tcphdr *tcph = tcpLayer->getTcpHeader();
    if (debug) SPDLOG_INFO("Sequence Number {}", pcpp::netToHost32(tcph->sequenceNumber));

    // Get socket information for the current packet. Will use to determine direction,
    // send or receive
    std::string tcpCurrentAddress = getTcpConversationAddress(pkt, debug);

    pcpp::RawPacket *rawPkt = pkt.getRawPacketReadOnly();
    timespec t = rawPkt->getPacketTimeStamp();
    if (tcpLayer->getLayerPayloadSize() > 0) {
        seqRec sr{};
        sr.ts = t;
        // Determine send or receive direction, set sequence map and check for retransmission
        if (tcpCurrentAddress == firstSpeaker) {  //Send Direction
            auto itr = sendSequenceNumbers.find(pcpp::netToHost32(tcph->sequenceNumber));
            if (itr == sendSequenceNumbers.end()) {
                sr.ack = false;
                sendSequenceNumbers[pcpp::netToHost32(tcph->sequenceNumber)] = sr;
                return false;
            } else {
                return true;
            }
        } else {        // Receive Direction
            auto itr = recvSequenceNumbers.find(pcpp::netToHost32(tcph->sequenceNumber));
            if (itr == recvSequenceNumbers.end()) {
                sr.ack = false;
                recvSequenceNumbers[pcpp::netToHost32(tcph->sequenceNumber)] = sr;
                return false;
            } else {
                return true;
            }
        }
    }
    return false;
}

/**
 * @callergraph
 * @callgraph
 * @param p         Parsed Packet
 *
 *  * Function will update retransmission counters for duplicate IP Id.
 */
void TCPConversation::checkIpId(pcpp::Packet &p) {
    if (debug) SPDLOG_INFO("Starting");
    auto *ipLayer = p.getLayerOfType<pcpp::IPv4Layer>();
    uint16_t idnum{pcpp::hostToNet16(ipLayer->getIPv4Header()->ipId)};
    std::string key = getTcpConversationAddress(p, debug);
    if (processIdNum(idnum, const_cast<pcpp::Packet &>(p))) {
        totalRetrans++;
        totalRetransPercentage = double(totalRetrans) / double(packetCount);
        if (key == getFirstSpeaker()) {
            outRetransCount++;
            sendRetranPercentage = double(outRetransCount) / double(packetCount);
        } else {
            inRetranCount++;
            recvRetranPercentage = double(inRetranCount) / double(packetCount);
        }
    }
}


/**
 * @callgraph
 * @callergraph
 * \brief Get TCP Conversation Key
 * Routine to create a key for TCP Conversation Stats Table ( tcpConversationList ). It builds the key by first
 * calling getIpPair to get the hostPair key. Lastly is will use the pcpp::tcphdr to get the source and destination
 * port and append to the hostPair key to construct the tcpKey.
 * @param pkt       Parsed packet.
 * @return
 */
std::vector<std::string> TCPConversation::getTcpConversation(const pcpp::Packet &pkt, bool debug) {
    std::vector<std::string> tcpKey{"", ""};

    pcpp::Layer *ipv4 = pkt.getLayerOfType(pcpp::IPv4);
    auto *ipv4hdr = dynamic_cast<pcpp::IPv4Layer *>(ipv4);
    std::string src = ipv4hdr->getSrcIPAddress().toString();
    std::string dst = ipv4hdr->getDstIPAddress().toString();

    if (pcpp::Layer *tcp = pkt.getLayerOfType(pcpp::TCP); tcp != nullptr) {
        auto *tcphdrlayer = dynamic_cast<pcpp::TcpLayer *>(tcp);
        pcpp::tcphdr *tcpHdr = tcphdrlayer->getTcpHeader();
        std::string sp = std::to_string(pcpp::hostToNet16(tcpHdr->portSrc));
        std::string dp = std::to_string(pcpp::hostToNet16(tcpHdr->portDst));
        std::string s1 = src + ":" + sp + "-" + dst + ":" + dp;
        std::string s2 = dst + ":" + dp + "-" + src + ":" + sp;
        tcpKey = {s1, s2};
    }
    if (debug) SPDLOG_INFO("tcp key {} {}", tcpKey[0], tcpKey[1]);
    return tcpKey;
}


/**
 * @callgraph
 * @callergraph
 * \brief Get TCP Socket
 * Function to construct a string with the TCP Socket information in the format:
 *
 * Source IP<-->Destination IP.Source Port.Destination Port <br>
 *      Example: \arg
 *          192.168.42.4<-->34.125.111.170.54487.47873
 *
 * @param pkt       Parsed Packet
 * @return
 */
std::string TCPConversation::getTcpConversationAddress(const pcpp::Packet &pkt, bool debug) {
    std::string tcpConversation;;

    if (pcpp::Layer *tcp = pkt.getLayerOfType(pcpp::TCP); tcp != nullptr) {
        pcpp::Layer *ipv4 = pkt.getLayerOfType(pcpp::IPv4);
        auto *ipv4hdr = dynamic_cast<pcpp::IPv4Layer *>(ipv4);
        std::string src = ipv4hdr->getSrcIPAddress().toString();
        std::string dst = ipv4hdr->getDstIPAddress().toString();
        auto *tcphdrlayer = dynamic_cast<pcpp::TcpLayer *>(tcp);
        pcpp::tcphdr *tcpHdr = tcphdrlayer->getTcpHeader();
        std::string sp = std::to_string(pcpp::hostToNet16(tcpHdr->portSrc));
        std::string dp = std::to_string(pcpp::hostToNet16(tcpHdr->portDst));
        tcpConversation = src + ":" + sp + "-" + dst + ":" + dp;
    }
    if (debug) SPDLOG_INFO("Socket {}", tcpConversation);
    return tcpConversation;
}

/**
 * @callergraph
 * @callgraph
 */
bool checkAckList(uint32_t ackNumber, const std::map<uint32_t, uint16_t> &al) {
    for (auto &[an, ws]: al) {
        if (ackNumber == an) return true;
    }
    return false;
}

/**
 * @callgraph
 * @callergraph
 * @param p         Parsed Packet
 *
 * Function to process Ack packets. Using the Ack number cycle over the proper sequence number map and
 * mark all instances that the Ack packet. Note: ignoring data packet ACKs.
 *
 */
void TCPConversation::processAck(const pcpp::Packet &p, int pc) {
    std::vector<std::string> v = packetFormat(p);
    if (debug) SPDLOG_INFO("");
    if (pcpp::Layer *tcp = p.getLayerOfType(pcpp::TCP); tcp != nullptr) {
        auto *tcphdrlayer = dynamic_cast<pcpp::TcpLayer *>(tcp);
        pcpp::tcphdr *tcpHdr = tcphdrlayer->getTcpHeader();
        pcpp::RawPacket *rawPkt = p.getRawPacketReadOnly();
        timespec t = rawPkt->getPacketTimeStamp();
        if (debug) SPDLOG_INFO("ACK Number {}", pcpp::netToHost32(tcpHdr->ackNumber));

        uint16_t dl = tcp->getLayerPayloadSize();
        if (dl == 0 && tcpHdr->ackFlag == 1 && tcpHdr->synFlag == 0) {
            uint16_t ws = pcpp::netToHost16(tcpHdr->windowSize);
            if (TCPConversation::getTcpConversationAddress(p, debug) == firstSpeaker) {
                // Check for duplicate ack
                if (checkAckList(pcpp::netToHost32(tcpHdr->ackNumber), sendAckList)) {
                    if (ws > sendAckList[pcpp::netToHost32(tcpHdr->ackNumber)]) {
                        recvWindowUpdates++;
                    } else {
                        recvDupAck++;
                    }
                }
                for (auto const &[k, v]: recvSequenceNumbers) {
                    uint32_t kc = k;
                    if (pcpp::netToHost32(tcpHdr->ackNumber) >= kc) {
                        if (!recvSequenceNumbers[k].ack) {
                            recvSequenceNumbers[k].ack = true;
                            recvSequenceNumbers[k].ackTime = t;
                            sendAckList[pcpp::netToHost32(tcpHdr->ackNumber)] = pcpp::netToHost16(tcpHdr->windowSize);
                        }
                    }
                }
            } else {
                // receive
                if (checkAckList(pcpp::netToHost32(tcpHdr->ackNumber), recvAckList)) {
                    if (ws > recvAckList[pcpp::netToHost32(tcpHdr->ackNumber)]) {
                        sendWindowUpdates++;
                    } else {
                        sendDupAck++;
                    }
                }
                for (auto const &[k, v]: sendSequenceNumbers) {
                    uint32_t kc = k;
                    if (pcpp::netToHost32(tcpHdr->ackNumber) >= kc) {
                        if (!sendSequenceNumbers[k].ack) {
                            sendSequenceNumbers[k].ack = true;
                            sendSequenceNumbers[k].ackTime = t;
                            recvAckList[pcpp::netToHost32(tcpHdr->ackNumber)] = pcpp::netToHost16(tcpHdr->windowSize);
                        }
                    }
                }
            }
        }
    }
}