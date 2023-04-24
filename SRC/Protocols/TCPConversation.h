//
// Created by Scott Roberts on 7/31/22.
//
/**
 * @file
 * @brief TCP Conversation Class
 * @class
 */

#ifndef MACPCAP_TCPCONVERSATION_H
#define MACPCAP_TCPCONVERSATION_H

#include <sys/time.h>
#include <vector>
#include <map>
#include <IPv4Layer.h>
#include <Packet.h>
#include <Layer.h>
#include <IPv4Layer.h>
#include <TcpLayer.h>
#include <fmt/format.h>
#include <spdlog/spdlog.h>
#include <EthLayer.h>
#include "HostPair.h"
#include "SystemUtils.h"
#include "../include/tabulate.hpp"
#include <regex>
#include <numeric>
#include "../include/csvfile.h"


class TCPConversation {
public:
    bool debug{false};

    class seqRec {
    public:
        bool ack{false};
        timespec ts{};
        timespec ackTime{};
    };

    /**
     * \callgraph
     * @callergraph
     * @param s
     */
    void setFirstSpeaker(std::string &s) {
        firstSpeaker = s;
    }

    /**
     * @callgraph
     * @callergraph
     * @return
     */
    std::string getFirstSpeaker() {
        return firstSpeaker;
    }

    /**
     * Set Mac Addresses
     * @callergraph
     * @callgraph
     */
    void setMacAdress(std::vector<std::string> m) {
        sourceMac = m[0];
        destMac = m[1];
    }


    void updateCounters(const pcpp::Packet &pkt, pcpp::Layer &ipHdr, pcpp::Layer &tcpLayer,
                        const std::string &tcpCurrentAddress, int pc);

    static void printTable(std::map<std::string, TCPConversation> &tcl, const std::string &ss,
                           bool debug
    );

    static void writeCsvTable(std::map<std::string, TCPConversation> &tcl, const std::string &ss,
                              bool debug
    );

    static std::vector<std::string>
    sortMap(const std::map<std::string, TCPConversation> &tcl, const std::string &colId);

    static std::vector<std::string> sortInt(std::vector<std::pair<std::string, int >> vint);

    static std::vector<std::string> sortDbl(std::vector<std::pair<std::string, double >> v);

    static std::vector<std::string> sortStr(std::vector<std::pair<std::string, std::string >> v);

    bool processIdNum(uint16_t idnum, const pcpp::Packet &pkt);

    bool processSequenceNumber(pcpp::Packet &pkt);

    void checkIpId(pcpp::Packet &p);

    static std::vector<std::string> getTcpConversation(const pcpp::Packet &pkt, bool debug);

    static std::string getTcpConversationAddress(const pcpp::Packet &pkt, bool debug);

    void processAck(const pcpp::Packet &p, int pc);

    static long double tsConSec(timespec ts) {
        return ((ts.tv_sec) * 1e9 + (ts.tv_nsec)) / 1e9L;
    }


private:
    std::string sourceMac;
    std::string destMac;
    std::string firstSpeaker;
    bool firstTS{false};
    timespec firstTimeStamp{};
    long double duration{0};
    int packetCount{0};
    int inputPacketCount{0};
    int outputPacketCount{0};
    int sendDataPkt{0};
    int recvDataPkt{0};
    int byteCount{0};
    int inputByteCount{0};
    int outputByteCount{0};
    double packetRate{0.0};
    double inputPacketRate{0.0};
    double outputPacketRate{0.0};
    int resetCount{0};

    // The following flags are used to track conversation set up state

    bool syn{false};
    timespec synTime{0};
    bool synAck{false};
    timespec synAckTime{0};
    bool ack{false};
    timespec ackTime{0};
    bool RST{false};
    long double synSynAckTime{0.0L};
    long double synAckAckTime{0.0L};

    // Response Time
    bool firstDataPacketSent{false};
    bool dataPacketRecv{false};
    long double currentRspTime{0.0L};
    std::vector<double> rspTime{};
    timespec sendTime{};
    std::string avgResponseTime{};
    //long double stdResponseTime{0};
    //long double maxResponseTime{0};

    // Inter-gap time - This is the time between a response to a request and the next request
    timespec igts;
    std::vector<double> iglist;
    std::string igAverageTime{};
    // long double igMaxTime{0};
    // long double  igStdTime{0};

    // Sequence Number Analysis
    std::map<uint32_t, seqRec> sendSequenceNumbers;
    std::map<uint32_t, seqRec> recvSequenceNumbers;
    long double sendAckTimeAvg{0.0};
    long double recvAckTimeAvg{0.0};
    std::map<uint16_t, bool> idnumList;
    int seqUnacknowledged{0};

    // Retransmission Stats
    int totalRetrans{0};
    int inRetranCount{0};
    int outRetransCount{0};
    double totalRetransPercentage{0.0};
    double recvRetranPercentage{0.0};
    double sendRetranPercentage{0.0};

    int recvDupAck{0};
    int sendDupAck{0};

    std::map<uint32_t, uint16_t> sendAckList;
    std::map<uint32_t, uint16_t> recvAckList;
    int sendWindowUpdates{0};
    int recvWindowUpdates{0};
    int zeroWindow{0};
};

#endif //MACPCAP_TCPCONVERSATION_H
