//
// Created by Scott Roberts on 7/27/22.
//

#include "parser.h"
#include <iostream>
#include <map>
#include "HostPair.h"

/**
 * @file
 * The parser function is used to take a packet and read its header to see which packet handler to send it too
 * @param pkt is a pcpp::Packet type and is the packet to be processed
 *
 * Layer is the base class for all protocol layers. Each protocol supported in PcapPlusPlus has a class that inherits Layer.
 * The protocol layer class expose all properties and methods relevant for viewing and editing protocol fields. For example:
 * a pointer to a structured header (e.g tcphdr, iphdr, etc.), protocol header size, payload size, compute fields that
 * can be automatically computed, print protocol data to string, etc. Each protocol instance is obviously part of a protocol
 * stack (which construct a packet). This protocol stack is represented in PcapPlusPlus in a linked list, and each layer is an
 * element in this list. That's why each layer has proprties to the next and previous layer in the protocol stack The Layer class,
 * as a base class, is abstract and the user can't create an instance of it (it has a private constructor) Each layer holds a pointer
 * to the relevant place in the packet. The layer sees all the data from this pointer forward until the end of the packet.
 *
 * Here is an example packet showing this concept:
 *
 * Packet will typically consist of the following headers:
 *
|-----|

	  |--------------------------------------------------|
	  EthLayer data

				 |---------------------------------------|
				 IPv4Layer data

							 |---------------------------|
							 TcpLayer data

										|----------------|
										PayloadLayer data
 */

/**
 * \callgraph
 * @callergraph
 * This routine is used to process the IP header and construct a HostPair instance if it is the  first packet.
 * @param pkt               - pcpp parsed packet
 * @param hostPairList      - map of HostPair instances
 * @return key              - key is a string of a source and destination IP pair: 1.1.1.1-2.2.2.2
 * - Returns a string key which is the IP host pair addresses in the format SRCIP<-->DSTIP
 *
 *  @vhdlflow
 */
std::string getIPMapInstance(const pcpp::Packet &pkt,
                             std::map<std::string,
                                     HostPair> &hostPairList,
                             bool debug
) {
    /**
     * ## Process Overview
     *
     * ### Get IP Pair Key and Return to Caller
     * - Call ipPairKey to get a vector that has two keys:
     *   - Source and destination key as seen in the first packet
     *   - Reverse key of the above.
     *   - Example:
     * 192.168.1.1-192.168.2.1
     * 192.168.2.1-192.168.1.1
     * - Using the keys search the map HostPair for a match. Return matching key.
     *  - Exception: Create a HostPair instance using the first key
     */
    std::vector<std::string> ipPairkey{HostPair::getIpPair(pkt, debug)};
    /**
    *  #### allocate instance of hostPair if key is not in Master.hostpair, otherwise select appropriate key.
    */
    std::string key{};
    std::string s1{ipPairkey[0]};
    std::string s2{ipPairkey[1]};
    std::map<std::string, HostPair>::iterator i1;
    std::map<std::string, HostPair>::iterator i2;
    i1 = hostPairList.find(s1);
    i2 = hostPairList.find(s2);
    if (debug) SPDLOG_INFO("S1 {}  s2 {}", s1, s2);
    if (i1 == hostPairList.end() && i2 == hostPairList.end()) {
        HostPair hp;
        hp.setFirstSpeaker(s1);
        hp.debug = debug;
        hostPairList.try_emplace(s1, hp);
        key = s1;
    } else
        key = (i1 == hostPairList.end()) ? s2 : s1;
    if (debug) SPDLOG_INFO("key {}", key);
    return key;
}

/**
 * \callgraph
 * @callergraph
 * ProcessTcpPacket is where most of the work is done for analyzing the TCP header. Note: in order for the SYN flag
 * too be used for the setting of first speaker this routine must be called before the processIpPacket.
 *
 * @param pkt           - This is a parsed pcap plus plus (pcpp) packet
 * @param ipHdr         - This is the pcpp IP header
 * @param tcpl          - This is the map that maintains stats data for the TCP conversations
 * @param hostPairList  - This is the hostPair table (map)
 */
int processTcpPacket(const pcpp::Packet &pkt,
                     pcpp::IPv4Layer *ipHdr,
                     std::map<std::string, TCPConversation> &tcpl,
                     std::map<std::string, HostPair> &hostPairList,
                     bool debug,
                     int pc
) {

    /**
     * ## Process Overview
     *
    *
    * ### Get TCP Layer and Header
    * - Return 1 to caller if this packet does not have a TCP Header
    */

    auto *tcplayer = pkt.getLayerOfType<pcpp::TcpLayer>();
    if (tcplayer == nullptr) {
        if (debug) SPDLOG_INFO("Packet does not have TCP layer");
        return 1;
    }
    pcpp::tcphdr *tcpHdr = tcplayer->getTcpHeader();

    if (tcplayer->getProtocol() == pcpp::TCP) {
        /**
         * ###  Construct a TCPConversation instance if this is the first packet. Set key to the conversation pair.
         *
         * - Call  Master::getTcpConversation(pkt) to get vector of TCP Conversation keys
         *     - Example:
         *     -# 192.168.1.1-192.168.2.1.5000.6000
         *     -# 192.168.2.1-192.168.1.1.6000.5000
         * - Search map TCP Conversations using the key vector.
         */

        std::vector<std::string> tcpKey = TCPConversation::getTcpConversation(pkt, debug);
        std::string key{};
        std::string s1{tcpKey[0]};
        std::string s2{tcpKey[1]};
        if (debug) SPDLOG_INFO("S1 {}  s2 {}", s1, s2);

        std::map<std::string, TCPConversation>::iterator i1;
        std::map<std::string, TCPConversation>::iterator i2;
        i1 = tcpl.find(s1);
        i2 = tcpl.find(s2);
        /**
        *    -  Set firstSpeaker to the first packet or if the SYN bit is set. <B>Note: hostPair first speaker will
        * also be set here</B>
        */
        if (i1 == tcpl.end() && i2 == tcpl.end()) {
            /**
            *    - Construct an IP HostPair entry in the HostPairList map and set the first speaker. This will make sure
            * the firstSpeaker in each class instance is the same IP pair
            */
            std::string ipKey{getIPMapInstance(pkt, hostPairList, debug)};

            /**
             * - Construct TCP Conversation Map Instance
             */
            TCPConversation tcpc;

            /**
            * set source and destination Mac Address
            */
            tcpc.setMacAdress(getMacAddress(const_cast<pcpp::Packet &>(pkt), debug));

            /**
            * - firstSpeaker will be set based on the following:
            *    -# SYN Packet - will use s1
            *    -#  SYN Ack - will use s2 (reverse key)
            *    -#  First data packet seen
            * - Add TCP Conversation instance to the TCP Conversation Map
            */
            if (tcpHdr->synFlag == 1 && tcpHdr->ackFlag == 1) {
                s1 = s2;
            }
            tcpc.setFirstSpeaker(s1);
            tcpc.debug = debug;
            tcpl.try_emplace(s1, tcpc);
            key = s1;
        } else
            key = (i1 == tcpl.end()) ? s2 : s1;
        if (debug) SPDLOG_INFO("Key {}", key);
        /**
         * Check for retransmissions
         */
        tcpl[key].checkIpId(const_cast<pcpp::Packet &>(pkt));
        tcpl[key].processSequenceNumber(const_cast<pcpp::Packet &>(pkt));
        if (tcpHdr->ackFlag == 1) tcpl[key].processAck((const_cast<pcpp::Packet &>(pkt)), pc);

        // Check for retransmissions of sequence numbers.

        /**
         * ### USe key from previous step to update counters for the TCP Conversation
         */
        std::string tcpCurrentAddress = tcpl[key].getTcpConversationAddress(pkt, debug);
        if (debug) SPDLOG_INFO("TCP Socket: {}", tcpCurrentAddress);
        tcpl[key].updateCounters(pkt, *ipHdr, *tcplayer, tcpCurrentAddress, pc);

    } // end if tcp
    return 0;
}

/**
 * Function to update counters for an IP packet. It will also call processTCPPacket to check for and handle
 * the TCP header.
 * @callgraph
 * @callergraph
 * @param master            Master Class
 * @param pkt               Parsed PCPP Packet
 * @param ipHdr             PCPP Layer for the IP Header
 * @param hostPairList      Map of HostPair instances
 * @param tcpl              Map of TCPConversation instances
 */
void processIpPacket(const pcpp::Packet &pkt,
                     pcpp::Layer *ipHdr,
                     std::map<std::string, HostPair> &hostPairList,
                     std::map<std::string,
                             TCPConversation> &tcpl,
                     int pc,
                     bool debug
) {
    std::vector<std::string> ipPairkey{HostPair::getIpPair(pkt, debug)};
    /**
     * ## Process Overview
     *
     * ### Check to see if this is a TCP packet, if so go process it
     *
     * ### Process counters for the IP packet and update HostPair instance
     */
    auto *ipv4 = pkt.getLayerOfType<pcpp::IPv4Layer>();
    processTcpPacket(pkt, ipv4, tcpl, hostPairList, debug, pc);

    std::string key = getIPMapInstance(pkt, hostPairList, debug);
    if (debug) SPDLOG_INFO("Key {}", key);

    std::string currentPacketIpAddress = HostPair::getIpAddress(pkt, debug);
    if (debug) SPDLOG_INFO("Current IP Address {}", currentPacketIpAddress);

    hostPairList[key].updateCounters(pkt, *ipHdr, currentPacketIpAddress);


}

/**
 * @callergraph
 * @callgraph
 * @param pkt
 * Process an Ethernet header and set up an ethernetStats instance
 */
void processEthernet(pcpp::Packet &pkt, std::map<std::string, EthernetStats> &ethernetStatsList, bool debug) {
    auto *ethLayer = dynamic_cast<pcpp::EthLayer *>(pkt.getLayerOfType(pcpp::Ethernet));
    std::string sourceMac = ethLayer->getSourceMac().toString();
    std::string destMac = ethLayer->getDestMac().toString();
    std::string key = sourceMac + "<->" + destMac;
    std::string rkey = destMac + "<->" + sourceMac;
    if (debug) SPDLOG_INFO("key {}  Rkey {}", key, rkey);

    std::string s1;

    std::map<std::string, EthernetStats>::iterator i1;
    std::map<std::string, EthernetStats>::iterator i2;
    i1 = ethernetStatsList.find(key);
    i2 = ethernetStatsList.find(rkey);
    if (i1 == ethernetStatsList.end() && i2 == ethernetStatsList.end()) {
        // no entry in list. Create an EtherStats instance and place in list
        EthernetStats es;
        es.setFs(key);
        es.debug = debug;
        ethernetStatsList.try_emplace(key, es);
        s1 = key;
    } else {
        s1 = (i1 == ethernetStatsList.end()) ? rkey : key;
    }

    if (debug) SPDLOG_INFO("S1 {}", s1);
    ethernetStatsList[s1].updateCounters(pkt);
}

/**
 * Routine to get mac addresses of a packet
 * @callergraph
 * @callgraph
 * @param pkt       Parsed Packet
 * @return
 */
std::vector<std::string> getMacAddress(pcpp::Packet &pkt, bool debug) {
    if (debug) SPDLOG_INFO("");
    std::vector<std::string> macAddresses{};
    auto *ethlayer = pkt.getLayerOfType<pcpp::EthLayer>();
    std::string srcMac{ethlayer->getSourceMac().toString()};
    macAddresses.emplace_back(srcMac);
    std::string dstMac{ethlayer->getDestMac().toString()};
    macAddresses.emplace_back(dstMac);
    return macAddresses;
}

/**
 * Routine to get mac addresses of a packet
 * @callergraph
 * @callgraph
 * @param pkt       Parsed Packet
 * @param p         protocol type of first layer of packet
 */
void
processProtocol(const pcpp::Packet &pkt, pcpp::ProtocolType p, std::map<std::string, ProtocolStats> &pl, bool debug) {
    std::map<uint16_t, std::string> etherTypeTable{
            {0x0806, "ARP"},
            {0x0800, "IpV4"},
            {0x8100, "Vlan"},
            {0x86dd, "IpV6"},
            {0x8035, "RevArp"},
    };
    std::map<uint8_t, std::string> ipProtocolTable{
            {pcpp::PACKETPP_IPPROTO_TCP,      "TCP"},
            {pcpp::PACKETPP_IPPROTO_EGP,      "EGP"},
            {pcpp::PACKETPP_IPPROTO_ICMP,     "ICMP"},
            {pcpp::PACKETPP_IPPROTO_ICMPV6,   "ICMPV6"},
            {pcpp::PACKETPP_IPPROTO_FRAGMENT, "FRAGMENT"},
            {pcpp::PACKETPP_IPPROTO_UDP,      "UDP"},
            {pcpp::PACKETPP_IPPROTO_GRE,      "GRE"},
    };
    if (debug) SPDLOG_INFO("P {}", p);
    if (p == pcpp::Ethernet) {
        auto *ethLayer = dynamic_cast<pcpp::EthLayer *>(pkt.getLayerOfType(pcpp::Ethernet));
        if (ethLayer != nullptr) {
            pcpp::ether_header *eh = ethLayer->getEthHeader();
            uint16_t et = pcpp::hostToNet16(eh->etherType);
            std::string ets{};
            try {
                ets = "(" + etherTypeTable[et] + ")";
            }
            catch (...) {
                if (debug) SPDLOG_INFO("Unknown EtherType: {}", et);
                ets = "";
            }
            std::string s = fmt::format("ethType:{:#04X}{}", et, ets);
            if (debug) SPDLOG_INFO("S {}", s);
            pl[s].debug = debug;
            pl[s].updateCounters(pkt);
        }

        auto *ip = dynamic_cast<pcpp::IPv4Layer *>(pkt.getLayerOfType(pcpp::IPv4));
        if (ip != nullptr) {
            pcpp::iphdr *iph = ip->getIPv4Header();
            std::string pts{};
            try {
                pts = "(" + ipProtocolTable[(iph->protocol)] + ")";
            }
            catch (...) {
                if (debug) SPDLOG_INFO("Unknown IP  Protocol {}", iph->protocol);
                pts = "";
            }
            std::string s = fmt::format("IpProt:{}{}", iph->protocol, pts);
            if (debug) SPDLOG_INFO("S {}", s);
            pl[s].debug = debug;
            pl[s].updateCounters(pkt);
        }
    }

}

/**
 * Parser is used to control the processing of pcapPlusPlus Parsed Packet
 * @callgraph
 * @callergraph
 * @param pkt                   Parsed PCPP Packet
 * @param hostPairList          Map of HostPair instances
 * @param tcpConversationList   Map of TCPConversation instances
 */
void parser(pcpp::Packet &pkt, std::map<std::string, HostPair> &hostPairList,
            std::map<std::string, TCPConversation> &tcpConversationList,
            std::map<std::string, EthernetStats> &ethernetStatsList,
            std::map<std::string, ProtocolStats> &pl,
            int pc, bool debug) {

    pcpp::Layer *hdr{pkt.getFirstLayer()};
    pcpp::ProtocolType protocol{hdr->getProtocol()};
    processProtocol(pkt, protocol, pl, debug);
    if (protocol == pcpp::Ethernet) {
        if (debug) SPDLOG_INFO("Protocol {}", protocol);
        processEthernet(pkt, ethernetStatsList, debug);
        pcpp::Layer *ipHdr{hdr->getNextLayer()};
        switch (ipHdr->getProtocol()) {

            case pcpp::IPv4: {
                processIpPacket(pkt, ipHdr, hostPairList, tcpConversationList, pc, debug);
                break;
            }

            case pcpp::VLAN: {
                break;
            }

            default: {
                if (debug) SPDLOG_INFO("Protocol {} is not handled", (ipHdr->getProtocol()));
                break;
            }
        } //endSwitch
    }// endif
}//endFunc

