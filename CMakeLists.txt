#
# Cmake file for the application macpcap
# Author: Scott Roberts
# Date: 07/25/2022
#

#
# Global Definitions
#

cmake_minimum_required(VERSION 3.23)
set(CMAKE_CXX_STANDARD 23)

project(macpcap VERSION 1.0.0.0)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/" /Users/scottroberts/CLionProjects/module)

include(cmake/include/GetDateTime.cmake)
include(cmake/include/misc.cmake)
include_directories(/usr/local/include/pcapplusplus)
include_directories(/usr/local/opt/libpcap/include)
include_directories(/usr/local/include/concurrencpp-0.1.4 /usr/local/Cellar/boost/1.79.0_1/include/)

getdatetime()  # sets dt
message("\nStarting at ${dt} - Version ${PROJECT_VERSION}")
systeminfo()
checkipo() # will set IPO True if supported

#
# Target for macpcap
#
message("\nTarget: macpcap")
add_executable(macpcap SRC/main.cpp SRC/Protocols/parser.cpp SRC/Protocols/HostPair.h SRC/Protocols/TCPConversation.h
        SRC/Protocols/HostPair.cpp SRC/Protocols/HostPair.h SRC/Protocols/TCPConversation.cpp myColor.h SRC/Protocols/EthernetStats.cpp SRC/Protocols/EthernetStats.h SRC/Protocols/ProtocolStats.cpp SRC/Protocols/ProtocolStats.h)

message("macpcap: FMT package")
find_package(fmt)
target_link_libraries(macpcap fmt::fmt)

message("macpcap: concurrencpp library")
target_link_libraries(macpcap /usr/local/lib/libconcurrencpp.a)

message("macpcap: Loading PCAP")
find_package(PCAP)
target_link_libraries(${PROJECT_NAME} ${PCAP_LIBRARY})

message("macpcap: Loading PCAP++")
find_package(PcapPlusPlus REQUIRED)
target_link_libraries(${PROJECT_NAME} ${PcapPlusPlus_LIBRARIES})

find_package(glog)
target_link_libraries(${PROJECT_NAME} glog::glog)

FIND_PACKAGE(Boost 1.79 COMPONENTS program_options REQUIRED)
INCLUDE_DIRECTORIES(${Boost_INCLUDE_DIR})

TARGET_LINK_LIBRARIES(${PROJECT_NAME} ${Boost_LIBRARIES})
#
# End oc CMake file
#
getdatetime()
message("\nStopping at ${dt}")

