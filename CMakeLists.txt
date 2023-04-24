#
# Cmake file for the application macpcap
# Author: Scott Roberts
# Date: 07/25/2022
#

#
# Global Definitions
#
set(CMAKE_OSX_SYSROOT /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX13.sdk)
cmake_minimum_required(VERSION 3.23)
set(CMAKE_CXX_STANDARD 23)

project(macpcap VERSION 1.1.0.0)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/" /Users/scottroberts/CLionProjects/module)

include(CheckIncludeFileCXX)

check_include_file_cxx(any HAS_ANY)
check_include_file_cxx(string_view HAS_STRING_VIEW)
check_include_file_cxx(coroutine HAS_COROUTINE)
if (NOT "${CMAKE_CXX_STANDARD}" STREQUAL "")
    # Do nothing
elseif (HAS_ANY AND HAS_STRING_VIEW AND HAS_COROUTINE)
    set(CMAKE_CXX_STANDARD 20)
elseif (HAS_ANY AND HAS_STRING_VIEW)
    set(CMAKE_CXX_STANDARD 17)
else ()
    set(CMAKE_CXX_STANDARD 14)
endif ()

set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(cmake/include/GetDateTime.cmake)
include(cmake/include/misc.cmake)
include_directories(/usr/local/include/pcapplusplus)
include_directories(/usr/local/opt/libpcap/include)
include_directories(/usr/local/include/concurrencpp-0.1.4 /usr/local/Cellar/boost/1.79.0_1/include/)

find_package(PkgConfig REQUIRED)

#pkg_check_modules(GTKMM gtkmm-4.0)

#include_directories(${GTKMM_INCLUDE_DIRS})
#link_directories(${GTKMM_LIBRARY_DIRS})

#message("GTKMM \ninclude: ${GTKMM_INCLUDE_DIRS}\n Lib: ${GTKMM_LIBRARY_DIRS}")

getdatetime()  # sets dt
message("\nStarting at ${dt} - Version ${PROJECT_VERSION}")
systeminfo()
checkipo() # will set IPO True if supported

#
# Target for macpcap
#
message("\nTarget: macpcap")
add_executable(macpcap SRC/main.cpp SRC/Protocols/parser.cpp SRC/Protocols/HostPair.h SRC/Protocols/TCPConversation.h
        SRC/Protocols/HostPair.cpp SRC/Protocols/HostPair.h SRC/Protocols/TCPConversation.cpp myColor.h SRC/Protocols/EthernetStats.cpp SRC/Protocols/EthernetStats.h SRC/Protocols/ProtocolStats.cpp SRC/Protocols/ProtocolStats.h SRC/include/csvfile.h)

message("macpcap: FMT package")
find_package(fmt)
target_link_libraries(macpcap fmt::fmt)

message("macpcap: concurrencpp library")
target_link_libraries(macpcap /usr/local/lib/libconcurrencpp.a)

message("macpcap: Loading PCAP")
find_package(PCAP REQUIRED)
message("Pcap Lib:${PCAP_LIBRARY}")
set(PCAP_LIBRARY /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX13.sdk/usr/lib/libpcap.tbd)
message("Pcap Lib:${PCAP_LIBRARY}")
target_link_libraries(${PROJECT_NAME} ${PCAP_LIBRARY})

message("macpcap: Loading PCAP++")
find_package(PcapPlusPlus REQUIRED)
message("PCAP++ ${PcapPlusPlus_LIBRARIES}")
target_link_libraries(${PROJECT_NAME} ${PcapPlusPlus_LIBRARIES};)

find_package(glog)
target_link_libraries(${PROJECT_NAME} glog::glog)

FIND_PACKAGE(Boost 1.79 COMPONENTS program_options REQUIRED)
INCLUDE_DIRECTORIES(${Boost_INCLUDE_DIR})

TARGET_LINK_LIBRARIES(${PROJECT_NAME} ${Boost_LIBRARIES})

#target_link_libraries(${CMAKE_PROJECT_NAME} ${GTKMM_LIBRARIES})

#target_link_libraries(${CMAKE_PROJECT_NAME} ${GTK3_LIBRARIES})

#
# End oc CMake file
#
getdatetime()
message("\nStopping at ${dt}")

