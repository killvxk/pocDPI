cmake_minimum_required (VERSION 2.6)
project (libreDPI)

#shared lib
include_directories(src/protocols/)
add_library(libreDPI
			SHARED
			src/libredpi.c
			src/protocols/eth.c
			src/protocols/ip.c
			src/protocols/udp.c
			src/protocols/dns.c
			)
			
target_link_libraries (libreDPI pthread)
set( CMAKE_C_FLAGS "-g" )


#test
add_executable(test test/main.c)
include_directories(src/include/)
target_link_libraries (test libreDPI pcap)

set( CMAKE_C_FLAGS "-g" )
