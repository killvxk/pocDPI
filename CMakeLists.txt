cmake_minimum_required (VERSION 2.6)
project (LibreDPI)
#TODO: SHARED !#
add_executable(test 
			src/main.c
			src/libredpi.c
			src/protocols/eth.c
			src/protocols/ip.c
			src/protocols/udp.c
			src/protocols/dns.c
			)
target_link_libraries (test pcap pthread)

set( CMAKE_C_FLAGS "-g " )
