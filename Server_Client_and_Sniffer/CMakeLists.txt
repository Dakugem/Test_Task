cmake_minimum_required(VERSION 3.23)
project("server-client and sniffer")

#Также должны быть установлены flex и bison
FetchContent_Declare(
      libpcap
      GIT_REPOSITORY https://github.com/the-tcpdump-group/libpcap
	  SOURCE_DIR 	${CMAKE_CURRENT_SOURCE_DIR}/libpcap
      GIT_TAG libpcap-1.10.5 
    )
FetchContent_MakeAvailable(libpcap)

set(SRC ${CMAKE_CURRENT_SOURCE_DIR}/src)
add_executable(server_client ${SRC}/server_client.cpp)
target_sources(server_client PRIVATE 
	${SRC}/network_io.cpp 
	${SRC}/registrar.cpp 
	${SRC}/node.cpp)
target_include_directories(server_client PRIVATE ${SRC})

add_executable(sniffer ${SRC}/sniffer.cpp)
target_sources(sniffer PRIVATE 
	${SRC}/network_io.cpp 
	${SRC}/top.cpp
	${SRC}/pcap_worker.cpp
	${SRC}/flow.cpp)
target_include_directories(server_client PRIVATE 
	${libpcap_SOURCE_DIR}
    ${libpcap_BINARY_DIR}
	${SRC})
target_link_libraries(sniffer PRIVATE pcap)

if(BUILD_TESTING)
	#file(GLOB Test_Sources CONFIGURE_DEPENDS
		#${CMAKE_CURRENT_SOURCE_DIR}/test/*.cpp
		#
		
	#add_executable(${PROJECT_NAME}_test ${Test_Sources})
	
	#target_sources(${PROJECT_NAME}_test PRIVATE ${Sources})
	
	#target_link_libraries(${PROJECT_NAME}_test PRIVATE gtest_main gmock)
	
	#add_test(NAME ${PROJECT_NAME}_TEST COMMAND ${PROJECT_NAME}_test)
endif()
