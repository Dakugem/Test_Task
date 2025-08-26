cmake_minimum_required(VERSION 3.23)
project("sniffer")

#Также должны быть установлены flex и bison
FetchContent_Declare(
      libpcap
      GIT_REPOSITORY https://github.com/the-tcpdump-group/libpcap
	  SOURCE_DIR 	${CMAKE_CURRENT_SOURCE_DIR}/libpcap
      GIT_TAG libpcap-1.10.5 
    )
FetchContent_MakeAvailable(libpcap)

file(GLOB Sources CONFIGURE_DEPENDS
	${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp)
	
list(REMOVE_ITEM Sources ${CMAKE_CURRENT_SOURCE_DIR}/src/main.cpp)
	
add_executable(${PROJECT_NAME} ${CMAKE_CURRENT_SOURCE_DIR}/src/main.cpp)

target_sources(${PROJECT_NAME} PRIVATE ${Sources})
#Проверить и это тоже
#target_include_directories(${PROJECT_NAME}_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/libpcap)
target_link_libraries(${PROJECT_NAME} PRIVATE libpcap)

if(BUILD_TESTING)
	file(GLOB Test_Sources CONFIGURE_DEPENDS
		${CMAKE_CURRENT_SOURCE_DIR}/test/*.cpp
		)
		
	add_executable(${PROJECT_NAME}_test ${Test_Sources})
	
	target_sources(${PROJECT_NAME}_test PRIVATE ${Sources})
   	#Проверить и это тоже
	#target_include_directories(${PROJECT_NAME}_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/libpcap)
	#Проверить и это тоже
	target_link_libraries(${PROJECT_NAME}_test PRIVATE libpcap gtest_main gmock)
	
	add_test(NAME ${PROJECT_NAME}_TEST COMMAND ${PROJECT_NAME}_test)
endif()
