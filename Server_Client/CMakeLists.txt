cmake_minimum_required(VERSION 3.23)
project("server-client")

file(GLOB Sources CONFIGURE_DEPENDS
	${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp)
	
list(REMOVE_ITEM Sources ${CMAKE_CURRENT_SOURCE_DIR}/src/main.cpp)
	
add_executable(${PROJECT_NAME} ${CMAKE_CURRENT_SOURCE_DIR}/src/main.cpp)

target_sources(${PROJECT_NAME} PRIVATE ${Sources})

if(BUILD_TESTING)
	file(GLOB Test_Sources CONFIGURE_DEPENDS
		${CMAKE_CURRENT_SOURCE_DIR}/test/*.cpp
		)
		
	add_executable(${PROJECT_NAME}_test ${Test_Sources})
	
	target_sources(${PROJECT_NAME}_test PRIVATE ${Sources})
	
	target_link_libraries(${PROJECT_NAME}_test PRIVATE gtest_main gmock)
	
	add_test(NAME ${PROJECT_NAME}_TEST COMMAND ${PROJECT_NAME}_test)
endif()
