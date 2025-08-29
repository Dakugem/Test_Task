cmake_minimum_required(VERSION 3.23)
project("test_task_infotecs")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(CTest)
include(FetchContent)

if(BUILD_TESTING)
	message(STATUS "TESTS ON")

	FetchContent_Declare(googletest
		GIT_REPOSITORY 	https://github.com/google/googletest.git
		SOURCE_DIR 	${CMAKE_CURRENT_SOURCE_DIR}/gtest
		GIT_TAG 	v1.17.0
		)
	FetchContent_MakeAvailable(googletest)
else()
	message(STATUS "TESTS OFF")
endif()

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/Server_Client_and_Sniffer)
