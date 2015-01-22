cmake_minimum_required (VERSION 2.8)
project (aafw)

include_directories(include)

IF("${CMAKE_SYSTEM}" MATCHES "Linux" OR "${CMAKE_SYSTEM}" MATCHES "FreeBSD")
	SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -std=c++11 -z defs")
	SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -std=c++11 -Wall -z defs")
ELSEIF("${CMAKE_SYSTEM}" MATCHES "Windows")
	SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE}")
	SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -Wall")
ENDIF()

set(PROJECT_SOVERSION "1")
set(PROJECT_VERSION "1.0.0")

file(GLOB SRC_FILES "src/*.c" "src/*.cpp")
file(GLOB_RECURSE INCS_H "include/*.h" "include/*.hpp")

add_library(${PROJECT_NAME} SHARED ${SRC_FILES} ${INCS_H})
set_target_properties(${PROJECT_NAME} PROPERTIES SOVERSION ${PROJECT_SOVERSION})
set_target_properties(${PROJECT_NAME} PROPERTIES VERSION ${PROJECT_VERSION})

install(TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX}/lib
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_PREFIX}/include 
    FILES_MATCHING PATTERN "*.h" PATTERN "*.hpp" PATTERN ".svn" EXCLUDE
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
#install(FILES .... DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}" )

# Openssl stuff
SET(OPENSSL_MIN_VERSION "1.0.0")
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIRS})
if (OPENSSL_VERSION STRGREATER OPENSSL_MIN_VERSION)
    message("-- Openssl suitable library found: ${OPENSSL_VERSION} (> ${OPENSSL_MIN_VERSION})")
else(OPENSSL_VERSION STRGREATER OPENSSL_MIN_VERSION)
    message(FATAL_ERROR "-- Openssl version required must be at least ${OPENSSL_MIN_VERSION} but ${OPENSSL_VERSION} was found")    
endif(OPENSSL_VERSION STRGREATER OPENSSL_MIN_VERSION)

IF("${CMAKE_SYSTEM}" MATCHES "Windows")
	include_directories("C:\\Desenvolvimento\\include")
ENDIF()


# Libraries without packages
# Helper macro to find libraries    
macro(my_find_library)          
    find_library(${ARGV0} ${ARGV1})    
    if (NOT ${ARGV0})
        message(FATAL_ERROR "-- could not find library ${ARGV1}")
    endif(NOT ${ARGV0})
    message("-- Library ${ARGV1} found as ${${ARGV0}}")   
endmacro()

my_find_library(CRYPTOBASE cryptobase)
my_find_library(POCO_FOUNDATION PocoFoundation)
my_find_library(POCO_CRYPTO PocoCrypto)
my_find_library(POCO_UTIL PocoUtil)
my_find_library(POCO_NET PocoNet)
my_find_library(POCO_NETSSL PocoNetSSL)

target_link_libraries (${PROJECT_NAME} 
							${OPENSSL_LIBRARIES} 
							${CRYPTOBASE} 
							${POCO_FOUNDATION} 
							${POCO_CRYPTO} 
							${POCO_UTIL} 
							${POCO_NET} 
							${POCO_NETSSL}
							)
