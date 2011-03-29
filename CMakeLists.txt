project (nident)

cmake_minimum_required (VERSION 2.6)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -s -std=gnu99 -Wall -DHAVE_CLEARENV -DLINUX")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -s -std=gnu++0x -Wall -DHAVE_CLEARENV -DLINUX")

include_directories("${PROJECT_SOURCE_DIR}/ncmlib")
add_subdirectory(ncmlib)

find_package( Boost COMPONENTS regex system program_options )
link_directories ( ${Boost_LIBRARY_DIRS} )
include_directories ( ${Boost_INCLUDE_DIRS} )

set(NIDENT_SRCS
  blake256.c
  netlink.cpp
  parse.cpp
  identclient.cpp
  nident.cpp
  )

set(NLTEST_SRCS
  netlink.cpp
  nl-test.cpp
  )

add_executable(nident ${NIDENT_SRCS})
target_link_libraries(nident ${Boost_LIBRARIES} ncmlib)

add_executable(nl-test ${NLTEST_SRCS})
target_link_libraries(nl-test ${Boost_LIBRARIES})
