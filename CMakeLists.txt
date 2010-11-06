project (nident)

cmake_minimum_required (VERSION 2.6)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99 -Wall -DHAVE_CLEARENV -DLINUX")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=gnu++0x -Wall -DHAVE_CLEARENV -DLINUX")

include_directories("${PROJECT_SOURCE_DIR}/ncmlib")
add_subdirectory(ncmlib)

find_package( Boost COMPONENTS regex )
link_directories ( ${Boost_LIBRARY_DIRS} )
include_directories ( ${Boost_INCLUDE_DIRS} )

set(NIDENT_SRCS
  parse.cpp
  identclient.cpp
  epoll.cpp
  nident.cpp
  )

add_executable(nident ${NIDENT_SRCS})
target_link_libraries(nident ${Boost_REGEX_LIBRARY} ncmlib)

add_executable(tiger tiger.c sboxes.c testtiger.c)