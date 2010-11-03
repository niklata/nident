project (nident)

cmake_minimum_required (VERSION 2.6)

set(CMAKE_C_FLAGS "-std=gnu99 -Wall -DHAVE_CLEARENV -DLINUX")
set(CMAKE_CXX_FLAGS "-std=gnu++0x -Wall -DHAVE_CLEARENV -DLINUX")

include_directories("${PROJECT_SOURCE_DIR}/ncmlib")
add_subdirectory(ncmlib)

set(NIDENT_SRCS
  identclient.cpp
  epoll.cpp
  nident.cpp
  )

add_executable(nident ${NIDENT_SRCS})
target_link_libraries(nident ncmlib)
