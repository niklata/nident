project (nident)

cmake_minimum_required (VERSION 2.6)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -std=gnu99 -Wall -DHAVE_CLEARENV -DLINUX")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -std=gnu++0x -Wall -DHAVE_CLEARENV -DLINUX")

include_directories("${PROJECT_SOURCE_DIR}" "${PROJECT_SOURCE_DIR}/ncmlib")
add_subdirectory(ncmlib)

find_package( Boost COMPONENTS system program_options )
link_directories ( ${Boost_LIBRARY_DIRS} )
include_directories ( ${Boost_INCLUDE_DIRS} )

set(RAGEL_PARSECFG ${CMAKE_CURRENT_BINARY_DIR}/parsecfg.cpp)
set(RAGEL_IDENTPARSE ${CMAKE_CURRENT_BINARY_DIR}/identparse.cpp)

find_program(RAGEL ragel)
add_custom_command(
  OUTPUT ${RAGEL_PARSECFG}
  COMMAND ${RAGEL} -G2 -o ${RAGEL_PARSECFG} parsecfg.rl
  DEPENDS parsecfg.rl
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  COMMENT "Compiling Ragel state machine: parsecfg.rl"
  VERBATIM
  )
add_custom_command(
  OUTPUT ${RAGEL_IDENTPARSE}
  COMMAND ${RAGEL} -G2 -o ${RAGEL_IDENTPARSE} identparse.rl
  DEPENDS identparse.rl
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  COMMENT "Compiling Ragel state machine: identparse.rl"
  VERBATIM
  )


set(NIDENT_SRCS
  siphash.cpp
  netlink.cpp
  parse.cpp
  identclient.cpp
  nident.cpp
  )

set(NLTEST_SRCS
  netlink.cpp
  nl-test.cpp
  )

set(PTEST_SRCS
  siphash.cpp
  netlink.cpp
  parse.cpp
  parsetest.cpp
  )

add_executable(nident ${RAGEL_IDENTPARSE} ${RAGEL_PARSECFG} ${NIDENT_SRCS})
target_link_libraries(nident ${Boost_LIBRARIES} ncmlib)

add_executable(nl-test ${NLTEST_SRCS})
target_link_libraries(nl-test ${Boost_LIBRARIES})

add_executable(parsetest ${RAGEL_PARSECFG} ${PTEST_SRCS})
target_link_libraries(parsetest ${Boost_LIBRARIES} ncmlib)
