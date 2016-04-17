project (nident)

cmake_minimum_required (VERSION 2.6)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -std=gnu99 -pedantic -Wall -Wextra -Wformat=2 -Wformat-security -Wpointer-arith -Wno-unused-parameter")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -std=gnu++14 -pedantic -Wall -Wextra -Wformat=2 -Wformat-security -Wpointer-arith -Wno-unused-parameter")

if (WIN32)
  set(OSNAME "Win32")
else()
execute_process(
  COMMAND uname
  COMMAND tr "\n" " "
  COMMAND sed "s/ //"
  OUTPUT_VARIABLE OSNAME
  )
endif()

if (${OSNAME} STREQUAL "Linux")
  message("Detected that the current host is a Linux system.")
else()
  message("nident requires a Linux host system for netlink support.")
  return()
endif()

include_directories("${PROJECT_SOURCE_DIR}"
                    "${PROJECT_SOURCE_DIR}/ncmlib"
                    "${PROJECT_SOURCE_DIR}/cppformat")
add_subdirectory(ncmlib)
add_subdirectory(cppformat)

find_package( Boost COMPONENTS system )
link_directories ( ${Boost_LIBRARY_DIRS} )
include_directories ( ${Boost_INCLUDE_DIRS} )
find_package(Threads)

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

#set(NLTEST_SRCS
#  netlink.cpp
#  nl-test.cpp
#  )
#
#set(PTEST_SRCS
#  siphash.cpp
#  netlink.cpp
#  parse.cpp
#  parsetest.cpp
#  )

add_executable(nident ${RAGEL_IDENTPARSE} ${RAGEL_PARSECFG} ${NIDENT_SRCS})
target_link_libraries(nident ${CMAKE_THREAD_LIBS_INIT} ${Boost_LIBRARIES} ncmlib cppformat)

#add_executable(nl-test ${NLTEST_SRCS})
#target_link_libraries(nl-test ${CMAKE_THREAD_LIBS_INIT} ${Boost_LIBRARIES}
#                              cppformat)
#
#add_executable(parsetest ${RAGEL_PARSECFG} ${PTEST_SRCS})
#target_link_libraries(parsetest ${CMAKE_THREAD_LIBS_INIT} ${Boost_LIBRARIES}
#                                ncmlib cppformat)

