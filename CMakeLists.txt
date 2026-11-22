cmake_minimum_required(VERSION 3.10)

PROJECT(bridger C)

ADD_DEFINITIONS(-Os -g3 -Wall -Wno-unknown-warning-option -Wno-array-bounds -Wno-format-truncation -Werror -Wno-error=deprecated-declarations --std=gnu99)

SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")

OPTION(UBUS_SUPPORT "ubus support" ON)
OPTION(NL_UDEBUG "libnl-tiny udebug support" OFF)
OPTION(MAT_SUPPORT "client bridge support for stations without 4-address mode" ON)

IF (NOT DEFINED LIBNL_LIBS)
	include(FindPkgConfig)
	pkg_search_module(NL libnl-3.0 libnl-3 libnl nl-3 nl)
	IF (NL_FOUND)
		include_directories(${NL_INCLUDE_DIRS})
		SET(LIBNL_LIBS ${NL_LIBRARIES})
	ENDIF()
ENDIF()

SET(SOURCES main.c nl.c device.c fdb.c bpf.c flow.c)
find_library(bpf NAMES bpf)
find_library(ubox NAMES ubox)

IF (UBUS_SUPPORT)
  ADD_DEFINITIONS(-DUBUS_SUPPORT)
  find_library(ubus NAMES ubus)
  find_library(udebug NAMES udebug)
  SET(SOURCES ${SOURCES} ubus.c)
  IF (NL_UDEBUG)
    ADD_DEFINITIONS(-DNL_UDEBUG)
  ENDIF()
ENDIF()

IF (MAT_SUPPORT)
  ADD_DEFINITIONS(-DMAT_SUPPORT)
  SET(SOURCES ${SOURCES} mat.c mat-arp.c mat-dhcp.c mat-nd.c mat-dhcp6.c
      mat-bpf.c)
ENDIF()

IF (DEFINED BPF_DIR)
  ADD_DEFINITIONS(-DBRIDGER_BPF_DIR="${BPF_DIR}")
ENDIF()

ADD_EXECUTABLE(bridger ${SOURCES})
TARGET_LINK_LIBRARIES(bridger ${bpf} ${ubox} ${ubus} ${udebug} ${LIBNL_LIBS})

INSTALL(TARGETS bridger
	RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR}
)
