cmake_minimum_required(VERSION 3.10)

PROJECT(bridger C)

ADD_DEFINITIONS(-Os -g3 -Wall -Wno-unknown-warning-option -Wno-array-bounds -Wno-format-truncation -Werror -Wno-error=deprecated-declarations --std=gnu99)

SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")

IF (NOT DEFINED LIBNL_LIBS)
	include(FindPkgConfig)
	pkg_search_module(LIBNL libnl-3.0 libnl-3 libnl nl-3 nl)
	IF (LIBNL_FOUND)
		include_directories(${LIBNL_INCLUDE_DIRS})
		SET(LIBNL_LIBS ${LIBNL_LIBRARIES})
	ENDIF()
ENDIF()

find_library(bpf NAMES bpf)
find_library(ubox NAMES ubox)
find_library(ubus NAMES ubus)

ADD_EXECUTABLE(bridger main.c nl.c device.c fdb.c bpf.c flow.c)
TARGET_LINK_LIBRARIES(bridger ${bpf} ${ubox} ${ubus} ${LIBNL_LIBS})

INSTALL(TARGETS bridger
	RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR}
)
