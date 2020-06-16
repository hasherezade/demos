cmake_minimum_required (VERSION 2.8)
project (DllInjection)

add_definitions(-DUNICODE -D_UNICODE)

set (srcs
	main.cpp
	sysutil.cpp
)

set (hdrs
	resource.h
	ntddk.h
	target_util.h
	createproc.h
	enumproc.h
	map_buffer_into_process.h
	inject_with_loadlibrary.h
	sysutil.h
)

set (rsrc
	resource.rc
)

add_executable (DllInjection ${rsrc} ${hdrs} ${srcs})

INSTALL( TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX} COMPONENT ${PROJECT_NAME} )
