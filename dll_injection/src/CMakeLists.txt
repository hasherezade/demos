cmake_minimum_required (VERSION 2.8)
project (DllInjection)

add_definitions(-DUNICODE -D_UNICODE)

set (srcs
    main.cpp
)

set (hdrs
	resource.h
	ntddk.h
	target_util.h
	createproc.h
	enumproc.h
)

set (rsrc
    resource.rc
)

add_executable (DllInjection ${rsrc} ${hdrs} ${srcs})