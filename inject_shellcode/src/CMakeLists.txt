cmake_minimum_required (VERSION 2.8)
project (Injections)

add_definitions(-DUNICODE -D_UNICODE)

set (srcs
    main.cpp
)

set (hdrs
    main.h
	ntddk.h
	ntdll_undoc.h
	kernel32_undoc.h
	target_util.h
	createproc.h
	add_thread.h
	add_apc.h
	patch_ep.h
	enumproc.h
    payload.h
)

add_executable (Injections ${hdrs} ${srcs})
