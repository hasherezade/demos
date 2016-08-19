cmake_minimum_required (VERSION 2.8)
project (Inject1)

add_definitions(-DUNICODE -D_UNICODE)

set (srcs
    main.cpp
)

set (hdrs
    main.h
	ntddk.h
	ntdll_undoc.h
	add_thread.h
	add_apc.h
	patch_ep.h
    payload.h
)

add_executable (Inject1 ${hdrs} ${srcs})
