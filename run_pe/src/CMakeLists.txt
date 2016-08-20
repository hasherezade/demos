cmake_minimum_required (VERSION 2.8)
project (RunPE)

add_definitions(-DUNICODE -D_UNICODE)

set (srcs
    main.cpp
)

set (hdrs
    resource.h
	createproc.h
	ntddk.h
	ntdll_undoc.h
)

set (rsrc
    resource.rc
)

add_executable (RunPE ${rsrc} ${hdrs} ${srcs})