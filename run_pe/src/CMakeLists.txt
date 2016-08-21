cmake_minimum_required (VERSION 2.8)
project (RunPE)

add_definitions(-DUNICODE -D_UNICODE)

set (srcs
    main.cpp
)

set (hdrs
	resource.h
	ntddk.h
	ntdll_undoc.h
	target_util.h
	createproc.h
	relocate.h
	runpe.h

)

set (rsrc
    resource.rc
)

add_executable (RunPE ${rsrc} ${hdrs} ${srcs})