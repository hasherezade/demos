cmake_minimum_required (VERSION 2.8)
project (ChimeraPE)

add_definitions(-DUNICODE -D_UNICODE)

set (srcs
    main.cpp
	pe_hdrs_helper.cpp
)

set (hdrs
	resource.h
	ntddk.h
	ntdll_undoc.h
	target_util.h
	enumproc.h
	createproc.h
	pe_hdrs_helper.h
	load_imports.h
	relocate.h
	inject_pe.h
)

set (rsrc
    resource.rc
)

add_executable (ChimeraPE ${rsrc} ${hdrs} ${srcs})