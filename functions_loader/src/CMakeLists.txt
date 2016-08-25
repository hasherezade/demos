cmake_minimum_required (VERSION 2.8)
project (FunctionsLoader)

add_definitions(-DUNICODE -D_UNICODE)

set (srcs
    main.cpp
	pe_hdrs_helper.cpp
)

set (hdrs
	ntddk.h
	pe_hdrs_helper.h
	peb_lookup.h
	exports_lookup.h
)

add_executable (FunctionsLoader ${hdrs} ${srcs})