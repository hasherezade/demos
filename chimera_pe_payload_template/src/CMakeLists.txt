cmake_minimum_required (VERSION 2.8)
project (ChimeraPE_Payload)

add_definitions(-DUNICODE -D_UNICODE)
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

set (srcs
    main.cpp
	start_actions.cpp
	reflective/pe_hdrs_helper.cpp
)

set (hdrs
	ntddk.h
	reflective/pe_hdrs_helper.h
	reflective/peb_lookup.h
	reflective/exports_lookup.h
	start_actions.h
	test.h
)

add_executable (ChimeraPE_Payload ${hdrs} ${srcs})