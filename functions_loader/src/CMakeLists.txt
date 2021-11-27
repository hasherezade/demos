cmake_minimum_required ( VERSION 2.8...3.21 )
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

	usage_demo.h
	test.h
)

add_executable (FunctionsLoader ${hdrs} ${srcs})

INSTALL( TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX} COMPONENT ${PROJECT_NAME} )
