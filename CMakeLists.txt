cmake_minimum_required ( VERSION 2.8...3.21 )
project (injection_demos)

# modules:
set ( M_CHIMERA_LOADER "chimera_pe" )
set ( M_CHIMERA_PAYLOAD "chimera_pe_payload_template" )
set ( M_DLL_INJ "dll_injection" )
set ( M_FUNC_LOADER "functions_loader" )
set ( M_INJ_SHELC "inject_shellcode" )
set ( M_RUNPE "run_pe" )

# Add sub-directories
#
add_subdirectory( ${M_CHIMERA_LOADER}/src )
add_subdirectory( ${M_CHIMERA_PAYLOAD}/src )

add_subdirectory( ${M_DLL_INJ}/src )
add_subdirectory( ${M_FUNC_LOADER}/src )
add_subdirectory( ${M_INJ_SHELC}/src )
add_subdirectory( ${M_RUNPE}/src )