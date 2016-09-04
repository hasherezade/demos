#pragma once
#include <Windows.h>

IMAGE_NT_HEADERS* get_nt_hrds(BYTE *pe_buffer);
IMAGE_DATA_DIRECTORY* get_pe_directory(PVOID pe_buffer, DWORD dir_id);
