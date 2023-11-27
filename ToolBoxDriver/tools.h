
#pragma once

#include "picostruct.h"

extern "C" {


	
	NTSTATUS GetPicoCallbacks(OUT PPS_PICO_PROVIDER_ROUTINES* pppr);

	NTSTATUS FindNtdll(OUT void** ppv);

	PVOID FindKernelBase(OUT PULONG puSize OPTIONAL);

	PVOID FindKernelSectionByName(IN LPCSTR pName, OUT PULONG puSize OPTIONAL);

	UINT8 EnablePicoRegistrations(IN BOOLEAN bEnable);


}