// various functions for support

#include "common.h"
#include "picostruct.h"
#include "os.h"
#include "log.h"
#include "pe.h"


extern "C" {

	// externs
	NTSTATUS ZwQuerySection(
		IN HANDLE               SectionHandle,
		IN SECTION_INFORMATION_CLASS InformationClass,
		OUT PVOID               InformationBuffer,
		IN ULONG                InformationBufferSize,
		OUT PULONG              ResultLength OPTIONAL);

	NTSTATUS ZwQuerySystemInformation(
		IN ULONG SystemInformationClass, 
		IN PVOID SystemInformation, 
		IN ULONG SystemInformationLength, 
		OUT PULONG ReturnLength);

	/* tries to find NTDLL address using KnownDlls*/
	NTSTATUS FindNtdll(OUT void** ppv)
	{
		NTSTATUS status;
		OBJECT_ATTRIBUTES oa;

		DECLARE_CONST_UNICODE_STRING(us, L"\\KnownDlls\\ntdll.dll");

		InitializeObjectAttributes(&oa, (PUNICODE_STRING)&us, NULL, NULL, NULL);

		HANDLE hSection;
		if (0 <= (status = ZwOpenSection(&hSection, SECTION_QUERY, &oa)))
		{
			SECTION_IMAGE_INFORMATION sii;
			if (0 <= (status = ZwQuerySection(hSection, SectionImageInformation, &sii,
				sizeof(sii), 0)))
			{
				*ppv = sii.TransferAddress;
			}
			ZwClose(hSection);
		}

		return status;
	}

	

	PVOID FindKernelBase(OUT PULONG puSize OPTIONAL)
	{
		PRTL_PROCESS_MODULES pModules;
		ULONG uLen;
		NTSTATUS status;


	LRepeat:
		ZwQuerySystemInformation(SystemModuleInformation, (PVOID)&uLen, 0, &uLen);

		pModules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(PagedPool, uLen, '--xS');
		if (!pModules) return NULL;

		status = ZwQuerySystemInformation(SystemModuleInformation, (PVOID)pModules, uLen, &uLen);
		if (!NT_SUCCESS(status)) {

			ExFreePoolWithTag(pModules, '--xS');
			if (STATUS_INFO_LENGTH_MISMATCH == status) goto LRepeat;
			return NULL;
		}

		for (ULONG i = 0; i < pModules->NumberOfModules; i++)
		{
			if (strstr((char*)pModules->Modules[i].FullPathName, "ntoskrnl.exe") ||		// 1 CPU
				strstr((char*)pModules->Modules[i].FullPathName, "ntkrnlmp.exe") ||		// N CPU, SMP
				strstr((char*)pModules->Modules[i].FullPathName, "ntkrnlpa.exe") ||		// 1 CPU, PAE
				strstr((char*)pModules->Modules[i].FullPathName, "ntkrpamp.exe") ||		// N CPU, SMP, PAE
				strstr((char*)pModules->Modules[i].FullPathName, "xNtKrnl.exe"))			// patched kernel
			{
				if (puSize) *puSize = pModules->Modules[i].ImageSize;
				PVOID pImageBase = pModules->Modules[i].ImageBase;
				ExFreePoolWithTag(pModules, '--xS');

				return pImageBase;
			}
		}

		ExFreePoolWithTag(pModules, '--xS');
		return NULL;
	}



	PVOID FindKernelSectionByName(IN LPCSTR pName, OUT PULONG puSize OPTIONAL)
	{
		ULONG uSize;
		PVOID pImageBase = FindKernelBase(&uSize);

		PBYTE pCurrent = (PBYTE)pImageBase;

		// Jump to the PE header.
		pCurrent = pCurrent + *((PINT)(pCurrent + 0x3C));

		PIMAGE_NT_HEADERS64 pPeHeader = (PIMAGE_NT_HEADERS64)pCurrent;

		pCurrent += sizeof(IMAGE_NT_HEADERS64);

		PIMAGE_SECTION_HEADER pInterestedSectionHeader = NULL;

		for (SIZE_T i = 0;
			i < pPeHeader->FileHeader.NumberOfSections;
			++i, pCurrent += sizeof(IMAGE_SECTION_HEADER))
		{
			PIMAGE_SECTION_HEADER pCurrentSectionHeader = (PIMAGE_SECTION_HEADER)pCurrent;

			if (strncmp(pName, (const char*)pCurrentSectionHeader->Name,
				IMAGE_SIZEOF_SHORT_NAME) == 0)
			{
				pInterestedSectionHeader = pCurrentSectionHeader;
			}
		}

		if (pInterestedSectionHeader == NULL)
		{
			return NULL;
		}

		if (puSize != NULL)
		{
			*puSize = pInterestedSectionHeader->SizeOfRawData;
		}

		return (PBYTE)pImageBase + pInterestedSectionHeader->VirtualAddress;
	}



	// big o'hack enabled registration of subsequent pico providers, in fact overwrite the other ones
	BOOLEAN EnablePicoRegistrations(IN BOOLEAN bEnable)
	{

		// get address of PsRegisterPicoProvider
		void* addr = (void*)PsRegisterPicoProvider;

		// find cmp ....
		INT32* pDis = (INT32*)((UINT_PTR)addr + 0x2e);

		// extract address
		UINT8* p_disbleRegistration = (UINT8*)((DWORD64)addr + 0x32 + *pDis);

		// just to be sure check we have really cmp
		// TODO:

		
		BOOLEAN old = (*p_disbleRegistration==0);

		*p_disbleRegistration = bEnable ? 0 : 1;

		return old;
	}


	// gets direct pointer to system's table of PICO provider's callbacks
	NTSTATUS GetPicoCallbacks(PPS_PICO_PROVIDER_ROUTINES* pppr)
	{
		// TODO: Another way to get the PICO routines?
		// This method is based on the disassembly of the PsRegisterPicoProvider function,
		// which is very fragile. It will not work on other architectures, or even different
		// releases of Windows x86_64.
		// Not to mention this method also relies on PspPicoProviderRoutines being right
		// next to PspPicoRegistrationDisabled.
		// 
		// One possible method is based on PsKernelRangeList:
		// https://redplait.blogspot.com/2019/01/simple-way-to-find-pskernelrangelist.html
		// PspPicoProviderRoutines is supposed to be an entry on the list, but on
		// Windows 11 23H2, it does not seem to be present here.
		//
		// Another method is to import lxcore.sys and then look for the Pico* functions
		// (e.g. PicoThreadExit). Then we can reconstruct a part of the struct and
		// find the byte patterns.
		//
		// Or, we can look for the kernel symbols and load them to get the function offset.


		//
		if (!pppr)
			return STATUS_INVALID_PARAMETER;

		// get address of PsRegisterPicoProvider
		void* addr = (void*)PsRegisterPicoProvider;

		// find cmp ....
		// cmp instruction starts at offset 0x2e, but the operand we are interested in
		// starts 2 bytes after that.
		INT32* dis = (INT32*)((UINT_PTR)addr + 0x30);

		// extract address
		UINT8* p_disbleRegistration = (UINT8*)((DWORD64)addr + 0x34 + *dis);

		PPS_PICO_PROVIDER_ROUTINES ppr = (PPS_PICO_PROVIDER_ROUTINES)ALIGN_UP_POINTER_BY(p_disbleRegistration + 1, 0x20);

		*pppr = ppr;

		return STATUS_SUCCESS;
	}



}