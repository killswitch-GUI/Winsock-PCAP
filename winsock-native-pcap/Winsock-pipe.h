#pragma once
#include "stdafx.h"
#include <thread>
#include <iostream>
#include <windows.h>
#include <time.h>
#include <stdio.h>
#include <wchar.h>

// Use std namespace for ease
//using namespace std;

/*
Setup global poison pill, after
much thought about how to properly handle
start, stop, exit, restart. I found that a
pill would be a great way to handle all of
these methods and properly exit a thread once
this variable has been set. Pill will follow:

0 = stop - dont write / output data (pause)
1 = star - starts the cappture / continue
2 = restart - restart and rebuild files
3 = exit - set poison pill / kill thread main will exit
*/
int pill = 0;
extern int pill;

int buildPipe();
bool threadedPipe();

// A function to build the pipe
int buildPipe() {
	HANDLE pipe = CreateNamedPipe(
		L"\\\\.\\pipe\\my_pipe",
		PIPE_ACCESS_DUPLEX, // client to server - server to client
		PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, // byte stream, do we need others?
		1, // nMaxInstances - 1
		0, // nOutBufferSize - none
		0, // nInBufferSize  - none
		0, // nDefaultTimeOut - 50 milliseconds. 
		NULL // security attributes - def
	);

	if (pipe == NULL || pipe == INVALID_HANDLE_VALUE) {
		DWORD lastError = GetLastError();
		std::wcout << "[!] Failed to create server pipe: " << lastError << std::endl;
		return 1;
	}
	std::cout << "[*] Pipe server waiting for command..." << std::endl;

	// blocking call till client connects / sends data
	BOOL message = ConnectNamedPipe(
		pipe, // the handle to the pipe
		NULL // lpOverlapped - not FILE_FLAG_OVERLAPPED
	);
	if (!message) {
		DWORD lastError = GetLastError();
		std::wcout << "[!] Failed to create connection to named pipe: " << lastError << std::endl;
		CloseHandle(pipe);
		return 1;
	}
	// init proper vars needed to reduce calls
	char vOne[] = "00"; // stop
	char vTwo[] = "01"; // start
	char vThree[] = "02"; // restart
	char vFour[] = "03"; // exit
	// build a while loop with blocking logic
	while (1) {
		// send message to client and block till read by client
		const wchar_t *data = L"---- Winscok Capture waiting for command ----\n";
		DWORD numBytesWritten = 0;
		BOOL write = WriteFile(
			pipe,
			data, // bytes to send
			wcslen(data) * sizeof(wchar_t), // byte size
			&numBytesWritten,
			NULL
		);
		if (write) {
			std::wcout << "[*] Server sent bytes: " << numBytesWritten << std::endl;
		}
		else {
			DWORD lastError = GetLastError();
			std::wcout << "[!] Failed to send data: " << lastError << std::endl;
			// break to the top of the loop
			continue;
		}
		BOOL success = FALSE;
		DWORD dwAvailable = 0;
		while (1) {
			success = PeekNamedPipe(pipe, NULL, NULL, NULL, &dwAvailable, NULL); // checks for data on the pipe
			if (success) {
				if (dwAvailable == 0) {
					Sleep(1 * 1000);
				}
				else {
					break;
				}
			}
			else {
				std::cout << "[!] ERROR peeking on the pipe: " << GetLastError() << std::endl;
				return 0;
				}
		}
		// now block for data from the pipe
		const int BUFFER_SIZE = 1024;
		BYTE buffer[BUFFER_SIZE];
		DWORD numBytesRead = 0;
		BOOL fSuccess = ReadFile(
			pipe,        // handle to pipe 
			buffer,    // buffer to receive data 
			127 * sizeof(wchar_t), // size of buffer 
			&numBytesRead, // number of bytes read 
			NULL);        // not overlapped I/O 

		// create pill logic
		if (fSuccess) {
			buffer[numBytesRead] = '\0'; // null-tem string
			std::wcout << "[*] Server received bytes: " << numBytesRead << std::endl;
			std::cout << "[*] Client sent the following message: " << buffer << std::endl;
			if (buffer) {
				if (memcmp(buffer, vOne, 2) == 0) {
					//00 = stop - dont write / output data(pause)
					std::wcout << "[!] Server received stop message - now pausing" << std::endl;
					pill = 0;
				}
				else if (memcmp(buffer, vTwo, 2) == 0) {
					//01 = star - starts the cappture / continue
					std::wcout << "[!] Server start message - now continuing" << std::endl;
					pill = 1;
				}
				else if (memcmp(buffer, vThree, 2) == 0) {
					//02 = restart - restart and rebuild files
					std::wcout << "[!] Server restart message - now restarting" << std::endl;
					pill = 2;
				}
				else if (memcmp(buffer, vFour, 2) == 0) {
					//03 = exit - set poison pill / kill thread main will exit
					std::wcout << "[!] Server exit message - now exiting" << std::endl;
					pill = 3;
					break;
				}
				else {
					std::wcout << "[!] Server received invalid request!" << std::endl;
				}
			}
		}
		else {
			DWORD lastError = GetLastError();
			std::wcout << "[!] Failed to read data from client: " << lastError << std::endl;
		}

	} // end of while loop
	try {
		std::cout << "[!] Pipe server shuting down" << std::endl;
		CloseHandle(pipe);
	}
	catch (int e) {
		std::cout << "[*] Pipe server already flushed: " << e << std::endl;
	}
	// In C++ code, you should return from your thread function.
	// ExitThread, bypasses garbage clean up
	return 0;

}

// A threaded function for the async pipe
bool threadedPipe() {
	try {
		std::cout << "[*] Starting pipe server! " << std::endl;
		std::thread first(buildPipe);     // spawn new thread that calls function
		std::cout << "[*] Pipe thread started! " << std::endl;
		first.detach(); // thread is broken off from main
		return true;
	}
	catch (int e) {
		std::cout << "[*] Failed to start pipe server: " << e << std::endl;
		return false;
	}
}