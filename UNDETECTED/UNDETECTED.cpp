#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <utility>

struct roblox_t {
	HANDLE hRoblox;
	DWORD pid;
	DWORD tid;

	PVOID win32uBase;
	PVOID robloxBase;
};

roblox_t GetRobloxHandle() {
	roblox_t robloxInfo{};

	HWND rbx = FindWindowA(NULL, "Roblox");

	DWORD pid = 0;
	DWORD tid = GetWindowThreadProcessId(rbx, &pid);

	return roblox_t{ OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid), pid, tid };
}

bool IsInvalid(HANDLE h) {
	return h == INVALID_HANDLE_VALUE;
}

bool GetModuleBases(roblox_t& robloxInfo) {
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, robloxInfo.pid);
	if (IsInvalid(hSnap)) {
		std::printf("INVALID SNAPSHOT!\n");
		return false;
	}

	MODULEENTRY32 currentModule{};
	currentModule.dwSize = sizeof(currentModule);

	if (Module32First(hSnap, &currentModule)) {
		do {
			if (!std::strcmp(currentModule.szModule, "win32u.dll")) {
				robloxInfo.win32uBase = currentModule.modBaseAddr;
			}
			else if (!std::strcmp(currentModule.szModule, "RobloxPlayerBeta.exe")) {
				robloxInfo.robloxBase = currentModule.modBaseAddr;
			}
		} while (Module32Next(hSnap, &currentModule));
	}
	else {
		std::printf("MODULE ITERATION FAILED!\n");
	}

	CloseHandle(hSnap);
	return robloxInfo.robloxBase && robloxInfo.win32uBase;
}

void CreateMessageBox(roblox_t& robloxInfo) {
	std::uintptr_t baseText = (std::uintptr_t)robloxInfo.win32uBase + 0x1000;
	unsigned char shellcode[] = { 0x41, 0x57, 0x49, 0xBF, 0x22, 0x11, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x49, 0x87, 0xE7, 0x41, 0x5E, 0x5A, 0x41, 0x58, 0x58, 0x49, 0x87, 0xE7, 0x41, 0x5F, 0x48, 0x31, 0xC9, 0x49, 0xC7, 0xC1, 0x30, 0x00, 0x00, 0x00, 0xFF, 0xD0, 0x41, 0xFF, 0xE6 };

	/*
		NOTE:
		I'VE DESIGNED THIS SHELLCODE TO TAKE AS LITTLE SPACE AS POSSIBLE, IF YOU HAVE ANY BETTER IDEAS GO AHEAD AND TRY THEM. EXCHANGING THE STACK CRASHES CE VEH DEBUGGER FYI.

		SHELLCODE:
		push r15 ; Preserve r15
		mov r15, 0xAABBCCDDEEFF1122 ; Temporary hold stack
		xchg r15, rsp ; Swap stack
		pop r14 ; Pop real return address
		pop rdx ; Text argument
		pop r8  ; Title argument
		pop rax ; Function to call
		xchg r15, rsp ; Restore stack
		pop r15 ; Restore r15

		xor rcx, rcx ; Clear RCX (HWND)
		mov r9, 0x30 ; Warning icon
		call rax ; Call MessageBoxA
		jmp r14 ; Go back to original return value
	*/


	const char* myMessage = "HELLO I AM UNDETECTED!";
	const char* myTitle = "UDASF V1.0";

	void* myMessagePtr = VirtualAllocEx(robloxInfo.hRoblox, 0, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); // Create message memory
	WriteProcessMemory(robloxInfo.hRoblox, myMessagePtr, myMessage, std::strlen(myMessage), nullptr); // Write our message into message memorys

	void* myTitlePtr = VirtualAllocEx(robloxInfo.hRoblox, 0, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); // Create title memory
	WriteProcessMemory(robloxInfo.hRoblox, myTitlePtr, myTitle, std::strlen(myMessage), nullptr); // Write our title into title memory

	void* MessageBoxAPtr = GetProcAddress(GetModuleHandleA("user32.dll"), "MessageBoxA"); // WILL BE LOADED AT SAME ADDRESS SINCE ITS A SHARED PAGE TECHNICALLY

	// Here is the injection logic
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, robloxInfo.tid);
	std::printf("HIJACKING THREAD: %d\n", robloxInfo.tid);

	DWORD result = SuspendThread(hThread);
	if (result == -1) {
		std::printf("Failed to suspend thread!\n");
	}
	else {
		std::printf("Thread suspend count: %d\n", result);

		CONTEXT threadCtx{};
		threadCtx.ContextFlags = CONTEXT_ALL;

		if (!GetThreadContext(hThread, &threadCtx)) {
			std::printf("Failed to get thread context!\n");
		}

		std::printf("Thread RIP: 0x%p|Thread RCX: 0x%p|Thread RDX: 0x%p\n", threadCtx.Rip, threadCtx.Rcx, threadCtx.Rdx);
		std::printf("DR0: 0x%p | DR1: 0x%p | DR2: 0x%p | DR3: 0x%p\n", threadCtx.Dr0, threadCtx.Dr1, threadCtx.Dr2, threadCtx.Dr3);

		// Retrieve old return value off stack (remember the thread is suspended so it has to have a return here)
		std::uintptr_t oldReturnValue = 0;
		ReadProcessMemory(robloxInfo.hRoblox, (PVOID)threadCtx.Rsp, &oldReturnValue, sizeof(oldReturnValue), nullptr);

		// Replace return to our hook
		WriteProcessMemory(robloxInfo.hRoblox, (PVOID)threadCtx.Rsp, &baseText, sizeof(baseText), nullptr);


		// We will store all the data our shellcode needs here in this custom stack space.
		// This allows us to pack the code tighter by storing some of the information in data such as pointers
		// On top of this if we use this storage as a stack we can turn an 8 byte moving a pointer into a register, into a 1 byte pop which saves a LOT of space.
		void* VariableStorage = VirtualAllocEx(robloxInfo.hRoblox, 0, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		WriteProcessMemory(robloxInfo.hRoblox, VariableStorage, &oldReturnValue, sizeof(oldReturnValue), nullptr); // +0 = Return
		WriteProcessMemory(robloxInfo.hRoblox, (PVOID)((std::uintptr_t)VariableStorage + 8), &myMessagePtr, sizeof(myMessagePtr), nullptr); // +8 = Message
		WriteProcessMemory(robloxInfo.hRoblox, (PVOID)((std::uintptr_t)VariableStorage + 16), &myTitlePtr, sizeof(myTitlePtr), nullptr); // +16 = Title
		WriteProcessMemory(robloxInfo.hRoblox, (PVOID)((std::uintptr_t)VariableStorage + 24), &MessageBoxAPtr, sizeof(MessageBoxAPtr), nullptr); // +24 = Func to call

		// Since the stack GROWS down, popping the stack will actually raise the value of the stack pointer (which in this case reads the variable storage for us)
		*(std::uintptr_t*)(&shellcode[4]) = (std::uintptr_t)VariableStorage;
		WriteProcessMemory(robloxInfo.hRoblox, (PVOID)baseText, shellcode, sizeof(shellcode), nullptr); // Write the code payload for shellcode.

		ResumeThread(hThread);
	}

	CloseHandle(hThread);
}

void CallPrintFunction(roblox_t& robloxInfo) {
	std::uintptr_t baseText = (std::uintptr_t)robloxInfo.win32uBase + 0x1000;
	std::uintptr_t printFunction = (std::uintptr_t)robloxInfo.robloxBase + 0x12E0650;

	unsigned char shellcode[] = { 0x41, 0x57, 0x49, 0xBF, 0x22, 0x11, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x49, 0x87, 0xE7, 0x41, 0x5E, 0x5A, 0x58, 0x49, 0x87, 0xE7, 0x41, 0x5F, 0xB9, 0x01, 0x00, 0x00, 0x00, 0xEB, 0xFE, 0xFF, 0xD0, 0x41, 0xFF, 0xE6 };

	/*
		NOTE:
		I'VE DESIGNED THIS SHELLCODE TO TAKE AS LITTLE SPACE AS POSSIBLE, IF YOU HAVE ANY BETTER IDEAS GO AHEAD AND TRY THEM. EXCHANGING THE STACK CRASHES CE VEH DEBUGGER FYI.

		X64 CALLING CONVENTION: rcx, rdx, r8, r9, stack (right to left)
		PRINT FUNCTION: rcx (print number), rdx (text formatting), ... = format args

		SHELLCODE:
		push r15 ; Preserve r15
		mov r15, 0xAABBCCDDEEFF1122 ; Temporary hold stack
		xchg r15, rsp ; Swap stack
		pop r14 ; Pop real return address
		pop rdx ; Text argument
		pop rax ; Roblox print function
		xchg r15, rsp ; Restore stack
		pop r15 ; Restore r15

		mov ecx, 1
		call rax ; Call Roblox print
		jmp r14 ; Go back to original return value
	*/


	const char* myMessage = "HELLO I AM UNDETECTED. Written by the WRD community!";

	void* myMessagePtr = VirtualAllocEx(robloxInfo.hRoblox, 0, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); // Create message memory
	WriteProcessMemory(robloxInfo.hRoblox, myMessagePtr, myMessage, std::strlen(myMessage), nullptr); // Write our message into message memorys

	// Here is the injection logic
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, robloxInfo.tid);
	std::printf("HIJACKING THREAD: %d\n", robloxInfo.tid);

	DWORD result = SuspendThread(hThread);
	if (result == -1) {
		std::printf("Failed to suspend thread!\n");
	}
	else {
		std::printf("Thread suspend count: %d\n", result);

		CONTEXT threadCtx{};
		threadCtx.ContextFlags = CONTEXT_ALL;

		if (!GetThreadContext(hThread, &threadCtx)) {
			std::printf("Failed to get thread context!\n");
		}

		std::printf("Thread RIP: 0x%p|Thread RCX: 0x%p|Thread RDX: 0x%p\n", threadCtx.Rip, threadCtx.Rcx, threadCtx.Rdx);
		std::printf("DR0: 0x%p | DR1: 0x%p | DR2: 0x%p | DR3: 0x%p\n", threadCtx.Dr0, threadCtx.Dr1, threadCtx.Dr2, threadCtx.Dr3);

		// Retrieve old return value off stack (remember the thread is suspended so it has to have a return here)
		std::uintptr_t oldReturnValue = 0;
		ReadProcessMemory(robloxInfo.hRoblox, (PVOID)threadCtx.Rsp, &oldReturnValue, sizeof(oldReturnValue), nullptr);

		// Replace return to our hook
		WriteProcessMemory(robloxInfo.hRoblox, (PVOID)threadCtx.Rsp, &baseText, sizeof(baseText), nullptr);


		// We will store all the data our shellcode needs here in this custom stack space.
		// This allows us to pack the code tighter by storing some of the information in data such as pointers
		// On top of this if we use this storage as a stack we can turn an 8 byte moving a pointer into a register, into a 1 byte pop which saves a LOT of space.
		void* VariableStorage = VirtualAllocEx(robloxInfo.hRoblox, 0, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		WriteProcessMemory(robloxInfo.hRoblox, VariableStorage, &oldReturnValue, sizeof(oldReturnValue), nullptr); // +0 = Return
		WriteProcessMemory(robloxInfo.hRoblox, (PVOID)((std::uintptr_t)VariableStorage + 8), &myMessagePtr, sizeof(myMessagePtr), nullptr); // +8 = Message
		WriteProcessMemory(robloxInfo.hRoblox, (PVOID)((std::uintptr_t)VariableStorage + 16), &printFunction, sizeof(printFunction), nullptr); // +16 = Print function

		// Since the stack GROWS down, popping the stack will actually raise the value of the stack pointer (which in this case reads the variable storage for us)
		*(std::uintptr_t*)(&shellcode[4]) = (std::uintptr_t)VariableStorage;
		WriteProcessMemory(robloxInfo.hRoblox, (PVOID)baseText, shellcode, sizeof(shellcode), nullptr); // Write the code payload for shellcode.


		std::cin.get();
		ResumeThread(hThread);
	}

	CloseHandle(hThread);
}

int main()
{
	std::printf("LOADING UNDETECTED CHEAT V1.0!\n");
	roblox_t robloxInfo = GetRobloxHandle();

	if (IsInvalid(robloxInfo.hRoblox)) {
		std::printf("FUCK DETECTED.\n");
		return 0;
	}

	std::printf("ROBLOX PID: %d\n", robloxInfo.pid);

	if (!GetModuleBases(robloxInfo)) {
		std::printf("Failed to find addresses!\n");

		CloseHandle(robloxInfo.hRoblox);
		return 0;
	}

	std::printf("win32u.dll: 0x%p\n", robloxInfo.win32uBase);
	std::printf("RobloxPlayerBeta.exe: 0x%p\n", robloxInfo.robloxBase);

	CallPrintFunction(robloxInfo);


	// What happens if I whitelist memory inside win32u as executable, will it get flipped back even though its inside a signed module?
		// Well perhaps it does because it is being set externally, but what if the case were internally?

			// We are gonna fix the IP of this thread to run our payload, along with the args
		// WE MUST USE ALL NON VOLATILE REGISTERS BECAUSE OTHERWISE THEY WILL BE OVERWRITTEN.

	// Once a thread is paused we can access its context
	// PROBLEM:
	/*
		GAME WILL CRASH YOU IF YOU TRY TO USE SETTHREADCONTEXT.

		SOLUTION:
		SIMPLY JUST READ THE STACK, REPLACE IT ON THE STACK, AND THEN LET THEM RETURN TO YOU. LOOOOOOOOL
		Obviously no control over arguments, that's another problem.
		Can find stack frame with RBP
	*/
	/*
		METHOD:
		REPLACE RETURN TO REDIRECT STACK, THE THREAD IS SUSPENDED SO RETURN IS ON THE TOP.
		ONCE REDIRECTED WE WILL SUBTRACT STACK SPACE, WHICH WILL ESSENTIALLY GIVE US THAT RETURN BACK, AND DATA BELOW IT
		POP ALL OUR ARGS OFF THE STACK
		LITERALLY RETURN ON THE SAME RETURN.
		PROFIT?
	*/


	CloseHandle(robloxInfo.hRoblox);
	return 0;
}