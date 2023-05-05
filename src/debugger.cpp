#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>
#include <iostream>
#include <string>
#include <fstream>
#include <psapi.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <Python.h>
#include <unordered_map>

std::unordered_map<LPVOID, BYTE> originalByteMap;



DWORD GetProcessIdByName(const std::string processName)
{
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return 0;

    DWORD pid = 0;
    if (Process32First(hSnapshot, &pe32))
    {
        do
        {
            if (pe32.szExeFile == processName)
            {
                pid = pe32.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return pid;
}
// Function to get the base address of the text section of an executable file
LPVOID GetStaticTextSectionBaseAddress(const char* filePath)
{
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "objdump -h %s", filePath);

    // Execute the objdump command and capture its output
    FILE* fp = popen(cmd, "r");
    if (!fp)
        return nullptr;
    

    char line[512];
    while (fgets(line, sizeof(line), fp))
    {
        // Find the line that describes the text section
        if (strstr(line, ".text"))
        {
            // Parse the line to get the base address
            char* addressStr = strtok(line, " ");
            for (int i = 0; i < 4; i++)
            {
                addressStr = strtok(nullptr, " ");
            }
            LPVOID baseAddress = (LPVOID)strtoull(addressStr, nullptr, 16);

            pclose(fp);
            return baseAddress;
        }
    }

    pclose(fp);
    return nullptr;
}

// Function to get the base address of the text section of a given process
LPVOID GetVirtualTextSectionBaseAddress(DWORD processId)
{
    /*static LPVOID baseAddress = 0;
    if (!baseAddress)
        return baseAddress;*/
    LPVOID baseAddress = 0;

    // Open a handle to the target process
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (!hProcess)
    {
        return nullptr;
    }

    // Start at the lowest address of the process's virtual address space
    LPVOID lpAddress = nullptr;

    // Loop until VirtualQueryEx returns zero (indicating the end of the process's address space)
    while (true)
    {
        // Structure to hold information about the next page in the process's virtual address space
        MEMORY_BASIC_INFORMATION mbi;

        // Call VirtualQueryEx to get information about the next page in the process's virtual address space
        SIZE_T dwSize = VirtualQueryEx(hProcess, lpAddress, &mbi, sizeof(mbi));
        if (dwSize == 0)
        {
            // End of process's address space
            break;
        }

        // If the current page is in the text section, return its base address
        if ((mbi.State & MEM_COMMIT) && (mbi.Protect & PAGE_EXECUTE_READ) && (mbi.Type & MEM_IMAGE))
        {
            return baseAddress = mbi.BaseAddress;
        }

        // Move lpAddress to the next page in the process's virtual address space
        lpAddress = (LPBYTE)mbi.BaseAddress + mbi.RegionSize;
    }

    // Close the handle to the target process
    CloseHandle(hProcess);

    return nullptr;
}

LPVOID GetVirtualAddress(DWORD processId, const char* exePath, char* staticAddressChar)
{
    // Get the base address of the text section of the process
    /*static LPVOID textVirtualAddress = nullptr;
    if (!textVirtualAddress)
        textVirtualAddress = GetVirtualTextSectionBaseAddress(processId);
    if (!textVirtualAddress)
        return nullptr;
    static LPVOID textStaticAddress = nullptr;
    if (!textVirtualAddress)
        textStaticAddress = GetStaticTextSectionBaseAddress(exePath);
    if (!textStaticAddress)
        return nullptr;*/

    unsigned long long hex_value = strtoull(staticAddressChar, NULL, 16);
    LPVOID staticAddress = (LPVOID)hex_value;


    LPVOID textVirtualAddress = GetVirtualTextSectionBaseAddress(processId);
    LPVOID textStaticAddress = GetStaticTextSectionBaseAddress(exePath);
    std::cout<<"virtual base=" << textVirtualAddress << std::endl;
    std::cout<<"static base=" << textStaticAddress << std::endl;
    std::cout<<"static addr=" << staticAddress << std::endl;
    

    // Calculate the offset from the static address to the base address of the text section
    ptrdiff_t offset = reinterpret_cast<char*>(staticAddress) - reinterpret_cast<char*>(textStaticAddress);
    std::cout<<"offset=" << offset << std::endl;
    // Return the virtual address of the static address
    return reinterpret_cast<LPVOID>(reinterpret_cast<char*>(textVirtualAddress) + offset);
}

void dump_registers(CONTEXT* ctx) {
    std::ofstream file("registers");

    if (file.is_open()) {
        file << "RAX: 0x" << std::hex << ctx->Rax << "\n";
        file << "RBX: 0x" << std::hex << ctx->Rbx << "\n";
        file << "RCX: 0x" << std::hex << ctx->Rcx << "\n";
        file << "RDX: 0x" << std::hex << ctx->Rdx << "\n";
        file << "R8:  0x" << std::hex << ctx->R8 << "\n";
        file << "R9:  0x" << std::hex << ctx->R9 << "\n";
        file << "R10: 0x" << std::hex << ctx->R10 << "\n";
        file << "R11: 0x" << std::hex << ctx->R11 << "\n";
        file << "R12: 0x" << std::hex << ctx->R12 << "\n";
        file << "R13: 0x" << std::hex << ctx->R13 << "\n";
        file << "R14: 0x" << std::hex << ctx->R14 << "\n";
        file << "R15: 0x" << std::hex << ctx->R15 << "\n";
        file << "RDI: 0x" << std::hex << ctx->Rdi << "\n";
        file << "RSI: 0x" << std::hex << ctx->Rsi << "\n";
        file << "RBP: 0x" << std::hex << ctx->Rbp << "\n";
        file << "RSP: 0x" << std::hex << ctx->Rsp << "\n";
        file << "RIP: 0x" << std::hex << ctx->Rip << "\n";
        file << "EFLAGS: 0x" << std::hex << ctx->EFlags << "\n";

        file.close();
    }
}

void dump_stack(CONTEXT* ctx, HANDLE& hProcess)
{
    std::ofstream file("stack");

    DWORD_PTR stack_top = ctx->Rsp;
    DWORD_PTR stack_bottom = ctx->Rbp + 0x100;
    std::cout << "sp " << stack_top << ", fp " << stack_bottom <<std::endl;

    for (DWORD_PTR i = stack_top; i <= stack_bottom; i += 8)
    {
        DWORD_PTR value;
        if (!ReadProcessMemory(hProcess, (LPCVOID)i, &value, sizeof(DWORD_PTR), NULL))
        {
            file << " 0x" << std::hex << i << "   Error reading memory\n";
            continue;
        }
        file << " 0x" << std::hex << i << "   0x" << std::hex << value << "\n";
    }

    file.close();
}


int get_stdin(char* buffer, const int BUFFER_SIZE){

    memset(buffer, 0 , BUFFER_SIZE);

    // Get the handle of the standard input file for the process
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    if (hStdin == INVALID_HANDLE_VALUE) {
        printf("Failed to get handle to stdin, error code %d\n", GetLastError());
        return 1;
    }

    DWORD bytesRead;
    if (!ReadFile(hStdin, buffer, BUFFER_SIZE, &bytesRead, NULL)) {
        printf("Failed to read stdin, error code %d\n", GetLastError());
        return 1;
    }

    // Output the content of stdin
    printf("Stdin content:\n%s", buffer);
}

void run_angr(char* exePath, LPVOID start_addr, LPVOID end_addr, LPVOID base_addr){
    char pypath[] = "overflow_detect.py";
    char stackpath[] = "stack";
    char regspath[] = "registers";
    char start_addr_str[18], end_addr_str[18], base_addr_str[18];

    sprintf(start_addr_str, "0x%p", start_addr);
    sprintf(end_addr_str, "0x%p", end_addr);
    sprintf(base_addr_str, "0x%p", base_addr);

    FILE* fp;
    int argc = 7;
    char* argv[7];

    argv[0] = pypath;
    argv[1] = exePath;
    argv[2] = regspath;
    argv[3] = stackpath;
    argv[4] = start_addr_str;
    argv[5] = end_addr_str;
    argv[6] = base_addr_str;

    wchar_t **changed_argv;
    changed_argv = new wchar_t*[argc];

    for (int i = 0; i < argc; i++)
    {
        changed_argv[i] = new wchar_t[strlen(argv[i]) + 1];
        mbstowcs(changed_argv[i], argv[i], strlen(argv[i]) + 1);
    }


    Py_Initialize();
    //FILE* python_stdout = fopen("python_stdout.txt", "w");
    //PySys_SetObject("stdout", PyFile_FromFd(fileno(python_stdout), "python_stdout.txt", "w", -1, NULL, NULL, NULL, 1));


    PySys_SetArgv(argc, changed_argv);
    fp = fopen(pypath, "r");
    PyRun_SimpleFile(fp, pypath);

    Py_Finalize();
}

int resume(DEBUG_EVENT &debugEvent, HANDLE &hThread, const DWORD_PTR exceptionAddress, bool step_mode){
    // Get the CONTEXT of the current thread
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(hThread, &ctx)) {
        printf("GetThreadContext failed, error code %d\n", GetLastError());
        return 1;
    }
    
    
    ctx.Rip = (DWORD_PTR)exceptionAddress;
    if (step_mode)
        ctx.EFlags |= 0x100;

    // Set the modified context
    if (!SetThreadContext(hThread, &ctx)) {
        printf("SetThreadContext failed, error code %d\n", GetLastError());
        return 1;
    }

    // Continue the debugged process
    if (!ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE)) {
        printf("ContinueDebugEvent failed, error code %d\n", GetLastError());
        return 1;
    }
    return 0;
}

void set_bp(HANDLE& hProcess, LPVOID address){
    // Read the original byte at the target address
    BYTE originalByte = 0;
    if (!ReadProcessMemory(hProcess, address, &originalByte, sizeof(originalByte), NULL)) {
        printf("Failed to read process memory, error code %d\n", GetLastError());
        CloseHandle(hProcess);
        
    }

    // Set a breakpoint at the target address
    // replace with the target address
    BYTE breakpoint_opcode = 0xCC;
    if (!WriteProcessMemory(hProcess, address, &breakpoint_opcode, 1, NULL)) {
        printf("Failed to set breakpoint\n");
        CloseHandle(hProcess);
        
    }
    originalByteMap[address] = originalByte;
}

void unset_bp(HANDLE& hProcess, LPVOID address) {
    BYTE originalByte = originalByteMap[address];
    // Restore the original byte at the breakpoint address
    if (!WriteProcessMemory(hProcess, address, &originalByte, sizeof(originalByte), NULL)) {
        printf("Failed to restore original byte, error code %d\n", GetLastError());
        CloseHandle(hProcess);
    }
}

void hook_function(HANDLE& hProcess, LPVOID current_addr, LPVOID hooked_address, char *saved_buffer){
    char patch[5]= {0};

    // 2. save the first 5 bytes into saved_buffer
    ReadProcessMemory(hProcess, current_addr, saved_buffer, 5, NULL);

    // 3. overwrite the first 5 bytes with a jump to proxy_function
    auto src = reinterpret_cast<char*>(current_addr) + 5; 
    auto dst = reinterpret_cast<char*>(hooked_address);
    DWORD* relative_offset = (DWORD*)(dst-src); 
    memcpy(patch, "\xE9", 1);
    memcpy(patch + 1, &relative_offset, 4);
    WriteProcessMemory(hProcess, (LPVOID)current_addr, patch, 5, NULL);

    // set bp at err handling function
    set_bp(hProcess, hooked_address);
}

void unhook_function(HANDLE& hProcess, LPVOID hooked_address, char *saved_buffer){
    // unhook the function (re-write the saved buffer) to prevent infinite recursion
    WriteProcessMemory(hProcess, (LPVOID)hooked_address, saved_buffer, 5, NULL);
}

void get_thread(DEBUG_EVENT &debugEvent, HANDLE &hThread){
    // Get the thread handle from the debug event
    hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, debugEvent.dwThreadId);
    if (!hThread) {
        std::cerr << "Failed to get thread handle. Error: " << GetLastError() << std::endl;
    }

}

int main(int argc, char** argv)
{
    printf("come\n");
	char* process_name = argv[1];
    char* exePath = argv[2];
    char* start_addr = argv[3];
    char* end_addr = argv[4];
    char* err_handling_addr = argv[5];


	DWORD pid = GetProcessIdByName(std::string(process_name));
	printf("pid = %d\n", pid);

	
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL) {
        printf("Failed to attach to process\n");
        return 1;
    }
    

    // Attach to the target process
    if (!DebugActiveProcess(pid)) {
        printf("Failed to debug to process\n");
        return 1;
    }
    
    // virtual address
    LPVOID address = GetVirtualAddress(pid, exePath, start_addr);
    LPVOID endAddress = GetVirtualAddress(pid, exePath, end_addr);
    LPVOID baseAddress = GetVirtualTextSectionBaseAddress(pid); 
    LPVOID errHandlingAddress = GetVirtualAddress(pid, exePath, err_handling_addr);

    std::cout<<"virtual address"<< address << std::endl;


    // Read the original byte at the target address
    set_bp(hProcess, address);

    // Create a buffer to hold the input data
    const int BUFFER_SIZE = 1024;
    char buffer[BUFFER_SIZE];

   // Wait for the breakpoint to trigger
    DEBUG_EVENT debugEvent;
    // buffer of original 5 bytes for jmp 
    char originalJmpBytes[5];
    while (true) {
        
        if (!WaitForDebugEvent(&debugEvent, INFINITE)) {
            std::cerr << "WaitForDebugEvent failed" << std::endl;
            CloseHandle(hProcess);
            return 1;
        }
        if (debugEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT){
            switch (debugEvent.u.Exception.ExceptionRecord.ExceptionCode) {
                
                case EXCEPTION_BREAKPOINT:
                    
                    if (debugEvent.u.Exception.ExceptionRecord.ExceptionAddress == address) {
                        
                        // Restore the original byte at the breakpoint address
                        unset_bp(hProcess, address);

                        HANDLE hThread;
                        get_thread(debugEvent, hThread);

                        // Get the thread context                            
                        CONTEXT ctx;
                        ctx.ContextFlags = CONTEXT_ALL;
                        if (!GetThreadContext(hThread, &ctx)) {
                            std::cerr << "Failed to get thread context. Error: " << GetLastError() << std::endl;
                            return 1;
                        }

                        dump_registers(&ctx);
                        dump_stack(&ctx, hProcess);
                        
                        //get_stdin(buffer, BUFFER_SIZE);
                        //run_angr(exePath, address, endAddress, baseAddress); 

                        set_bp(hProcess, errHandlingAddress);
                        hook_function(hProcess, address, errHandlingAddress, originalJmpBytes);

                        bool step_flag = true;
                        const DWORD_PTR dwExceptionAddress = (DWORD_PTR)debugEvent.u.Exception.ExceptionRecord.ExceptionAddress;
                        resume(debugEvent, hThread, dwExceptionAddress, step_flag);
                    } else if (debugEvent.u.Exception.ExceptionRecord.ExceptionAddress == errHandlingAddress){
                        
                        unhook_function(hProcess, errHandlingAddress, originalJmpBytes);
                        unset_bp(hProcess, errHandlingAddress);

                        HANDLE hThread;
                        get_thread(debugEvent, hThread);
                        bool step_flag = false;
                        const DWORD_PTR dwExceptionAddress = (DWORD_PTR)debugEvent.u.Exception.ExceptionRecord.ExceptionAddress;
                        resume(debugEvent, hThread, dwExceptionAddress, step_flag);
                    }

                    break;
                case EXCEPTION_SINGLE_STEP:
                    // Set a breakpoint at the target address
                    // replace with the target address
                    
                
                    set_bp(hProcess, address);
                    
                    HANDLE hThread;
                    get_thread(debugEvent, hThread);

                    // Get the thread context
                    CONTEXT ctx;
                    ctx.ContextFlags = CONTEXT_ALL;
                    if (!GetThreadContext(hThread, &ctx)) {
                        std::cerr << "Failed to get thread context. Error: " << GetLastError() << std::endl;
                        return 1;
                    }
                    ctx.EFlags &= ~0x100;  // turn off single step
                    if (!SetThreadContext(hThread, &ctx))
                    {
                        printf("Failed to set thread context, error code %d\n", GetLastError());
                        return 1;
                    }
                    ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
                    break;
                default:
                    // Handle other exception types
                    std::cout<<"exception code ="<< debugEvent.u.Exception.ExceptionRecord.ExceptionCode << std::endl;
                    ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
                    break;      
            }     
        }
        else{
            ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
        }
    }




    DebugActiveProcessStop(pid);
    CloseHandle(hProcess);
    return 0;
}