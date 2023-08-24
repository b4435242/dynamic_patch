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
//#include <Python.h>


LPVOID virtualTextBaseAddress, staticTextBaseAddress, angrTextBaseAddress;
char* exe_path;

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
                //break;
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

LPVOID GetVirtualAddrFromStatic(char* addrInChar){
    unsigned long long hex_value = strtoull(addrInChar, NULL, 16);
    LPVOID addr = (LPVOID)hex_value;

    ptrdiff_t offset = reinterpret_cast<char*>(addr) - reinterpret_cast<char*>(staticTextBaseAddress);    
    return reinterpret_cast<LPVOID>(reinterpret_cast<char*>(virtualTextBaseAddress) + offset);
}

LPVOID GetVirtualAddrFromAngr(const char* addrInChar){
    unsigned long long hex_value = strtoull(addrInChar, NULL, 16);
    LPVOID addr = (LPVOID)hex_value;

    ptrdiff_t offset = reinterpret_cast<char*>(addr) - reinterpret_cast<char*>(angrTextBaseAddress);    
    return reinterpret_cast<LPVOID>(reinterpret_cast<char*>(virtualTextBaseAddress) + offset - 0x1000); // recover offset by minus 0x1000 back
}

LPVOID GetAngrAddrFromVirtual(LPVOID addr){
    //unsigned long long hex_value = strtoull(addrInChar, NULL, 16);
    //LPVOID addr = (LPVOID)hex_value;

    ptrdiff_t offset = reinterpret_cast<char*>(addr) - reinterpret_cast<char*>(virtualTextBaseAddress);    
    return reinterpret_cast<LPVOID>(reinterpret_cast<char*>(angrTextBaseAddress) + offset + 0x1000); // text offset is 0x1000 // 0x1000 for angr offset to locate right libc
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
    DWORD_PTR stack_bottom = ctx->Rbp + 0x1010 + 0x10; // nginx offset and rbp/rip offset // Not sure why $rbp doesn't point at bottom 
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

void dump_memory(HANDLE& hProcess, LPVOID var_addr, long long unsigned int var_size){
    std::ofstream file("concrete_input");

    DWORD_PTR stack_top = reinterpret_cast<DWORD_PTR>(var_addr);
    DWORD_PTR stack_bottom = stack_top+reinterpret_cast<DWORD_PTR>(var_size);
    std::cout << "var start" <<"   0x" << std::hex << stack_top << ", end " <<"   0x" << std::hex << stack_bottom <<std::endl;

    for (DWORD_PTR i = stack_top; i < stack_bottom; i += 8)
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


bool detect_overflow(LPVOID start_addr, LPVOID end_addr, LPVOID base_addr, std::string &mode, LPVOID& vulnerable_virtual_addr, LPVOID& key_variable_virtual_addr){
    /*char py_path[] = "overflow_detect.py";
    char stack_path[] = "stack";
    char regs_path[] = "registers";
    char start_addr_str[18], end_addr_str[18], base_addr_str[18];

    sprintf(start_addr_str, "0x%p", start_addr);
    sprintf(end_addr_str, "0x%p", end_addr);
    sprintf(base_addr_str, "0x%p", base_addr);

    int argc = 7;
    char* argv[7];

    argv[0] = py_path;
    argv[1] = exe_path;
    argv[2] = regs_path;
    argv[3] = stack_path;
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
    FILE* fp = fopen(py_path, "r");
    PyRun_SimpleFile(fp, py_path);
    fclose(fp);
    Py_Finalize();
    */
    char start_addr_str[18], end_addr_str[18], base_addr_str[18];

    sprintf(start_addr_str, "0x%p", start_addr);
    sprintf(end_addr_str, "0x%p", end_addr);
    sprintf(base_addr_str, "0x%p", base_addr);

    std::string cmd;
    cmd += "python overflow_detect.py ";
    cmd += std::string(exe_path) + " ";
    cmd += "registers ";
    cmd += "stack ";
    cmd += std::string(start_addr_str) + " ";
    cmd += std::string(end_addr_str) + " ";
    cmd += std::string(base_addr_str) + " ";
    int result = system(cmd.c_str());
    std::cout << cmd << ", ret =" << result << std::endl;
    // Return analysis by reading file //
    std::ifstream file("analysis"); 
    std::string line[4];
    for (int i=0; i<4; i++)
        std::getline(file, line[i]);

    bool is_overflowed = (line[0]=="True");
    vulnerable_virtual_addr = GetVirtualAddrFromAngr(line[1].c_str()); // only instruction addr needs conversion
    mode = line[2];
    unsigned long long hex_value = strtoull(line[3].c_str(), NULL, 16);
    key_variable_virtual_addr = (LPVOID)hex_value;
    std::cout << "key_variable_virtual_addr" <<key_variable_virtual_addr<<std::endl;

    return is_overflowed;
}

bool check_overflow_satisfiability(){
    /*char py_path[] = "check_satisfiability.py";

    int argc = 2;
    char* argv[2];
    argv[0] = py_path;
    argv[1] = exe_path;

    wchar_t **changed_argv;
    changed_argv = new wchar_t*[argc];

    for (int i = 0; i < argc; i++)
    {
        changed_argv[i] = new wchar_t[strlen(argv[i]) + 1];
        mbstowcs(changed_argv[i], argv[i], strlen(argv[i]) + 1);
    }


    Py_Initialize();
    PySys_SetArgv(argc, changed_argv);
    FILE* fp = fopen(py_path, "r");
    PyRun_SimpleFile(fp, py_path);
    fclose(fp);
    Py_Finalize();*/
    std::string cmd;
    cmd += "python check_satisfiability.py ";
    cmd += std::string(exe_path);
    int result = system(cmd.c_str());
    std::cout<< cmd << ", ret ="<<result<<std::endl;

    std::ifstream file("satisfiabililty"); 
    std::string line;
    std::getline(file, line);
    bool is_triggered = (line=="True");
    return is_triggered;
}


int main(int argc, char** argv)
{
	char* process_name = argv[1];
    exe_path = argv[2]; // global
    char* start_addr = argv[3];
    char* end_addr = argv[4];
    char* err_handling_addr = argv[5];


	DWORD pid = GetProcessIdByName(std::string(process_name));
	printf("pid = %d\n", pid);

    // Set base addresses for conversion //
    angrTextBaseAddress = reinterpret_cast<LPVOID>(0x100400000); //0x400000
    virtualTextBaseAddress = GetVirtualTextSectionBaseAddress(pid);
    staticTextBaseAddress = GetStaticTextSectionBaseAddress(exe_path);
    std::cout << "angrTextBaseAddress" << angrTextBaseAddress << std::endl;
    std::cout << "virtualTextBaseAddress" << virtualTextBaseAddress << std::endl;
    std::cout << "staticTextBaseAddress" << staticTextBaseAddress << std::endl;

    // Convert static to virtual address //
    LPVOID suspicious_begin_virtual_addr = GetVirtualAddrFromStatic(start_addr);
    LPVOID suspicious_end_virtual_addr = GetVirtualAddrFromStatic(end_addr);
    LPVOID err_handling_virtual_addr = GetVirtualAddrFromStatic(err_handling_addr);
    
    
 
    DEBUG_EVENT debugEvent;
    HANDLE hThread;
    CONTEXT ctx;
    char originalJmpBytes[5]; // buffer of original 5 bytes for jmp 
    BYTE originalBpBytes[3]; // 0 for suspicious start address, 1 for vulnerable address, 2 for err handling
    // result of analysis //
    LPVOID vulnerable_virtual_addr, key_variable_virtual_addr; 
    std::string mode;

    // Attach to the target process //
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL) {
        printf("Failed to attach to process\n");
        return 1;
    }
    
    if (!DebugActiveProcess(pid)) {
        printf("Failed to debug to process\n");
        return 1;
    }

    // First setup breakpoint on suspicious point //
    BYTE breakpoint_opcode = 0xCC;
    if (!ReadProcessMemory(hProcess, suspicious_begin_virtual_addr, &originalBpBytes[0], 1, NULL)) { // Save the original byte for recovering
        printf("Failed to read process memory, error code %d\n", GetLastError());
        CloseHandle(hProcess);
    }
    if (!WriteProcessMemory(hProcess, suspicious_begin_virtual_addr, &breakpoint_opcode, 1, NULL)) { // Replace byte with a bp opcode, 0xCC
        printf("Failed to set breakpoint\n");
        CloseHandle(hProcess);
    }

    // 1. Run overflow detection once //
    // 2. Run overflow triggered infinite times if finding a vulnerability in 1. //
    while (true) {
        
        if (!WaitForDebugEvent(&debugEvent, INFINITE)) {
            std::cerr << "WaitForDebugEvent failed" << std::endl;
            CloseHandle(hProcess);
            return 1;
        }
        //std::cout << "code " << debugEvent.dwDebugEventCode  <<std::endl;
        if (debugEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT){
            hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, debugEvent.dwThreadId);

            if (debugEvent.u.Exception.ExceptionRecord.ExceptionCode==EXCEPTION_BREAKPOINT) {
                ctx.ContextFlags = CONTEXT_ALL;
                if (!GetThreadContext(hThread, &ctx)) { // Get the thread context      
                    std::cerr << "Failed to get thread context. Error: " << GetLastError() << std::endl;
                    return 1;
                }
                ctx.Rip = (DWORD_PTR)debugEvent.u.Exception.ExceptionRecord.ExceptionAddress; 


                if (debugEvent.u.Exception.ExceptionRecord.ExceptionAddress == suspicious_begin_virtual_addr) {
                    
                    if (!WriteProcessMemory(hProcess, suspicious_begin_virtual_addr, &originalBpBytes[0], 1, NULL)) { // Restore the original byte
                        printf("Failed to restore original byte, error code %d\n", GetLastError());
                        CloseHandle(hProcess);
                    }
                                          
                    std::cout<<"[sus bp] hit"<<std::endl;
                    dump_registers(&ctx); // prepare for env of symbolic execution
                    dump_stack(&ctx, hProcess);

                    bool is_vulnerable = detect_overflow( 
                        GetAngrAddrFromVirtual(suspicious_begin_virtual_addr), GetAngrAddrFromVirtual(suspicious_end_virtual_addr), angrTextBaseAddress,  // args
                        mode, vulnerable_virtual_addr, key_variable_virtual_addr); // results
                    std::cout << "[detect overflow]vulnerable= "<< is_vulnerable << ", vulnerable_virtual_addr= " << vulnerable_virtual_addr << std::endl;
                    if (is_vulnerable){ // check if overflow will be triggered on vulnerable addr when vulnerability is detected 
                        
                        // Set bp on vulnerable_addr // 
                        if (!ReadProcessMemory(hProcess, vulnerable_virtual_addr, &originalBpBytes[1], 1, NULL)) {
                            printf("Failed to read process memory, error code %d\n", GetLastError());
                            CloseHandle(hProcess);
                        }

                        if (!WriteProcessMemory(hProcess, vulnerable_virtual_addr, &breakpoint_opcode, 1, NULL)) {
                            printf("Failed to set breakpoint\n");
                            CloseHandle(hProcess);
                        }
                    }
                    
                } else if (debugEvent.u.Exception.ExceptionRecord.ExceptionAddress == vulnerable_virtual_addr){
                    std::cout<<"bp hitted on vul addr" << std::endl;
                    // Set bp on vulnerable address infinitely //
                    if (!WriteProcessMemory(hProcess, vulnerable_virtual_addr, &originalBpBytes[1], 1, NULL)) { // Restore the original byte
                        printf("Failed to restore original byte, error code %d\n", GetLastError());
                        CloseHandle(hProcess);
                    }
                    ctx.EFlags |= 0x100; // set step mode
                    

                    if (mode=="continuous")
                        dump_memory(hProcess, key_variable_virtual_addr, 256); // stdin_buf_size=256, which supposes largest len of stdin is 256
                    else if (mode=="size")
                        dump_memory(hProcess, key_variable_virtual_addr, 8);  // suppose type of size is size_t, unsigned long long 

                    bool is_triggered = check_overflow_satisfiability();

                    std::cout<<"is_triggered " <<is_triggered<<std::endl;
                    if (is_triggered){
                        // Set bp on err handler
                        if (!ReadProcessMemory(hProcess, err_handling_virtual_addr, &originalBpBytes[2], 1, NULL)) { 
                            printf("Failed to read process memory, error code %d\n", GetLastError());
                            CloseHandle(hProcess);
                        }
                        if (!WriteProcessMemory(hProcess, err_handling_virtual_addr, &breakpoint_opcode, 1, NULL)) { 
                            printf("Failed to set breakpoint\n");
                            CloseHandle(hProcess);
                        }
                        // Redirect to err handler by hooking //                            
                        char patch[5]; // 5 bytes of jmp op + offset
                        auto src = reinterpret_cast<char*>(vulnerable_virtual_addr) + 5; 
                        auto dst = reinterpret_cast<char*>(err_handling_virtual_addr);
                        DWORD* relative_offset = (DWORD*)(dst-src); 
                        memcpy(patch, "\xE9", 1); // jmp opcode
                        memcpy(patch + 1, &relative_offset, 4);
                        ReadProcessMemory(hProcess, vulnerable_virtual_addr, originalJmpBytes, 5, NULL); // save the first 5 bytes
                        WriteProcessMemory(hProcess, (LPVOID)vulnerable_virtual_addr, patch, 5, NULL); // overwrite the first 5 bytes with a jump to err
                    }

                } else if (debugEvent.u.Exception.ExceptionRecord.ExceptionAddress == err_handling_virtual_addr){
                    std::cout<<"[err handler] bp hitted " <<std::endl;
                    WriteProcessMemory(hProcess, (LPVOID)vulnerable_virtual_addr, &originalJmpBytes, 5, NULL); // unhook to avoid infinite triggering
                    WriteProcessMemory(hProcess, err_handling_virtual_addr, &originalBpBytes[2], 1, NULL); // cancel bp
                    
                }
                // Reset rip to exception address after hitting bp//
                if (!SetThreadContext(hThread, &ctx)) { // Set the modified context
                    printf("SetThreadContext failed, error code %d\n", GetLastError());
                    return 1;
                }
            } else if (debugEvent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP){ // Trigger bp on vulnerable addr infinitely                    
                std::cout << "single step" << std::endl;
                if (!WriteProcessMemory(hProcess, vulnerable_virtual_addr, &breakpoint_opcode, 1, NULL)) { // reset bp
                    printf("Failed to set breakpoint\n");
                    CloseHandle(hProcess);
                }
                                
                // Cancel step mode to keep process running // 
                CONTEXT ctx;
                ctx.ContextFlags = CONTEXT_ALL;
                if (!GetThreadContext(hThread, &ctx)) { // Get the thread context
                    std::cerr << "Failed to get thread context. Error: " << GetLastError() << std::endl;
                    return 1;
                }
                ctx.EFlags &= ~0x100;  // turn off single step
                if (!SetThreadContext(hThread, &ctx))
                {
                    printf("Failed to set thread context, error code %d\n", GetLastError());
                    return 1;
                }
            } else {
                // Handle other exception types
                //std::cout<<"exception code ="<< debugEvent.u.Exception.ExceptionRecord.ExceptionCode << std::endl;
            }  
            
                 
        }
        ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
        
    }




    DebugActiveProcessStop(pid);
    CloseHandle(hProcess);
    return 0;
}