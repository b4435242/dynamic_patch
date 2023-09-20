# Dynamic Patch

## Intro
Prevent from a known stack buffer overflow attack to become RCE. Reproduce the path of crash in Angr, and get the condition of it to prevent attack. Debugger is for breakpoint, context dump, and memory operation of target process. Python is to analyze vulnerability with Angr.  
**Analysis of vulnerability will be needed to apply this tool.**  


## Usage
Attach vulnerable process with defense tool  
`debugger.exe [bof_bin] [bof_func] [hook_len] [exe_name] [exe_path] [dll_name] [dll_path] [start_addr] [end_addr] [err_handling_addr]`  
[bof_bin] stands for the kind of binary that has buffer overflow vulnerability, which is either "exe" or "dll".  
[bof_func] stands for the library call that causes buffer overflow. Currently support "gets", "recv", "sprintf".  
[hook_len] is byte length of instruction that calls [bof_func] in vulnerable function.  
[exe_name] is the name of vulnerable application.  
[exe_path] is the path of vulnerable application.  
[dll_name] is the name of vulnerable module. If vulnerability is in application, just type "none".  
[dll_path]is the path of vulnerable module. If vulnerability is in application, just type "none".  
[start_addr] is static address of instruction that calls [bof_func] in vulnerable binary.  
[end_addr] is static address of ret instruction in vulnerable function.   
[err_handling_addr] is static address of error handler in application.  

delete tmp directory first before calling debugger, tmp is used to check if constraints solved

## Platform
Windows only