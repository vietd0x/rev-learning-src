# detect anti-debug by tracing WinAPI

Step1: Install [tinytracer](https://github.com/hasherezade/tiny_tracer) on your machine

Step2: Use this list below for hooking WindowAPI we concern in C:\pin\source\tools\tiny_tracer\install32_64\params.txt

```cpp
kernel32;LoadLibraryA;1
kernel32;LoadLibraryW;1

kernel32;GetProcAddress;2
advapi32;RegQueryValueW;3
kernel32;CreateFileW;6

kernel32;IsDebuggerPresent;0
kernel32;CheckRemoteDebuggerPresent;2
ntdll;NtQueryInformationProcess;5
ntdll;NtQuerySystemInformation;4
kernel32;GetProcessHeap;0
kernel32;HeapWalk;2

ntdll;CsrGetProcessId;0
kernel32;OpenProcess;3
kernel32;CreateFileA;6
kernel32;CreateFileW;6
ntdll;NtClose;1
kernel32;CloseHandle;1
ntdll;NtQueryObject;5

kernel32;SetUnhandledExceptionFilter;1
kernel32;RaiseException;4
ntdll;RtlAddVectoredExceptionHandler;2

kernel32;GetLocalTime;1
kernel32;GetSystemTime;1
kernel32;GetTickCount;0
kernel32;QueryPerformanceCounter;1

kernel32;VirtualProtect;4
kernel32;WriteProcessMemory;5
kernel32;GetThreadContext;2
ntdll;NtQueryVirtualMemory;6

kernel32;DebugBreak;0
user32;BlockInput;1
ntdll;NtSetInformationThread;4
user32;EnumWindows;2
user32;EnumThreadWindows;2
user32;GetWindowTextW;3
kernel32;SuspendThread;1
ntdll;NtSuspendThread;1
user32;CreateDesktopA;6
user32;SwitchDesktop;1
kernel32;OutputDebugString;1

user32;FindWindowW;2
user32;FindWindowA;2
user32;FindWindowExW;2
user32;FindWindowExA;2
ntdll;NtQueryInformationProcess;5
ntdll;NtSetDebugFilterState;3
```

Step3: Use this script to detect base on trace log

```python
import re

# example
log_file = "ConsoleApplication3.exe.tag"

apiName_rex = r"^([A-Z][a-z]+)([A-Z][a-z]*)*"
log_list = []
line_numb = 0

with open(log_file, 'r') as f:
    for line in f:
        line_numb += 1

        if(re.match(apiName_rex, line)):
            log_list.append({
                "line_numb": line_numb,
                "name": line[:-1], # ":" character
                "args": []})
            
        elif("Arg" in line):
            tmp = line.strip()[9:]
            if("ptr" == tmp[:3]):
                if ("{" in tmp): 
                    log_list[-1]["args"].append(tmp) 
                else: 
                    log_list[-1]["args"].append(tmp.split('"')[1])
            else: # get value arg
                log_list[-1]["args"].append(int(tmp.split(' ')[-1]))

# print(log_list)

timing_api = ["GetLocalTime", "GetSystemTime", "GetTickCount", "QueryPerformanceCounter"]
timing_api_cnt = 0
api_name_only = ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "DebugBreak", "BlockInput", "OutputDebugString", "NtSetDebugFilterState"]
api_name_list = []
for i in range(len(log_list)):
    api_name = log_list[i]["name"]
    api_name_list.append(api_name)

    if("LoadLibrary" in api_name):
        print(f"[+] {log_list[i]['args'][0]} is loaded")

    elif("GetProcAddress" in api_name):
        print(f"[+] Resolve address of {log_list[i]['args'][1]} by GetProcAddress")

    elif("QueryInformationProcess" in api_name):
        if(log_list[i]['args'][0] == 0xffffffff and log_list[i]['args'][1] == 7): # arg0 = -1 and arg1 = ProcessDbgPort
            print(f"[*] Detect anti-debug technique: Debug Flags_NtQueryInformationProcess_ProcessDebugPort")
        if(log_list[i]['args'][0] == 0xffffffff and log_list[i]['args'][1] == 0x1f): # arg0 = -1 and arg1 = ProcessDebugFlags
            print(f"[*] Detect anti-debug technique: Debug Flags_NtQueryInformationProcess_ProcessDebugFlags_NoDebugInherit")
        if(log_list[i]['args'][0] == 0xffffffff and log_list[i]['args'][1] == 0x1e): # arg0 = -1 and arg1 = ProcessDebugObjectHandle 
            print(f"[*] Detect anti-debug technique: Debug Flags_NtQueryInformationProcess_ProcessDebugObjectHandle")
        
    elif("QuerySystemInformation" in api_name and log_list[i]['args'][0] == 0x23):
        print(f"[*] Detect anti-debug technique: Debug Flags_NtQuerySystemInformation_SystemKernelDebuggerInformation")
    
    elif("CreateFile" in api_name):
        print(f"[+] CreateFile(arg0 = {log_list[i]['args'][0]}). Maybe anti-debug if it open path of current process")    

    elif("NtClose" in api_name or "CloseHandle" in api_name):
        print(f"[+] Maybe use invalid/fixed handle to raise EXCEPTION_INVALID_HANDLE")

    elif("NtQueryObject" in api_name and log_list[i]['args'][1] == 3):
        print(f"[*] Maybe anti-debug technique: objHandle_NtQueryObject")

    elif("RaiseException" in api_name and (log_list[i]['args'][0] == 0x40010005 or log_list[i]['args'][0] == 0x40010007)):
        #  DBC_CONTROL_C (0x40010005)
        #  DBG_RIPEVENT (0x40010007)
        print(f"[*] Detect anti-debug technique: RaiseException")

    elif("RtlAddVectoredExceptionHandler" in api_name):
        print(f"[*] Maybe register a vectored exception handler")

    elif(api_name in timing_api):
        timing_api_cnt += 1

    elif("WriteProcessMemory" in api_name and log_list[i]['args'][0] == 0xffffffff and '\xCC' in log_list[i]['args'][1]):
        print(f"[*] Detect anti-debug technique: processMem_WriteProcessMemory")

    elif("VirtualProtect" in api_name and log_list[i]['args'][2] == 0x140):
    # PAGE_EXECUTE_READWRIRE| PAGE_GUARD = 140h
        print(f"[*] Detect anti-debug technique: processMem_pageGuard")

    elif("GetThreadContext" in api_name and log_list[i]['args'][0] == 0xffffffff):
        print(f"[*] Detect anti-debug technique: processMem_hardwareBP")

    elif("QueryVirtualMemory" in api_name and log_list[i]['args'][0] == 0xffffffff and log_list[i]['args'][2] == 1):
    # arg0 = -1 and arg2 = ntdll::MemoryWorkingSetList
        print(f"[*] Detect anti-debug technique: processMem_NtQueryVirtualMemory_sharedPage")

    elif("SetInformationThread" in api_name and log_list[i]['args'][1] == 17):
    # ntdll::THREAD_INFORMATION_CLASS::ThreadHideFromDebugger = 17
        print(f"[*] Detect anti-debug technique: intertaction_NtCurrentThread_")

    elif("FindWindow" in api_name):
        print("[+] May be used to find Window class of debugger")

    elif("NtQueryInformationProcess" in api_name and log_list[i]['args'][1] == 0 and log_list[i]['args'][0] == 0xffffffff):
        # ProcessBasicInformation = 0,
        print(f"[*] Detect anti-debug technique: intertaction_NtQueryInformationProcess_PROCESS_BASIC_INFORMATION")

    elif(api_name in api_name_only):
        print(f"[*] {api_name}")

if("GetProcessHeap" in api_name_list and "HeapWalk" in api_name_list):
    print(f"[*] Maybe anti-debug technique: Debug Flags_Heap Protection")
if("CsrGetProcessId" in api_name_list and "OpenProcess" in api_name_list):
    print(f"[*] Maybe anti-debug technique: objHandle_openProcess_csrss")
if("SetUnhandledExceptionFilter" in api_name):
    print(f"[+] Maybe register a custom unhandled exception")
if(timing_api_cnt > 2):
    print(f"[+] Maybe anti-debug technique: timming")
if("Enum" in api_name_list and "SuspendThread" in api_name_list):
    print(f"[*] Detect anti-debug technique: intertaction_EnumWindows and SuspendThread")
if("SwitchDesktop" in api_name_list and "CreateDesktop" in api_name_list):
    print(f"[*] Detect anti-debug technique: intertaction_SwitchDesktop")
```