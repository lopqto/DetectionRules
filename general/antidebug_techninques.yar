/*
    This Yara rule will check some of the most used debugger detection and anti-debug techniques.  
    This is a PoC for my upcoming project and shouldn't be used in production.
    Based on "The Art of Unpacking" by Mark Vincent Yason (https://www.blackhat.com/presentations/bh-usa-07/Yason/Whitepaper/bh-usa-07-yason-WP.pdf)
*/

import "pe"

rule Debugger_Detection_And_Anti_Debug_Techninques 
{
    meta:
		description = "unpack version of Gh0st rat (dll)"
		author = "lopqto https://lopqto.me"

    strings:

        $import1 = "IsDebuggerPresent" // PEB.BeingDebugged Flag

        $import2 = "RtlCreateHeap" // PEB.NtGlobalFlag, Heap Flags

        $import3 = "CheckRemoteDebuggerPresent" // DebugPort
        $import4 = "NtQueryInformationProcess"

        $opcode1 = { 0F 31 } // Timing Checks (RDTSC)

        $string1 = "csrss.exe" // SeDebugPrivilege

        $import5 = "GetCurrentProcessId" // Parent Process
        $import6 = "Process32First"
        $import7 = "Process32Next"
        $string2 = "explorer.exe"

        $import8 = "NtQueryObject" // DebugObject
        
        $import9 = "FindWindow" // Debugger Window
        $import10 = "FindWindowEX"

        $import11 = "Process32First" // Debugger Process
        $import12 = "Process32Next"
        $import13 = "ReadProcessMemory"

        $import14 = "NtSetInformationThread" // ThreadHideFromDebugger
        // $opcode2 = {11} commented due to slow down warning. uncomment to increase accuracy

        $import15 = "SetUnhandledExceptionFilter" // Unhandled Exception Filter

        $import16 = "DebugActiveProcess" // Debugger Blocker
        $import17 = "WaitForDebugEvent"
        $import18 = "DebugActiveProcessStop"


    condition:
        $import1 or // PEB.BeingDebugged Flag
        $import2 or // PEB.NtGlobalFlag, Heap Flags
        ($import3 and $import4) or // DebugPort
        $opcode1 or // Timing Checks (RDTSC)
        $string1 or // SeDebugPrivilege
        ($import5 and $import6 and $import7 and $string2) or // Parent Process
        $import8 or // DebugObject
        ($import9 and $import10) or // Debugger Window
        ($import11 and $import12 and $import13) or // Debugger Process
        $import14 or // ThreadHideFromDebugger
        $import15 or // Unhandled Exception Filter
        ($import16 and $import17 and $import18) // Debugger Blocker
}