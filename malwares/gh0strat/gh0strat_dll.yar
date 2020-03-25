// password for sample: infected

import "pe"

rule is_dll
{
	condition:
		pe.characteristics & pe.DLL 
}

rule Gh0st : rat
{
	meta:
		desciption = "unpack version of Gh0st rat (dll)"
		author = "lopqto https://lopqto.me"

	strings:
		$capability1 = "CreateRemoteThread" // attaching to remote process
		$capability2 = "OpenSCManagerA" // managing services (create / delete / enum)
		$capability3 = "ClearEventLogA" // managing windows event logs
		$capability4 = "AbortSystemShutdownA" // restarting and shut downing system
		$capability5 = "AttachConsole" // interacting with remote process
		$capability6 = "CreateMutexA" 
		$capability7 = "Process32Next" // process enumeration
		$capability8 = "NetUserAdd" // user management
		$capability9 = "GetClipboardData" // clipboard read & write
		$capability10 = "GetAsyncKeyState" //keylogging
		$capability11 = "InternetReadFile" // internet functionality
		$capability12 = "HttpSendRequestA" // c&c over http
		$string1 = "/c ping -n 2 127.0.0.1 > nul && del" // self delete

	condition:
		all of them
}