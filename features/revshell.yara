import "pe"

// Detect capabilities of running reverse shell

rule win_revshell : feature networking windows
{
meta:
	description = "Imports Win reverse shell"



condition:
	// MZ at the beginning of file
        uint16be(0) == 0x4d5a and

	pe.imports("wsock32.dll","WSAStartup") and
	pe.imports("wsock32.dll","WSASocketA") and
	pe.imports("wsock32.dll","connect") and
	pe.imports("kernel32.dll","CreateProcessA")
}




