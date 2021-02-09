rule jsp_webshell_chopper_02: malware linux windows backdoor weblogic tomcat
{
    meta:
        author = "@h3x2b <tracker@h3x.eu>"
        description = "Detects variant 2 of JPS China Chopper backdoor"
	reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.chinachopper"
        // Check also:
        // Samples:

    strings:
        $chopper_02_01 = "EC(String s)"
        $chopper_02_02 = "showDatabases"
        $chopper_02_03 = "ExecuteCommandCode"
        $chopper_02_04 = "Runtime.getRuntime().exec"
        $chopper_02_05 = "executeSQL"
        $chopper_02_06 = "DeleteFileOrDirCode"
        $chopper_02_07 = "DownloadFileCode"
        $chopper_02_08 = "FileTreeCode"
        $chopper_02_09 = "WwwRootPathCode"

    condition:
        //<%@page import
        uint32be(0) == 0x3c254070 and

        //Contains all of the china chooper strings
        5 of ($chopper_02_*)
}

