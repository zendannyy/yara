rule MAL_BURNTCIGAR_Strings
{

    meta:
        Description = "Rule for burntcigar malware"
        Author = "zendannyy"
        Reference = "https://www.mandiant.com/resources/blog/unc2596-cuba-ransomware"

    strings:
        $l0 = "!This program cannot be run in DOS mode."
        $l1 = "CorExitProcess"
        $l2 = "Kill PID ="
        $l3 = "CreateFile Error = "
        $s1 = "F:\\Source\\WorkNew19\\KillAV\\Release\\KillAV.pdb"
        $s2 = "SAVAdminService.exe" wide
        $s3 = "SavService.exe" wide
        $s4 = "SEDService.exe" wide
        $s5 = "ALsvc.exe" wide
        $s6 = "SophosCleanM64.exe" wide
        $s7 = "SophosFS.exe" wide
        $s8 = "SophosFileScanner.exe" wide
        $s9 = "SophosHealth.exe" wide
        $s10 = "Endpoint Agent Tray.exe" wide
        $s11 = "EAServiceMonitor.exe" wide
        $s12 = "MsMpEng.exe" wide
        $re1 = /Sentinel[\w]+[.]exe/
        $re2 = /\\{4}[.]\\{2}aswSP_[A-Za-z0-9]+/
        $re3 = /\\{4}[.]\\{2}aswSP_Avar+/

    condition: 50% of ($l*) or 
               50% of ($s*) or 
               2 of ($re*)
    
}
