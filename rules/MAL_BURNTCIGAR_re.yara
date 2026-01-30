rule MAL_BURNTCIGAR_re
{

    meta:
        Description = "Rule for burntcigar malware, for re"
        Reference = "https://www.mandiant.com/resources/blog/unc2596-cuba-ransomware"

    strings:
        $re1 = /Sentinel[\w]+[.]exe/
        $re2 = /\\{4}[.]\\{2}aswSP_[A-Za-z0-9]+/
        $re3 = /\\{4}[.]\\{2}aswSP_Avar+/


     condition: all of them 
    
}
