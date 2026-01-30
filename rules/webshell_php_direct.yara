rule webshell_php_direct
{

    strings:
        # First, check if its php file
        $php = "<?php" ascii
        

        $c1     = "system(" nocase
        $c2      = "exec(" nocase
        $c3 = "shell_exec(" nocase
        $c4 = "echo shell_exec($com);" fullword
        $c4  = "passthru(" nocase
        # for an all-in-one
        # $geval = /\b(exec|shell_exec|passthru|system|proc_open|pcntl_exec|eval|assert)[\t ]{0,300}(\(base64_decode)?(\(stripslashes)?[\t ]{0,300}(\(trim)?[\t ]{0,300}\(\$(_POST|_GET|_REQUEST|_SERVER\s?\[['"]HTTP_|GLOBALS\[['"]_(POST|GET|REQUEST))/ wide ascii
        

        $s1     = "$_GET[" nocase
        $s2    = "$_POST[" nocase
        $s3 = "$_REQUEST[" nocase
        
    condition:
        $php and
        2 of ($c*) and 
        2 of ($s*)
}
