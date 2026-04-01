/*
 * YARA Rule: Advanced Information Stealer Configuration Detection
 * MITRE ATT&CK: T1005 - Data from Local System
 * Description: Detects stealer malware with encrypted configuration blocks and exfil targets
 */

rule advanced_stealer_configuration_parsing : stealer_config {
    meta:
        description = "Detects information stealer malware with encrypted configuration parsing targeting Crypto wallets"
        author = "zendannyy"
        reference = "https://www.fortinet.com/blog/threat-research/new-campaign-uses-remcos-rat-to-exploit-victims"
        mitre_attack = "T1005"
        severity = "high"
        false_positive1 = "Development tools or scripts that contain strings matching exfiltration methods (e.g., 'POST', 'application/json', 'ToBase64String') within their code or configuration."
        false_positive2 = "Benign applications that use XOR or RC4 for internal data obfuscation and include anti-analysis strings for self-protection."
strings:
        // PE header
        $pe_mz = { 4D 5A }
        
        // Remcos-specific configuration delimiter
        $remcos_config_delim = { 7C 1E 1E 1F 7C }  // |....|
        $settings_resource = "SETTINGS" ascii wide
        
        // Browser data targeting paths (specific and current)
        $chrome_login = "\Google\Chrome\User Data\Default\Login Data" ascii wide
        $firefox_key4 = "\Mozilla\Firefox\Profiles\*.default-release\key4.db" ascii wide
        $edge_login = "\Microsoft\Edge\User Data\Default\Login Data" ascii wide
        $brave_login = "\BraveSoftware\Brave-Browser\User Data\Default\Login Data" ascii wide
        
        // Modern cryptocurrency wallet paths
        $wallet_metamask = "\MetaMask\vault" ascii wide
        $wallet_trust = "\Trust Wallet" ascii wide
        $wallet_phantom = "\Phantom" ascii wide
        $wallet_coinbase = "\Base Wallet" ascii wide
        $wallet_exodus = "\Exodus\exodus.wallet" ascii wide
        
        // communication platforms
        $comm_discord_tokens = "\discord\Local Storage\leveldb" ascii wide
        $comm_telegram = "\Telegram Desktop	data" ascii wide
        $comm_steam = "\Steam\config" ascii wide
        $comm_minecraft = "\.minecraft\launcher_profiles.json" ascii wide
        
        // Email client targeting
        $outlook_pst = "\.pst" ascii wide
        $thunderbird_profiles = "\Thunderbird\Profiles" ascii wide
        
        // Exfiltration method indicators
        $http_post = "POST" ascii wide
        $multipart_form = "multipart/form-data" ascii wide
        $json_exfil = "application/json" ascii wide
        $base64_encode = "ToBase64String" ascii wide
        
        // Anti-analysis in config context
        $anti_vm_config = "vm_check" ascii wide nocase
        $anti_debug_config = "debug_check" ascii wide nocase
        $anti_delay_config = "delay" ascii wide nocase
        
        // RC4/XOR decryption patterns for configs
        $key_pattern = { 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F }
        $key_pattern_xor = { ?? ?? ?? ?? 00 01 02 03 }

    condition:
        $pe_mz at 0 and
        filesize < 8MB and
        (
            // Remcos-style configuration with delimiters
            ($remcos_config_delim and any of ($settings_resource)) or
            // Modern browser + crypto wallet targeting
            (any of ($chrome_login, $firefox_key4, $edge_login, $brave_login) and any of ($wallet*)) or
            // Gaming/communication platforms with exfiltration methods
            (any of ($comm*) and any of ($http_post, $multipart_form, $json_exfil)) or
            // Configuration structure with C2 communication
            (any of ($base64_encode, $http_post)) or
            // Encrypted configuration with anti-analysis
            (any of ($key_pattern, $key_pattern_xor) and any of ($anti_*))
        )
}
