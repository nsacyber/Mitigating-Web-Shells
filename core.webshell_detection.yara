/*
    WARNING: Host-based security systems may DETECT this file as malicious!
    Because the text used in these signatures is also used in some malware definitions, this file may be detected as malicious. If this happens, it is recommended that the limited.yara.bin file be used instead. Because limited.yara.bin is a compiled yara ruleset, it is unlikely to trigger host-based security systems
*/

private rule b374k
{
    meta:
        author = "Blair Gillam (@blairgillam)"

    strings:
        $string = "b374k"
        $password_var = "$s_pass"
        $default_password = "0de664ecd2be02cdd54234a0d1229b43"

    condition:
        any of them
}

private rule pas_tool
{
    meta:
        author = "US CERT"

    strings:
        $php = "<?php"
        $base64decode = /\='base'\.\(\d+\*\d+\)\.'_de'\.'code'/ 
        $strreplace = "(str_replace("
        $md5 = ".substr(md5(strrev("
        $gzinflate = "gzinflate"
        $cookie = "_COOKIE"
        $isset = "isset"

    condition:
        (filesize > 20KB and filesize < 22KB) and
        #cookie == 2 and
        #isset == 3 and
        all of them
}

private rule pbot
{
    meta:
        author = "Jacob Baines (Tenable)"

    strings:
        $ = "class pBot" ascii
        $ = "function start(" ascii
        $ = "PING" ascii
        $ = "PONG" ascii

    condition:
        all of them
}

private rule generic_jsp
{
    meta:
        source = "https://www.tenable.com/blog/hunting-for-web-shells"

    strings:
        $ = /Runtime.getRuntime\(\).exec\(request.getParameter\(\"[a-zA-Z0-9]+\"\)\);/ ascii

    condition:
        all of them
}

private rule eval
{
    meta:
        source = "https://www.tenable.com/blog/hunting-for-web-shells"

    strings:
        $ = /eval[\( \t]+((base64_decode[\( \t]+)|(str_rot13[\( \t]+)|(gzinflate[\( \t]+)|(gzuncompress[\( \t]+)|(strrev[\( \t]+)|(gzdecode[\( \t]+))+/

    condition:
        all of them
}

private rule fopo
{
    meta:
        source = "https://github.com/tenable/yara-rules/blob/master/webshells/"

    strings:
        $ = /\$[a-zA-Z0-9]+=\"\\(142|x62)\\(141|x61)\\(163|x73)\\(145|x65)\\(66|x36)\\(64|x34)\\(137|x5f)\\(144|x64)\\(145|x65)\\(143|x63)\\(157|x6f)\\(144|x64)\\(145|x65)\";@eval\(/

    condition:
        all of them
}

private rule hardcoded_urldecode
{
    meta:
        source = "https://github.com/tenable/yara-rules/blob/master/webshells/"

    strings:
        $ = /urldecode[\t ]*\([\t ]*'(%[0-9a-fA-F][0-9a-fA-F])+'[\t ]*\)/

    condition:
        all of them
}

private rule chr_obfuscation
{
    meta:
        source = "https://github.com/tenable/yara-rules/blob/master/webshells/"

    strings:
        $ = /\$[^=]+=[\t ]*(chr\([0-9]+\)\.?){2,}/

    condition:
        all of them
}

private rule phpInImage
{
    meta:
        source = "Vlad https://github.com/vlad-s"

    strings:
        $php_tag = "<?php"
        $gif = {47 49 46 38 ?? 61} // GIF8[version]a
        $jfif = { ff d8 ff e? 00 10 4a 46 49 46 }
        $png = { 89 50 4e 47 0d 0a 1a 0a }
        $jpeg = {FF D8 FF E0 ?? ?? 4A 46 49 46 } 

    condition:
        (($gif at 0) or ($jfif at 0) or ($png at 0) or ($jpeg at 0)) and $php_tag
}

rule hiddenFunctionality
{
    meta:
        author = "NSA Cybersecurity"
        description = "Hidden functionality allows malware to masquerade as another filetype"

    condition:
        phpInImage
}

rule webshellArtifact 
{
    meta:
        author = "NSA Cybersecurity"
        description = "Artifacts common to web shells and rare in benign files"

    condition:
        b374k or pas_tool or pbot or generic_jsp
}

rule suspiciousFunctionality
{
    meta:
        author = "NSA Cybersecurity"
        description = "Artifacts common to web shells and somewhat rare in benign files"

    condition:
        hardcoded_urldecode or fopo or eval
}

rule obfuscatedFunctionality
{
    meta:
        author = "NSA Cybersecurity"
        description = "Obfuscation sometimes hides malicious functionality"

    condition:
        chr_obfuscation
}

private rule APT_Backdoor_MSIL_SUNBURST_1
{
    meta:
        author = "FireEye"
        description = "This rule is looking for portions of the SUNBURST backdoor that are vital to how it functions. The first signature fnv_xor matches a magic byte xor that the sample performs on process, service, and driver names/paths. SUNBURST is a backdoor that has the ability to spawn and kill processes, write and delete files, set and create registry keys, gather system information, and disable a set of forensic analysis tools and services."
        source = "https://github.com/fireeye/sunburst_countermeasures/blob/main/rules/SUNBURST/yara/APT_Backdoor_MSIL_SUNBURST_1.yar"
    
    strings:
        $cmd_regex_encoded = "U4qpjjbQtUzUTdONrTY2q42pVapRgooABYxQuIZmtUoA" wide
        $cmd_regex_plain = { 5C 7B 5B 30 2D 39 61 2D 66 2D 5D 7B 33 36 7D 5C 7D 22 7C 22 5B 30 2D 39 61 2D 66 5D 7B 33 32 7D 22 7C 22 5B 30 2D 39 61 2D 66 5D 7B 31 36 7D }
        $fake_orion_event_encoded = "U3ItS80rCaksSFWyUvIvyszPU9IBAA==" wide
        $fake_orion_event_plain = { 22 45 76 65 6E 74 54 79 70 65 22 3A 22 4F 72 69 6F 6E 22 2C }
        $fake_orion_eventmanager_encoded = "U3ItS80r8UvMTVWyUgKzfRPzEtNTi5R0AA==" wide
        $fake_orion_eventmanager_plain = { 22 45 76 65 6E 74 4E 61 6D 65 22 3A 22 45 76 65 6E 74 4D 61 6E 61 67 65 72 22 2C }
        $fake_orion_message_encoded = "U/JNLS5OTE9VslKqNqhVAgA=" wide
        $fake_orion_message_plain = { 22 4D 65 73 73 61 67 65 22 3A 22 7B 30 7D 22 }
        $fnv_xor = { 67 19 D8 A7 3B 90 AC 5B }
    condition:
        $fnv_xor and ($cmd_regex_encoded or $cmd_regex_plain) or ( ($fake_orion_event_encoded or $fake_orion_event_plain) and ($fake_orion_eventmanager_encoded or $fake_orion_eventmanager_plain) and ($fake_orion_message_encoded and $fake_orion_message_plain) )
}

private rule APT_Backdoor_MSIL_SUNBURST_2
{
    meta:
        author = "FireEye"
        description = "The SUNBURST backdoor uses a domain generation algorithm (DGA) as part of C2 communications. This rule is looking for each branch of the code that checks for which HTTP method is being used. This is in one large conjunction, and all branches are then tied together via disjunction. The grouping is intentionally designed so that if any part of the DGA is re-used in another sample, this signature should match that re-used portion. SUNBURST is a backdoor that has the ability to spawn and kill processes, write and delete files, set and create registry keys, gather system information, and disable a set of forensic analysis tools and services."
        source = "https://github.com/fireeye/sunburst_countermeasures/blob/main/rules/SUNBURST/yara/APT_Backdoor_MSIL_SUNBURST_2.yar"
    
    strings:
        $a = "0y3Kzy8BAA==" wide
        $aa = "S8vPKynWL89PS9OvNqjVrTYEYqNa3fLUpDSgTLVxrR5IzggA" wide
        $ab = "S8vPKynWL89PS9OvNqjVrTYEYqPaauNaPZCYEQA=" wide
        $ac = "C88sSs1JLS4GAA==" wide
        $ad = "C/UEAA==" wide
        $ae = "C89MSU8tKQYA" wide
        $af = "8wvwBQA=" wide
        $ag = "cyzIz8nJBwA=" wide
        $ah = "c87JL03xzc/LLMkvysxLBwA=" wide
        $ai = "88tPSS0GAA==" wide
        $aj = "C8vPKc1NLQYA" wide
        $ak = "88wrSS1KS0xOLQYA" wide
        $al = "c87PLcjPS80rKQYA" wide
        $am = "Ky7PLNAvLUjRBwA=" wide
        $an = "06vIzQEA" wide
        $b = "0y3NyyxLLSpOzIlPTgQA" wide
        $c = "001OBAA=" wide
        $d = "0y0oysxNLKqMT04EAA==" wide
        $e = "0y3JzE0tLknMLQAA" wide
        $f = "003PyU9KzAEA" wide
        $h = "0y1OTS4tSk1OBAA=" wide
        $i = "K8jO1E8uytGvNqitNqytNqrVA/IA" wide
        $j = "c8rPSQEA" wide
        $k = "c8rPSfEsSczJTAYA" wide
        $l = "c60oKUp0ys9JAQA=" wide
        $m = "c60oKUp0ys9J8SxJzMlMBgA=" wide
        $n = "8yxJzMlMBgA=" wide
        $o = "88lMzygBAA==" wide
        $p = "88lMzyjxLEnMyUwGAA==" wide
        $q = "C0pNL81JLAIA" wide
        $r = "C07NzXTKz0kBAA==" wide
        $s = "C07NzXTKz0nxLEnMyUwGAA==" wide
        $t = "yy9IzStOzCsGAA==" wide
        $u = "y8svyQcA" wide
        $v = "SytKTU3LzysBAA==" wide
        $w = "C84vLUpOdc5PSQ0oygcA" wide
        $x = "C84vLUpODU4tykwLKMoHAA==" wide
        $y = "C84vLUpO9UjMC07MKwYA" wide
        $z = "C84vLUpO9UjMC04tykwDAA==" wide
    condition:
        ($a and $b and $c and $d and $e and $f and $h and $i) or ($j and $k and $l and $m and $n and $o and $p and $q and $r and $s and ($aa or $ab)) or ($t and $u and $v and $w and $x and $y and $z and ($aa or $ab)) or ($ac and $ad and $ae and $af and $ag and $ah and ($am or $an)) or ($ai and $aj and $ak and $al and ($am or $an))
}

private rule APT_Backdoor_MSIL_SUNBURST_3
{
    meta:
        author = "FireEye"
        description = "This rule is looking for certain portions of the SUNBURST backdoor that deal with C2 communications. SUNBURST is a backdoor that has the ability to spawn and kill processes, write and delete files, set and create registry keys, gather system information, and disable a set of forensic analysis tools and services."
        source = "https://github.com/fireeye/sunburst_countermeasures/blob/main/rules/SUNBURST/yara/APT_Backdoor_MSIL_SUNBURST_3.yar"
    
    strings:
        $sb1 = { 05 14 51 1? 0A 04 28 [2] 00 06 0? [0-16] 03 1F ?? 2E ?? 03 1F ?? 2E ?? 03 1F ?? 2E ?? 03 1F [1-32] 03 0? 05 28 [2] 00 06 0? [0-32] 03 [0-16] 59 45 06 }
        $sb2 = { FE 16 [2] 00 01 6F [2] 00 0A 1? 8D [2] 00 01 [0-32] 1? 1? 7B 9? [0-16] 1? 1? 7D 9? [0-16] 6F [2] 00 0A 28 [2] 00 0A 28 [2] 00 0A [0-32] 02 7B [2] 00 04 1? 6F [2] 00 0A [2-32] 02 7B [2] 00 04 20 [4] 6F [2] 00 0A [0-32] 13 ?? 11 ?? 11 ?? 6E 58 13 ?? 11 ?? 11 ?? 9? 1? [0-32] 60 13 ?? 0? 11 ?? 28 [4] 11 ?? 11 ?? 9? 28 [4] 28 [4-32] 9? 58 [0-32] 6? 5F 13 ?? 02 7B [2] 00 04 1? ?? 1? ?? 6F [2] 00 0A 8D [2] 00 01 }
        $ss1 = "\x00set_UseShellExecute\x00"
        $ss2 = "\x00ProcessStartInfo\x00"
        $ss3 = "\x00GetResponseStream\x00"
        $ss4 = "\x00HttpWebResponse\x00"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

private rule APT_Backdoor_MSIL_SUNBURST_4
{
    meta:
        author = "FireEye"
        description = "This rule is looking for specific methods used by the SUNBURST backdoor. SUNBURST is a backdoor that has the ability to spawn and kill processes, write and delete files, set and create registry keys, gather system information, and disable a set of forensic analysis tools and services."
        source = "https://github.com/fireeye/sunburst_countermeasures/blob/main/rules/SUNBURST/yara/APT_Backdoor_MSIL_SUNBURST_4.yar"
    
    strings:
        $ss1 = "\x00set_UseShellExecute\x00"
        $ss2 = "\x00ProcessStartInfo\x00"
        $ss3 = "\x00GetResponseStream\x00"
        $ss4 = "\x00HttpWebResponse\x00"
        $ss5 = "\x00ExecuteEngine\x00"
        $ss6 = "\x00ParseServiceResponse\x00"
        $ss7 = "\x00RunTask\x00"
        $ss8 = "\x00CreateUploadRequest\x00"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule sunburstArtifacts
{
    meta:
        author = "NSA Cybersecurity"
        description = "Artifacts common to the SUNBURST backdoor."

    condition:
        APT_Backdoor_MSIL_SUNBURST_1 or APT_Backdoor_MSIL_SUNBURST_2 or APT_Backdoor_MSIL_SUNBURST_3 or APT_Backdoor_MSIL_SUNBURST_4
}

private rule APT_Dropper_Raw64_TEARDROP_1
{
    meta:
        author = "FireEye"
        description = "This rule looks for portions of the TEARDROP backdoor that are vital to how it functions. TEARDROP is a memory only dropper that can read files and registry keys, XOR decode an embedded payload, and load the payload into memory. TEARDROP persists as a Windows service and has been observed dropping Cobalt Strike BEACON into memory."
        source = "https://github.com/fireeye/sunburst_countermeasures/blob/main/rules/TEARDROP/yara/APT_Dropper_Raw64_TEARDROP_1.yar"
    
    strings:
        $sb1 = { C7 44 24 ?? 80 00 00 00 [0-64] BA 00 00 00 80 [0-32] 48 8D 0D [4-32] FF 15 [4] 48 83 F8 FF [2-64] 41 B8 40 00 00 00 [0-64] FF 15 [4-5] 85 C0 7? ?? 80 3D [4] FF }
        $sb2 = { 80 3D [4] D8 [2-32] 41 B8 04 00 00 00 [0-32] C7 44 24 ?? 4A 46 49 46 [0-32] E8 [4-5] 85 C0 [2-32] C6 05 [4] 6A C6 05 [4] 70 C6 05 [4] 65 C6 05 [4] 67 }
        $sb3 = { BA [4] 48 89 ?? E8 [4] 41 B8 [4] 48 89 ?? 48 89 ?? E8 [4] 85 C0 7? [1-32] 8B 44 24 ?? 48 8B ?? 24 [1-16] 48 01 C8 [0-32] FF D0 }
    condition:
        all of them
}

private rule APT_Dropper_Win64_TEARDROP_2
{
    meta:
        author = "FireEye"
        description = "This rule is intended match specific sequences of opcode found within TEARDROP, including those that decode the embedded payload. TEARDROP is a memory only dropper that can read files and registry keys, XOR decode an embedded payload, and load the payload into memory. TEARDROP persists as a Windows service and has been observed dropping Cobalt Strike BEACON into memory."
        source = "https://github.com/fireeye/sunburst_countermeasures/blob/main/rules/TEARDROP/yara/APT_Dropper_Win64_TEARDROP_2.yar"
    
    strings:
        $loc_4218FE24A5 = { 48 89 C8 45 0F B6 4C 0A 30 }
        $loc_4218FE36CA = { 48 C1 E0 04 83 C3 01 48 01 E8 8B 48 28 8B 50 30 44 8B 40 2C 48 01 F1 4C 01 FA }
        $loc_4218FE2747 = { C6 05 ?? ?? ?? ?? 6A C6 05 ?? ?? ?? ?? 70 C6 05 ?? ?? ?? ?? 65 C6 05 ?? ?? ?? ?? 67 }
        $loc_5551D725A0 = { 48 89 C8 45 0F B6 4C 0A 30 48 89 CE 44 89 CF 48 F7 E3 48 C1 EA 05 48 8D 04 92 48 8D 04 42 48 C1 E0 04 48 29 C6 }
        $loc_5551D726F6 = { 53 4F 46 54 57 41 52 45 ?? ?? ?? ?? 66 74 5C 43 ?? ?? ?? ?? 00 }
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule teardropArtifacts
{
    meta:
        author = "NSA Cybersecurity"
        description = "Artifacts common to the TEARDROP backdoor."

    condition:
        APT_Dropper_Raw64_TEARDROP_1 or APT_Dropper_Win64_TEARDROP_2
}
