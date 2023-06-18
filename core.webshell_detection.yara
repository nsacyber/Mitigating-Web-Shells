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


// Webshell rules by Arnim Rupp (https://github.com/ruppde), Version 2
import "math"

/*
Rationale behind the rules:
1. a webshell must always execute some kind of payload (in $payload*). the payload is either:
-- direct php function like exec, file write, sql, ...
-- indirect via eval, self defined functions, callbacks, reflection, ...
2. a webshell must always have some way to get the attackers input, e.g. for PHP in $_GET, php://input or $_SERVER (HTTP for headers).

The input may be hidden in obfuscated code, so we look for either:
a) payload + input
b) eval-style-payloads + obfuscation
c) includers (webshell is split in 2+ files)
d) unique strings, if the coder doesn't even intend to hide

Additional conditions will be added to reduce false positves. Check all findings for unintentional webshells aka vulnerabilities ;)

The rules named "suspicious_" are commented by default. uncomment them to find more potentially malicious files at the price of more false positives. if that finds too many results to manually check, you can compare the hashes to virustotal with e.g. https://github.com/Neo23x0/munin

Some samples in the collection were UTF-16 and at least PHP and Java support it, so I use "wide ascii" for all strings. The performance impact is 1%. See also https://thibaud-robin.fr/articles/bypass-filter-upload/

Rules tested on the following webshell repos and collections:
    https://github.com/sensepost/reGeorg
    https://github.com/WhiteWinterWolf/wwwolf-php-webshell
    https://github.com/k8gege/Ladon
    https://github.com/x-o-r-r-o/PHP-Webshells-Collection
    https://github.com/mIcHyAmRaNe/wso-webshell
    https://github.com/LandGrey/webshell-detect-bypass
    https://github.com/threedr3am/JSP-Webshells
    https://github.com/02bx/webshell-venom
    https://github.com/pureqh/webshell
    https://github.com/secwiki/webshell-2
    https://github.com/zhaojh329/rtty
    https://github.com/modux/ShortShells
    https://github.com/epinna/weevely3
    https://github.com/chrisallenlane/novahot
    https://github.com/malwares/WebShell
    https://github.com/tanjiti/webshellSample
    https://github.com/L-codes/Neo-reGeorg
    https://github.com/bayufedra/Tiny-PHP-Webshell
    https://github.com/b374k/b374k
    https://github.com/wireghoul/htshells
    https://github.com/securityriskadvisors/cmd.jsp
    https://github.com/WangYihang/Webshell-Sniper
    https://github.com/Macr0phag3/WebShells
    https://github.com/s0md3v/nano
    https://github.com/JohnTroony/php-webshells
    https://github.com/linuxsec/indoxploit-shell
    https://github.com/hayasec/reGeorg-Weblogic
    https://github.com/nil0x42/phpsploit
    https://github.com/mperlet/pomsky
    https://github.com/FunnyWolf/pystinger
    https://github.com/tanjiti/webshellsample
    https://github.com/lcatro/php-webshell-bypass-waf
    https://github.com/zhzyker/exphub
    https://github.com/dotcppfile/daws
    https://github.com/lcatro/PHP-WebShell-Bypass-WAF
    https://github.com/ysrc/webshell-sample
    https://github.com/JoyChou93/webshell
    https://github.com/k4mpr3t/b4tm4n
    https://github.com/mas1337/webshell
    https://github.com/tengzhangchao/pycmd
    https://github.com/bartblaze/PHP-backdoors
    https://github.com/antonioCoco/SharPyShell
    https://github.com/xl7dev/WebShell
    https://github.com/BlackArch/webshells
    https://github.com/sqlmapproject/sqlmap
    https://github.com/Smaash/quasibot
    https://github.com/tennc/webshell

Webshells in these repos after fdupes run: 4722
Old signature-base rules found: 1315
This rules found: 3286
False positives in 8gb of common webapps plus yara-ci: 2

*/

rule webshell_php_generic
{
    meta:
        description = "php webshell having some kind of input and some kind of payload. restricted to small files or big ones inclusing suspicious strings"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021/01/14"
        modified = "2023-04-05"
        hash = "bee1b76b1455105d4bfe2f45191071cf05e83a309ae9defcf759248ca9bceddd"
        hash = "6bf351900a408120bee3fc6ea39905c6a35fe6efcf35d0a783ee92062e63a854"
        hash = "e3b4e5ec29628791f836e15500f6fdea19beaf3e8d9981c50714656c50d3b365"
        hash = "00813155bf7f5eb441e1619616a5f6b21ae31afc99caa000c4aafd54b46c3597"
        hash = "e31788042d9cdeffcb279533b5a7359b3beb1144f39bacdd3acdef6e9b4aff25"
        hash = "36b91575a08cf40d4782e5aebcec2894144f1e236a102edda2416bc75cbac8dd"
        hash = "a34154af7c0d7157285cfa498734cfb77662edadb1a10892eb7f7e2fb5e2486c"
        hash = "791a882af2cea0aa8b8379791b401bebc235296858266ddb7f881c8923b7ea61"
        hash = "9a8ab3c225076a26309230d7eac7681f85b271d2db22bf5a190adbf66faca2e6"
        hash = "0d3ee83adc9ebf8fb1a8c449eed5547ee5e67e9a416cce25592e80963198ae23"
        hash = "3d8708609562a27634df5094713154d8ca784dbe89738e63951e12184ff07ad6"
        hash = "70d64d987f0d9ab46514abcc868505d95dbf458387f858b0d7580e4ee8573786"
        hash = "259b3828694b4d256764d7d01b0f0f36ca0526d5ee75e134c6a754d2ab0d1caa"
        hash = "04d139b48d59fa2ef24fb9347b74fa317cb05bd8b7389aeb0a4d458c49ea7540"
        hash = "58d0e2ff61301fe0c176b51430850239d3278c7caf56310d202e0cdbdde9ac3f"
        hash = "731f36a08b0e63c63b3a2a457667dfc34aa7ff3a2aee24e60a8d16b83ad44ce2"
        hash = "e4ffd4ec67762fe00bb8bd9fbff78cffefdb96c16fe7551b5505d319a90fa18f"
        hash = "fa00ee25bfb3908808a7c6e8b2423c681d7c52de2deb30cbaea2ee09a635b7d4"
        hash = "98c1937b9606b1e8e0eebcb116a784c9d2d3db0039b21c45cba399e86c92c2fa"
        hash = "e9423ad8e51895db0e8422750c61ef4897b3be4292b36dba67d42de99e714bff"
        hash = "7a16311a371f03b29d5220484e7ecbe841cfaead4e73c17aa6a9c23b5d94544d"
        hash = "7ca5dec0515dd6f401cb5a52c313f41f5437fc43eb62ea4bcc415a14212d09e9"
        hash = "3de8c04bfdb24185a07f198464fcdd56bb643e1d08199a26acee51435ff0a99f"
        hash = "63297f8c1d4e88415bc094bc5546124c9ed8d57aca3a09e36ae18f5f054ad172"
        hash = "a09dcf52da767815f29f66cb7b03f3d8c102da5cf7b69567928961c389eac11f"
        hash = "d9ae762b011216e520ebe4b7abcac615c61318a8195601526cfa11bbc719a8f1"
        hash = "dd5d8a9b4bb406e0b8f868165a1714fe54ffb18e621582210f96f6e5ae850b33"

    strings:
        $wfp_tiny1 = "escapeshellarg" fullword
        $wfp_tiny2 = "addslashes" fullword

        //strings from private rule php_false_positive_tiny
        // try to use only strings which would be flagged by themselves as suspicious by other rules, e.g. eval
        //$gfp_tiny1 = "addslashes" fullword
        //$gfp_tiny2 = "escapeshellarg" fullword
        $gfp_tiny3 = "include \"./common.php\";" // xcache
        $gfp_tiny4 = "assert('FALSE');"
        $gfp_tiny5 = "assert(false);"
        $gfp_tiny6 = "assert(FALSE);"
        $gfp_tiny7 = "assert('array_key_exists("
        $gfp_tiny8 = "echo shell_exec($aspellcommand . ' 2>&1');"
        $gfp_tiny9 = "throw new Exception('Could not find authentication source with id ' . $sourceId);"
        $gfp_tiny10= "return isset( $_POST[ $key ] ) ? $_POST[ $key ] : ( isset( $_REQUEST[ $key ] ) ? $_REQUEST[ $key ] : $default );"

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

        //strings from private rule capa_php_input
        $inp1 = "php://input" wide ascii
        $inp2 = /_GET\s?\[/ wide ascii
        // for passing $_GET to a function
        $inp3 = /\(\s?\$_GET\s?\)/ wide ascii
        $inp4 = /_POST\s?\[/ wide ascii
        $inp5 = /\(\s?\$_POST\s?\)/ wide ascii
        $inp6 = /_REQUEST\s?\[/ wide ascii
        $inp7 = /\(\s?\$_REQUEST\s?\)/ wide ascii
        $inp8 = /\(\s?\$_HEADERS\s?[\)\[]/ wide ascii
        // PHP automatically adds all the request headers into the $_SERVER global array, prefixing each header name by the "HTTP_" string, so e.g. @eval($_SERVER['HTTP_CMD']) will run any code in the HTTP header CMD
        $inp15 = "_SERVER['HTTP_" wide ascii
        $inp16 = "_SERVER[\"HTTP_" wide ascii
        $inp17 = /getenv[\t ]{0,20}\([\t ]{0,20}['"]HTTP_/ wide ascii
        $inp18 = "array_values($_SERVER)" wide ascii
        $inp19 = /file_get_contents\("https?:\/\// wide ascii
        $inp20 = "TSOP_" wide ascii

        //strings from private rule capa_php_payload
        // \([^)] to avoid matching on e.g. eval() in comments
        $cpayload1 = /\beval[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload2 = /\bexec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload3 = /\bshell_exec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload4 = /\bpassthru[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload5 = /\bsystem[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload6 = /\bpopen[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload7 = /\bproc_open[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload8 = /\bpcntl_exec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload9 = /\bassert[\n\t ]*\([^)0]/ nocase wide ascii
        $cpayload10 = /\bpreg_replace[\n\t ]*(\(.{1,|\/\*)100}\/[ismxADSUXju]{0,11}(e|\\x65)/ nocase wide ascii
        $cpayload12 = /\bmb_ereg_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
        $cpayload13 = /\bmb_eregi_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
        $cpayload20 = /\bcreate_function[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload21 = /\bReflectionFunction[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload22 = /fetchall\(PDO::FETCH_FUNC[\n\t ]*[,}\)]/ nocase wide ascii

        $m_cpayload_preg_filter1 = /\bpreg_filter[\n\t ]*(\([^\)]|\/\*)/ nocase wide ascii
        $m_cpayload_preg_filter2 = "'|.*|e'" nocase wide ascii
        // TODO backticks

        //strings from private rule capa_gen_sus

        // these strings are just a bit suspicious, so several of them are needed, depending on filesize
        $gen_bit_sus1  = /:\s{0,20}eval}/ nocase wide ascii
        $gen_bit_sus2  = /\.replace\(\/\w\/g/ nocase wide ascii
        $gen_bit_sus6  = "self.delete"
        $gen_bit_sus9  = "\"cmd /c" nocase
        $gen_bit_sus10 = "\"cmd\"" nocase
        $gen_bit_sus11 = "\"cmd.exe" nocase
        $gen_bit_sus12 = "%comspec%" wide ascii
        $gen_bit_sus13 = "%COMSPEC%" wide ascii
        //TODO:$gen_bit_sus12 = ".UserName" nocase
        $gen_bit_sus18 = "Hklm.GetValueNames();" nocase
        // bonus string for proxylogon exploiting webshells
        $gen_bit_sus19 = "http://schemas.microsoft.com/exchange/" wide ascii
        $gen_bit_sus21 = "\"upload\"" wide ascii
        $gen_bit_sus22 = "\"Upload\"" wide ascii
        $gen_bit_sus23 = "UPLOAD" fullword wide ascii
        $gen_bit_sus24 = "fileupload" wide ascii
        $gen_bit_sus25 = "file_upload" wide ascii
        // own base64 or base32 func
        $gen_bit_sus29 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" fullword wide ascii
        $gen_bit_sus29b = "abcdefghijklmnopqrstuvwxyz234567" fullword wide ascii
        $gen_bit_sus30 = "serv-u" wide ascii
        $gen_bit_sus31 = "Serv-u" wide ascii
        $gen_bit_sus32 = "Army" fullword wide ascii
        // single letter paramweter
        $gen_bit_sus33 = /\$_(GET|POST|REQUEST)\["\w"\]/ fullword wide ascii
        $gen_bit_sus34 = "Content-Transfer-Encoding: Binary" wide ascii
        $gen_bit_sus35 = "crack" fullword wide ascii

        $gen_bit_sus44 = "<pre>" wide ascii
        $gen_bit_sus45 = "<PRE>" wide ascii
        $gen_bit_sus46 = "shell_" wide ascii
        //fp: $gen_bit_sus47 = "Shell" fullword wide ascii
        $gen_bit_sus50 = "bypass" wide ascii
        $gen_bit_sus52 = " ^ $" wide ascii
        $gen_bit_sus53 = ".ssh/authorized_keys" wide ascii
        $gen_bit_sus55 = /\w'\.'\w/ wide ascii
        $gen_bit_sus56 = /\w\"\.\"\w/ wide ascii
        $gen_bit_sus57 = "dumper" wide ascii
        $gen_bit_sus59 = "'cmd'" wide ascii
        $gen_bit_sus60 = "\"execute\"" wide ascii
        $gen_bit_sus61 = "/bin/sh" wide ascii
        $gen_bit_sus62 = "Cyber" wide ascii
        $gen_bit_sus63 = "portscan" fullword wide ascii
        //$gen_bit_sus64 = "\"command\"" fullword wide ascii
        //$gen_bit_sus65 = "'command'" fullword wide ascii
        $gen_bit_sus66 = "whoami" fullword wide ascii
        $gen_bit_sus67 = "$password='" fullword wide ascii
        $gen_bit_sus68 = "$password=\"" fullword wide ascii
        $gen_bit_sus69 = "$cmd" fullword wide ascii
        $gen_bit_sus70 = "\"?>\"." fullword wide ascii
        $gen_bit_sus71 = "Hacking" fullword wide ascii
        $gen_bit_sus72 = "hacking" fullword wide ascii
        $gen_bit_sus73 = ".htpasswd" wide ascii
        $gen_bit_sus74 = /\btouch\(\$[^,]{1,30},/ wide ascii
        $gen_bit_sus75 = "uploaded" fullword wide ascii

        // very suspicious strings, one is enough
        $gen_much_sus7  = "Web Shell" nocase
        $gen_much_sus8  = "WebShell" nocase
        $gen_much_sus3  = "hidded shell"
        $gen_much_sus4  = "WScript.Shell.1" nocase
        $gen_much_sus5  = "AspExec"
        $gen_much_sus14 = "\\pcAnywhere\\" nocase
        $gen_much_sus15 = "antivirus" nocase
        $gen_much_sus16 = "McAfee" nocase
        $gen_much_sus17 = "nishang"
        $gen_much_sus18 = "\"unsafe" fullword wide ascii
        $gen_much_sus19 = "'unsafe" fullword wide ascii
        $gen_much_sus24 = "exploit" fullword wide ascii
        $gen_much_sus25 = "Exploit" fullword wide ascii
        $gen_much_sus26 = "TVqQAAMAAA" wide ascii
        $gen_much_sus30 = "Hacker" wide ascii
        $gen_much_sus31 = "HACKED" fullword wide ascii
        $gen_much_sus32 = "hacked" fullword wide ascii
        $gen_much_sus33 = "hacker" wide ascii
        $gen_much_sus34 = "grayhat" nocase wide ascii
        $gen_much_sus35 = "Microsoft FrontPage" wide ascii
        $gen_much_sus36 = "Rootkit" wide ascii
        $gen_much_sus37 = "rootkit" wide ascii
        $gen_much_sus38 = "/*-/*-*/" wide ascii
        $gen_much_sus39 = "u\"+\"n\"+\"s" wide ascii
        $gen_much_sus40 = "\"e\"+\"v" wide ascii
        $gen_much_sus41 = "a\"+\"l\"" wide ascii
        $gen_much_sus42 = "\"+\"(\"+\"" wide ascii
        $gen_much_sus43 = "q\"+\"u\"" wide ascii
        $gen_much_sus44 = "\"u\"+\"e" wide ascii
        $gen_much_sus45 = "/*//*/" wide ascii
        $gen_much_sus46 = "(\"/*/\"" wide ascii
        $gen_much_sus47 = "eval(eval(" wide ascii
        // self remove
        $gen_much_sus48 = "unlink(__FILE__)" wide ascii
        $gen_much_sus49 = "Shell.Users" wide ascii
        $gen_much_sus50 = "PasswordType=Regular" wide ascii
        $gen_much_sus51 = "-Expire=0" wide ascii
        $gen_much_sus60 = "_=$$_" wide ascii
        $gen_much_sus61 = "_=$$_" wide ascii
        $gen_much_sus62 = "++;$" wide ascii
        $gen_much_sus63 = "++; $" wide ascii
        $gen_much_sus64 = "_.=$_" wide ascii
        $gen_much_sus70 = "-perm -04000" wide ascii
        $gen_much_sus71 = "-perm -02000" wide ascii
        $gen_much_sus72 = "grep -li password" wide ascii
        $gen_much_sus73 = "-name config.inc.php" wide ascii
        // touch without parameters sets the time to now, not malicious and gives fp
        $gen_much_sus75 = "password crack" wide ascii
        $gen_much_sus76 = "mysqlDll.dll" wide ascii
        $gen_much_sus77 = "net user" wide ascii
        $gen_much_sus80 = "fopen(\".htaccess\",\"w" wide ascii
        $gen_much_sus81 = /strrev\(['"]/ wide ascii
        $gen_much_sus82 = "PHPShell" fullword wide ascii
        $gen_much_sus821= "PHP Shell" fullword wide ascii
        $gen_much_sus83 = "phpshell" fullword wide ascii
        $gen_much_sus84 = "PHPshell" fullword wide ascii
        $gen_much_sus87 = "deface" wide ascii
        $gen_much_sus88 = "Deface" wide ascii
        $gen_much_sus89 = "backdoor" wide ascii
        $gen_much_sus90 = "r00t" fullword wide ascii
        $gen_much_sus91 = "xp_cmdshell" fullword wide ascii
        $gen_much_sus92 = "str_rot13" fullword wide ascii

        $gif = { 47 49 46 38 }


        //strings from private rule capa_php_payload_multiple
        // \([^)] to avoid matching on e.g. eval() in comments
        $cmpayload1 = /\beval[\t ]*\([^)]/ nocase wide ascii
        $cmpayload2 = /\bexec[\t ]*\([^)]/ nocase wide ascii
        $cmpayload3 = /\bshell_exec[\t ]*\([^)]/ nocase wide ascii
        $cmpayload4 = /\bpassthru[\t ]*\([^)]/ nocase wide ascii
        $cmpayload5 = /\bsystem[\t ]*\([^)]/ nocase wide ascii
        $cmpayload6 = /\bpopen[\t ]*\([^)]/ nocase wide ascii
        $cmpayload7 = /\bproc_open[\t ]*\([^)]/ nocase wide ascii
        $cmpayload8 = /\bpcntl_exec[\t ]*\([^)]/ nocase wide ascii
        $cmpayload9 = /\bassert[\t ]*\([^)0]/ nocase wide ascii
        $cmpayload10 = /\bpreg_replace[\t ]*\([^\)]{1,100}\/e/ nocase wide ascii
        $cmpayload11 = /\bpreg_filter[\t ]*\([^\)]{1,100}\/e/ nocase wide ascii
        $cmpayload12 = /\bmb_ereg_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
        $cmpayload20 = /\bcreate_function[\t ]*\([^)]/ nocase wide ascii
        $cmpayload21 = /\bReflectionFunction[\t ]*\([^)]/ nocase wide ascii

        $fp1 = "# Some examples from obfuscated malware:" ascii
    condition:
        //any of them or
        not (
            any of ( $gfp_tiny* )
            or 1 of ($fp*)
        )
        and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and (
            any of ( $inp* )
        )
        and (
            any of ( $cpayload* ) or
        all of ( $m_cpayload_preg_filter* )
        )
        and
        ( ( filesize < 1000 and not any of ( $wfp_tiny* ) ) or
        ( (
        $gif at 0 or
        (
            filesize < 4KB and
            (
                1 of ( $gen_much_sus* ) or
                2 of ( $gen_bit_sus* )
            )
        ) or (
            filesize < 20KB and
            (
                2 of ( $gen_much_sus* ) or
                3 of ( $gen_bit_sus* )
            )
        ) or (
            filesize < 50KB and
            (
                2 of ( $gen_much_sus* ) or
                4 of ( $gen_bit_sus* )
            )
        ) or (
            filesize < 100KB and
            (
                2 of ( $gen_much_sus* ) or
                6 of ( $gen_bit_sus* )
            )
        ) or (
            filesize < 150KB and
            (
                3 of ( $gen_much_sus* ) or
                7 of ( $gen_bit_sus* )
            )
        ) or (
            filesize < 500KB and
            (
                4 of ( $gen_much_sus* ) or
                8 of ( $gen_bit_sus* )
            )
        )
        )
        and
        ( filesize > 5KB or not any of ( $wfp_tiny* ) ) ) or
        ( filesize < 500KB and (
            4 of ( $cmpayload* )
        )
        ) )
}

rule webshell_php_generic_callback
{
    meta:
        description = "php webshell having some kind of input and using a callback to execute the payload. restricted to small files or would give lots of false positives"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021/01/14"
        modified = "2023-04-05"
        score = 60
        hash = "e98889690101b59260e871c49263314526f2093f"
        hash = "63297f8c1d4e88415bc094bc5546124c9ed8d57aca3a09e36ae18f5f054ad172"
        hash = "81388c8cc99353cdb42572bb88df7d3bd70eefc748c2fa4224b6074aa8d7e6a2"
        hash = "27d3bfabc283d851b0785199da8b1b0384afcb996fa9217687274dd56a7b5f49"
        hash = "ee256d7cc3ceb2bf3a1934d553cdd36e3fbde62a02b20a1b748a74e85d4dbd33"
        hash = "4adc6c5373c4db7b8ed1e7e6df10a3b2ce5e128818bb4162d502056677c6f54a"
        hash = "1fe4c60ea3f32819a98b1725581ac912d0f90d497e63ad81ccf258aeec59fee3"
        hash = "2967f38c26b131f00276bcc21227e54ee6a71881da1d27ec5157d83c4c9d4f51"
        hash = "1ba02fb573a06d5274e30b2b05573305294497769414e964a097acb5c352fb92"
        hash = "f4fe8e3b2c39090ca971a8e61194fdb83d76fadbbace4c5eb15e333df61ce2a4"
        hash = "badda1053e169fea055f5edceae962e500842ad15a5d31968a0a89cf28d89e91"
        hash = "0a29cf1716e67a7932e604c5d3df4b7f372561200c007f00131eef36f9a4a6a2"
        hash = "51c2c8b94c4b8cce806735bcf6e5aa3f168f0f7addce47b699b9a4e31dc71b47"
        hash = "de1ef827bcd3100a259f29730cb06f7878220a7c02cee0ebfc9090753d2237a8"

    strings:

        //strings from private rule php_false_positive
        // try to use only strings which would be flagged by themselves as suspicious by other rules, e.g. eval
        // a good choice is a string with good atom quality = ideally 4 unusual characters next to each other
        $gfp1  = "eval(\"return [$serialised_parameter" // elgg
        $gfp2  = "$this->assert(strpos($styles, $"
        $gfp3  = "$module = new $_GET['module']($_GET['scope']);"
        $gfp4  = "$plugin->$_POST['action']($_POST['id']);"
        $gfp5  = "$_POST[partition_by]($_POST["
        $gfp6  = "$object = new $_REQUEST['type']($_REQUEST['id']);"
        $gfp7  = "The above example code can be easily exploited by passing in a string such as" // ... ;)
        $gfp8  = "Smarty_Internal_Debug::start_render($_template);"
        $gfp9  = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
        $gfp10 = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
        $gfp11 = "(eval (getenv \"EPROLOG\")))"
        $gfp12 = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"

        //strings from private rule php_false_positive_tiny
        // try to use only strings which would be flagged by themselves as suspicious by other rules, e.g. eval
        //$gfp_tiny1 = "addslashes" fullword
        //$gfp_tiny2 = "escapeshellarg" fullword
        $gfp_tiny3 = "include \"./common.php\";" // xcache
        $gfp_tiny4 = "assert('FALSE');"
        $gfp_tiny5 = "assert(false);"
        $gfp_tiny6 = "assert(FALSE);"
        $gfp_tiny7 = "assert('array_key_exists("
        $gfp_tiny8 = "echo shell_exec($aspellcommand . ' 2>&1');"
        $gfp_tiny9 = "throw new Exception('Could not find authentication source with id ' . $sourceId);"
        $gfp_tiny10= "return isset( $_POST[ $key ] ) ? $_POST[ $key ] : ( isset( $_REQUEST[ $key ] ) ? $_REQUEST[ $key ] : $default );"

        //strings from private rule capa_php_input
        $inp1 = "php://input" wide ascii
        $inp2 = /_GET\s?\[/ wide ascii
        // for passing $_GET to a function
        $inp3 = /\(\s?\$_GET\s?\)/ wide ascii
        $inp4 = /_POST\s?\[/ wide ascii
        $inp5 = /\(\s?\$_POST\s?\)/ wide ascii
        $inp6 = /_REQUEST\s?\[/ wide ascii
        $inp7 = /\(\s?\$_REQUEST\s?\)/ wide ascii
        // PHP automatically adds all the request headers into the $_SERVER global array, prefixing each header name by the "HTTP_" string, so e.g. @eval($_SERVER['HTTP_CMD']) will run any code in the HTTP header CMD
        $inp15 = "_SERVER['HTTP_" wide ascii
        $inp16 = "_SERVER[\"HTTP_" wide ascii
        $inp17 = /getenv[\t ]{0,20}\([\t ]{0,20}['"]HTTP_/ wide ascii
        $inp18 = "array_values($_SERVER)" wide ascii
        $inp19 = /file_get_contents\("https?:\/\// wide ascii

        // TODO: arraywalk \n /*
        //strings from private rule capa_php_callback
        // the end is 1. ( followed by anything but a direct closing ) 2. /* for the start of an obfuscation comment
        $callback1 = /\bob_start[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback2 = /\barray_diff_uassoc[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback3 = /\barray_diff_ukey[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback4 = /\barray_filter[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback5 = /\barray_intersect_uassoc[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback6 = /\barray_intersect_ukey[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback7 = /\barray_map[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback8 = /\barray_reduce[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback9 = /\barray_udiff_assoc[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback10 = /\barray_udiff_uassoc[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback11 = /\barray_udiff[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback12 = /\barray_uintersect_assoc[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback13 = /\barray_uintersect_uassoc[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback14 = /\barray_uintersect[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback15 = /\barray_walk_recursive[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback16 = /\barray_walk[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback17 = /\bassert_options[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback18 = /\buasort[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback19 = /\buksort[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback20 = /\busort[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback21 = /\bpreg_replace_callback[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback22 = /\bspl_autoload_register[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback23 = /\biterator_apply[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback24 = /\bcall_user_func[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback25 = /\bcall_user_func_array[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback26 = /\bregister_shutdown_function[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback27 = /\bregister_tick_function[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback28 = /\bset_error_handler[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback29 = /\bset_exception_handler[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback30 = /\bsession_set_save_handler[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback31 = /\bsqlite_create_aggregate[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback32 = /\bsqlite_create_function[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback33 = /\bmb_ereg_replace_callback[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii

        $m_callback1 = /\bfilter_var[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $m_callback2 = "FILTER_CALLBACK" fullword wide ascii

        $cfp1 = /ob_start\(['\"]ob_gzhandler/ nocase wide ascii
        $cfp2 = "IWPML_Backend_Action_Loader" ascii wide
        $cfp3 = "<?phpclass WPML" ascii

        //strings from private rule capa_gen_sus

        // these strings are just a bit suspicious, so several of them are needed, depending on filesize
        $gen_bit_sus1  = /:\s{0,20}eval}/ nocase wide ascii
        $gen_bit_sus2  = /\.replace\(\/\w\/g/ nocase wide ascii
        $gen_bit_sus6  = "self.delete"
        $gen_bit_sus9  = "\"cmd /c" nocase
        $gen_bit_sus10 = "\"cmd\"" nocase
        $gen_bit_sus11 = "\"cmd.exe" nocase
        $gen_bit_sus12 = "%comspec%" wide ascii
        $gen_bit_sus13 = "%COMSPEC%" wide ascii
        //TODO:$gen_bit_sus12 = ".UserName" nocase
        $gen_bit_sus18 = "Hklm.GetValueNames();" nocase
        // bonus string for proxylogon exploiting webshells
        $gen_bit_sus19 = "http://schemas.microsoft.com/exchange/" wide ascii
        $gen_bit_sus21 = "\"upload\"" wide ascii
        $gen_bit_sus22 = "\"Upload\"" wide ascii
        $gen_bit_sus23 = "UPLOAD" fullword wide ascii
        $gen_bit_sus24 = "fileupload" wide ascii
        $gen_bit_sus25 = "file_upload" wide ascii
        // own base64 or base32 func
        $gen_bit_sus29 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" fullword wide ascii
        $gen_bit_sus29b = "abcdefghijklmnopqrstuvwxyz234567" fullword wide ascii
        $gen_bit_sus30 = "serv-u" wide ascii
        $gen_bit_sus31 = "Serv-u" wide ascii
        $gen_bit_sus32 = "Army" fullword wide ascii
        // single letter paramweter
        $gen_bit_sus33 = /\$_(GET|POST|REQUEST)\["\w"\]/ fullword wide ascii
        $gen_bit_sus34 = "Content-Transfer-Encoding: Binary" wide ascii
        $gen_bit_sus35 = "crack" fullword wide ascii

        $gen_bit_sus44 = "<pre>" wide ascii
        $gen_bit_sus45 = "<PRE>" wide ascii
        $gen_bit_sus46 = "shell_" wide ascii
        //fp: $gen_bit_sus47 = "Shell" fullword wide ascii
        $gen_bit_sus50 = "bypass" wide ascii
        $gen_bit_sus52 = " ^ $" wide ascii
        $gen_bit_sus53 = ".ssh/authorized_keys" wide ascii
        $gen_bit_sus55 = /\w'\.'\w/ wide ascii
        $gen_bit_sus56 = /\w\"\.\"\w/ wide ascii
        $gen_bit_sus57 = "dumper" wide ascii
        $gen_bit_sus59 = "'cmd'" wide ascii
        $gen_bit_sus60 = "\"execute\"" wide ascii
        $gen_bit_sus61 = "/bin/sh" wide ascii
        $gen_bit_sus62 = "Cyber" wide ascii
        $gen_bit_sus63 = "portscan" fullword wide ascii
        //$gen_bit_sus64 = "\"command\"" fullword wide ascii
        //$gen_bit_sus65 = "'command'" fullword wide ascii
        $gen_bit_sus66 = "whoami" fullword wide ascii
        $gen_bit_sus67 = "$password='" fullword wide ascii
        $gen_bit_sus68 = "$password=\"" fullword wide ascii
        $gen_bit_sus69 = "$cmd" fullword wide ascii
        $gen_bit_sus70 = "\"?>\"." fullword wide ascii
        $gen_bit_sus71 = "Hacking" fullword wide ascii
        $gen_bit_sus72 = "hacking" fullword wide ascii
        $gen_bit_sus73 = ".htpasswd" wide ascii
        $gen_bit_sus74 = /\btouch\(\$[^,]{1,30},/ wide ascii

        // very suspicious strings, one is enough
        $gen_much_sus7  = "Web Shell" nocase
        $gen_much_sus8  = "WebShell" nocase
        $gen_much_sus3  = "hidded shell"
        $gen_much_sus4  = "WScript.Shell.1" nocase
        $gen_much_sus5  = "AspExec"
        $gen_much_sus14 = "\\pcAnywhere\\" nocase
        $gen_much_sus15 = "antivirus" nocase
        $gen_much_sus16 = "McAfee" nocase
        $gen_much_sus17 = "nishang"
        $gen_much_sus18 = "\"unsafe" fullword wide ascii
        $gen_much_sus19 = "'unsafe" fullword wide ascii
        $gen_much_sus24 = "exploit" fullword wide ascii
        $gen_much_sus25 = "Exploit" fullword wide ascii
        $gen_much_sus26 = "TVqQAAMAAA" wide ascii
        $gen_much_sus30 = "Hacker" wide ascii
        $gen_much_sus31 = "HACKED" fullword wide ascii
        $gen_much_sus32 = "hacked" fullword wide ascii
        $gen_much_sus33 = "hacker" wide ascii
        $gen_much_sus34 = "grayhat" nocase wide ascii
        $gen_much_sus35 = "Microsoft FrontPage" wide ascii
        $gen_much_sus36 = "Rootkit" wide ascii
        $gen_much_sus37 = "rootkit" wide ascii
        $gen_much_sus38 = "/*-/*-*/" wide ascii
        $gen_much_sus39 = "u\"+\"n\"+\"s" wide ascii
        $gen_much_sus40 = "\"e\"+\"v" wide ascii
        $gen_much_sus41 = "a\"+\"l\"" wide ascii
        $gen_much_sus42 = "\"+\"(\"+\"" wide ascii
        $gen_much_sus43 = "q\"+\"u\"" wide ascii
        $gen_much_sus44 = "\"u\"+\"e" wide ascii
        $gen_much_sus45 = "/*//*/" wide ascii
        $gen_much_sus46 = "(\"/*/\"" wide ascii
        $gen_much_sus47 = "eval(eval(" wide ascii
        // self remove
        $gen_much_sus48 = "unlink(__FILE__)" wide ascii
        $gen_much_sus49 = "Shell.Users" wide ascii
        $gen_much_sus50 = "PasswordType=Regular" wide ascii
        $gen_much_sus51 = "-Expire=0" wide ascii
        $gen_much_sus60 = "_=$$_" wide ascii
        $gen_much_sus61 = "_=$$_" wide ascii
        $gen_much_sus62 = "++;$" wide ascii
        $gen_much_sus63 = "++; $" wide ascii
        $gen_much_sus64 = "_.=$_" wide ascii
        $gen_much_sus70 = "-perm -04000" wide ascii
        $gen_much_sus71 = "-perm -02000" wide ascii
        $gen_much_sus72 = "grep -li password" wide ascii
        $gen_much_sus73 = "-name config.inc.php" wide ascii
        // touch without parameters sets the time to now, not malicious and gives fp
        $gen_much_sus75 = "password crack" wide ascii
        $gen_much_sus76 = "mysqlDll.dll" wide ascii
        $gen_much_sus77 = "net user" wide ascii
        $gen_much_sus80 = "fopen(\".htaccess\",\"w" wide ascii
        $gen_much_sus81 = /strrev\(['"]/ wide ascii
        $gen_much_sus82 = "PHPShell" fullword wide ascii
        $gen_much_sus821= "PHP Shell" fullword wide ascii
        $gen_much_sus83 = "phpshell" fullword wide ascii
        $gen_much_sus84 = "PHPshell" fullword wide ascii
        $gen_much_sus87 = "deface" wide ascii
        $gen_much_sus88 = "Deface" wide ascii
        $gen_much_sus89 = "backdoor" wide ascii
        $gen_much_sus90 = "r00t" fullword wide ascii
        $gen_much_sus91 = "xp_cmdshell" fullword wide ascii
        $gen_much_sus92 = "base64_decode(base64_decode(" fullword wide ascii
        $gen_much_sus93 = "eval(\"/*" wide ascii

        $gif = { 47 49 46 38 }


    condition:
        //any of them or
        not (
            any of ( $gfp* )
        )
        and not (
            any of ( $gfp_tiny* )
        )
        and (
            any of ( $inp* )
        )
        and (
            not any of ( $cfp* ) and
                (
                    any of ( $callback* )  or
                    all of ( $m_callback* )
                )
            )
            and
            ( filesize < 1000 or (
                $gif at 0 or
                (
                    filesize < 4KB and
                    (
                        1 of ( $gen_much_sus* ) or
                        2 of ( $gen_bit_sus* )
                    )
                ) or (
                    filesize < 20KB and
                    (
                        2 of ( $gen_much_sus* ) or
                        3 of ( $gen_bit_sus* )
                    )
                ) or (
                    filesize < 50KB and
                    (
                        2 of ( $gen_much_sus* ) or
                        4 of ( $gen_bit_sus* )
                    )
                ) or (
                    filesize < 100KB and
                    (
                        2 of ( $gen_much_sus* ) or
                        6 of ( $gen_bit_sus* )
                    )
                ) or (
                    filesize < 150KB and
                    (
                        3 of ( $gen_much_sus* ) or
                        7 of ( $gen_bit_sus* )
                    )
                ) or (
                    filesize < 500KB and
                    (
                        4 of ( $gen_much_sus* ) or
                        8 of ( $gen_bit_sus* )
                    )
                )
            )
        )
}

rule WEBSHELL_php_base64_encoded_payloads : FILE {
    meta:
        description = "php webshell containing base64 encoded payload"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021/01/07"
        modified = "2023-04-05"
        hash = "88d0d4696c9cb2d37d16e330e236cb37cfaec4cd"
        hash = "e3b4e5ec29628791f836e15500f6fdea19beaf3e8d9981c50714656c50d3b365"
        hash = "e726cd071915534761822805724c6c6bfe0fcac604a86f09437f03f301512dc5"
        hash = "39b8871928d00c7de8d950d25bff4cb19bf9bd35942f7fee6e0f397ff42fbaee"
        hash = "8cc9802769ede56f1139abeaa0735526f781dff3b6c6334795d1d0f19161d076"
        hash = "4cda0c798908b61ae7f4146c6218d7b7de14cbcd7c839edbdeb547b5ae404cd4"
        hash = "afd9c9b0df0b2ca119914ea0008fad94de3bd93c6919f226b793464d4441bdf4"
        hash = "b2048dc30fc7681094a0306a81f4a4cc34f0b35ccce1258c20f4940300397819"
        hash = "da6af9a4a60e3a484764010fbf1a547c2c0a2791e03fc11618b8fc2605dceb04"
        hash = "222cd9b208bd24955bcf4f9976f9c14c1d25e29d361d9dcd603d57f1ea2b0aee"
        hash = "98c1937b9606b1e8e0eebcb116a784c9d2d3db0039b21c45cba399e86c92c2fa"
        hash = "6b6cd1ef7e78e37cbcca94bfb5f49f763ba2f63ed8b33bc4d7f9e5314c87f646"
        hash = "51c2c8b94c4b8cce806735bcf6e5aa3f168f0f7addce47b699b9a4e31dc71b47"
        hash = "7a16311a371f03b29d5220484e7ecbe841cfaead4e73c17aa6a9c23b5d94544d"
        hash = "e2b1dfcfaa61e92526a3a444be6c65330a8db4e692543a421e19711760f6ffe2"

    strings:
        $decode1 = "base64_decode" fullword nocase wide ascii
        $decode2 = "openssl_decrypt" fullword nocase wide ascii
        // exec
        $one1 = "leGVj"
        $one2 = "V4ZW"
        $one3 = "ZXhlY"
        $one4 = "UAeABlAGMA"
        $one5 = "lAHgAZQBjA"
        $one6 = "ZQB4AGUAYw"
        // shell_exec
        $two1 = "zaGVsbF9leGVj"
        $two2 = "NoZWxsX2V4ZW"
        $two3 = "c2hlbGxfZXhlY"
        $two4 = "MAaABlAGwAbABfAGUAeABlAGMA"
        $two5 = "zAGgAZQBsAGwAXwBlAHgAZQBjA"
        $two6 = "cwBoAGUAbABsAF8AZQB4AGUAYw"
        // passthru
        $three1 = "wYXNzdGhyd"
        $three2 = "Bhc3N0aHJ1"
        $three3 = "cGFzc3Rocn"
        $three4 = "AAYQBzAHMAdABoAHIAdQ"
        $three5 = "wAGEAcwBzAHQAaAByAHUA"
        $three6 = "cABhAHMAcwB0AGgAcgB1A"
        // system
        $four1 = "zeXN0ZW"
        $four2 = "N5c3Rlb"
        $four3 = "c3lzdGVt"
        $four4 = "MAeQBzAHQAZQBtA"
        $four5 = "zAHkAcwB0AGUAbQ"
        $four6 = "cwB5AHMAdABlAG0A"
        // popen
        $five1 = "wb3Blb"
        $five2 = "BvcGVu"
        $five3 = "cG9wZW"
        $five4 = "AAbwBwAGUAbg"
        $five5 = "wAG8AcABlAG4A"
        $five6 = "cABvAHAAZQBuA"
        // proc_open
        $six1 = "wcm9jX29wZW"
        $six2 = "Byb2Nfb3Blb"
        $six3 = "cHJvY19vcGVu"
        $six4 = "AAcgBvAGMAXwBvAHAAZQBuA"
        $six5 = "wAHIAbwBjAF8AbwBwAGUAbg"
        $six6 = "cAByAG8AYwBfAG8AcABlAG4A"
        // pcntl_exec
        $seven1 = "wY250bF9leGVj"
        $seven2 = "BjbnRsX2V4ZW"
        $seven3 = "cGNudGxfZXhlY"
        $seven4 = "AAYwBuAHQAbABfAGUAeABlAGMA"
        $seven5 = "wAGMAbgB0AGwAXwBlAHgAZQBjA"
        $seven6 = "cABjAG4AdABsAF8AZQB4AGUAYw"
        // eval
        $eight1 = "ldmFs"
        $eight2 = "V2YW"
        $eight3 = "ZXZhb"
        $eight4 = "UAdgBhAGwA"
        $eight5 = "lAHYAYQBsA"
        $eight6 = "ZQB2AGEAbA"
        // assert
        $nine1 = "hc3Nlcn"
        $nine2 = "Fzc2Vyd"
        $nine3 = "YXNzZXJ0"
        $nine4 = "EAcwBzAGUAcgB0A"
        $nine5 = "hAHMAcwBlAHIAdA"
        $nine6 = "YQBzAHMAZQByAHQA"

        // false positives

        // execu
        $execu1 = "leGVjd"
        $execu2 = "V4ZWN1"
        $execu3 = "ZXhlY3"

        // esystem like e.g. filesystem
        $esystem1 = "lc3lzdGVt"
        $esystem2 = "VzeXN0ZW"
        $esystem3 = "ZXN5c3Rlb"

        // opening
        $opening1 = "vcGVuaW5n"
        $opening2 = "9wZW5pbm"
        $opening3 = "b3BlbmluZ"

        // false positives
        $fp1 = { D0 CF 11 E0 A1 B1 1A E1 }
        // api.telegram
        $fp2 = "YXBpLnRlbGVncmFtLm9"
        // Log files
        $fp3 = " GET /"
        $fp4 = " POST /"

    $fpa1 = "/cn=Recipients"

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

    condition:
        filesize < 300KB and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and not any of ( $fp* ) and any of ( $decode* ) and
        ( ( any of ( $one* ) and not any of ( $execu* ) ) or any of ( $two* ) or any of ( $three* ) or
        ( any of ( $four* ) and not any of ( $esystem* ) ) or
        ( any of ( $five* ) and not any of ( $opening* ) ) or any of ( $six* ) or any of ( $seven* ) or any of ( $eight* ) or any of ( $nine* ) )
}

rule webshell_php_unknown_1
{
    meta:
        description = "obfuscated php webshell"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        hash = "12ce6c7167b33cc4e8bdec29fb1cfc44ac9487d1"
        hash = "cf4abbd568ce0c0dfce1f2e4af669ad2"
        date = "2021/01/07"
        modified = "2023-04-05"

    strings:
        $sp0 = /^<\?php \$[a-z]{3,30} = '/ wide ascii
        $sp1 = "=explode(chr(" wide ascii
        $sp2 = "; if (!function_exists('" wide ascii
        $sp3 = " = NULL; for(" wide ascii

    condition:
        filesize <300KB and all of ($sp*)
}

rule webshell_php_generic_eval
{
    meta:
        description = "Generic PHP webshell which uses any eval/exec function in the same line with user input"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021/01/07"
        modified = "2023-04-05"
        hash = "a61437a427062756e2221bfb6d58cd62439d09d9"
        hash = "90c5cc724ec9cf838e4229e5e08955eec4d7bf95"
        hash = "2b41abc43c5b6c791d4031005bf7c5104a98e98a00ee24620ce3e8e09a78e78f"
        hash = "5c68a0fa132216213b66a114375b07b08dc0cb729ddcf0a29bff9ca7a22eaaf4"
        hash = "de3c01f55d5346577922bbf449faaaaa1c8d1aaa64c01e8a1ee8c9d99a41a1be"
        hash = "124065176d262bde397b1911648cea16a8ff6a4c8ab072168d12bf0662590543"
        hash = "cd7450f3e5103e68741fd086df221982454fbcb067e93b9cbd8572aead8f319b"
        hash = "ab835ce740890473adf5cc804055973b926633e39c59c2bd98da526b63e9c521"
        hash = "31ff9920d401d4fbd5656a4f06c52f1f54258bc42332fc9456265dca7bb4c1ea"
        hash = "64e6c08aa0b542481b86a91cdf1f50c9e88104a8a4572a8c6bd312a9daeba60e"
        hash = "80e98e8a3461d7ba15d869b0641cdd21dd5b957a2006c3caeaf6f70a749ca4bb"
        hash = "93982b8df76080e7ba4520ae4b4db7f3c867f005b3c2f84cb9dff0386e361c35"
        hash = "51c2c8b94c4b8cce806735bcf6e5aa3f168f0f7addce47b699b9a4e31dc71b47"
        hash = "7a16311a371f03b29d5220484e7ecbe841cfaead4e73c17aa6a9c23b5d94544d"
        hash = "7ca5dec0515dd6f401cb5a52c313f41f5437fc43eb62ea4bcc415a14212d09e9"
        hash = "fd5f0f81204ca6ca6e93343500400d5853012e88254874fc9f62efe0fde7ab3c"
        hash = "883f48ed4e9646da078cabf6b8b4946d9f199660262502650f76450ecf60ddd5"
        hash = "6d042b6393669bb4d98213091cabe554ab192a6c916e86c04d06cc2a4ca92c00"
        hash = "dd5d8a9b4bb406e0b8f868165a1714fe54ffb18e621582210f96f6e5ae850b33"


    strings:
        // new: eval($GLOBALS['_POST'
        $geval = /\b(exec|shell_exec|passthru|system|popen|proc_open|pcntl_exec|eval|assert)[\t ]*(\(base64_decode)?(\(stripslashes)?[\t ]*(\(trim)?[\t ]*\(\$(_POST|_GET|_REQUEST|_SERVER\s?\[['"]HTTP_|GLOBALS\[['"]_(POST|GET|REQUEST))/ wide ascii

        //strings from private rule php_false_positive
        // try to use only strings which would be flagged by themselves as suspicious by other rules, e.g. eval
        // a good choice is a string with good atom quality = ideally 4 unusual characters next to each other
        $gfp1  = "eval(\"return [$serialised_parameter" // elgg
        $gfp2  = "$this->assert(strpos($styles, $"
        $gfp3  = "$module = new $_GET['module']($_GET['scope']);"
        $gfp4  = "$plugin->$_POST['action']($_POST['id']);"
        $gfp5  = "$_POST[partition_by]($_POST["
        $gfp6  = "$object = new $_REQUEST['type']($_REQUEST['id']);"
        $gfp7  = "The above example code can be easily exploited by passing in a string such as" // ... ;)
        $gfp8  = "Smarty_Internal_Debug::start_render($_template);"
        $gfp9  = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
        $gfp10 = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
        $gfp11 = "(eval (getenv \"EPROLOG\")))"
        $gfp12 = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"
        // Log files
        $gfp_3 = " GET /"
        $gfp_4 = " POST /"
    condition:
        filesize < 300KB and not (
            any of ( $gfp* )
        )
        and $geval
}

rule webshell_php_double_eval_tiny
{
    meta:
        description = "PHP webshell which probably hides the input inside an eval()ed obfuscated string"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        hash = "aabfd179aaf716929c8b820eefa3c1f613f8dcac"
        date = "2021-01-11"
        modified = "2023-04-05"
        score = 50
        hash = "f66fb918751acc7b88a17272a044b5242797976c73a6e54ac6b04b02f61e9761"
        hash = "6b2f0a3bd80019dea536ddbf92df36ab897dd295840cb15bb7b159d0ee2106ff"


    strings:
        $payload = /(\beval[\t ]*\([^)]|\bassert[\t ]*\([^)])/ nocase wide ascii
        $fp1 = "clone" fullword wide ascii
        $fp2 = "* @assert" ascii
        $fp3 = "*@assert" ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

    condition:
        filesize > 70 and filesize < 300 and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and #payload >= 2 and not any of ( $fp* )
}

rule webshell_php_obfuscated
{
    meta:
        description = "PHP webshell obfuscated"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021/01/12"
        modified = "2023-04-05"
        hash = "eec9ac58a1e763f5ea0f7fa249f1fe752047fa60"
        hash = "181a71c99a4ae13ebd5c94bfc41f9ec534acf61cd33ef5bce5fb2a6f48b65bf4"
        hash = "76d4e67e13c21662c4b30aab701ce9cdecc8698696979e504c288f20de92aee7"
        hash = "1d0643927f04cb1133f00aa6c5fa84aaf88e5cf14d7df8291615b402e8ab6dc2"
    strings:

        //strings from private rule php_false_positive
        // try to use only strings which would be flagged by themselves as suspicious by other rules, e.g. eval
        // a good choice is a string with good atom quality = ideally 4 unusual characters next to each other
        $gfp1  = "eval(\"return [$serialised_parameter" // elgg
        $gfp2  = "$this->assert(strpos($styles, $"
        $gfp3  = "$module = new $_GET['module']($_GET['scope']);"
        $gfp4  = "$plugin->$_POST['action']($_POST['id']);"
        $gfp5  = "$_POST[partition_by]($_POST["
        $gfp6  = "$object = new $_REQUEST['type']($_REQUEST['id']);"
        $gfp7  = "The above example code can be easily exploited by passing in a string such as" // ... ;)
        $gfp8  = "Smarty_Internal_Debug::start_render($_template);"
        $gfp9  = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
        $gfp10 = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
        $gfp11 = "(eval (getenv \"EPROLOG\")))"
        $gfp12 = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

        //strings from private rule capa_php_obfuscation_multi
        $o1 = "chr(" nocase wide ascii
        $o2 = "chr (" nocase wide ascii
        // not excactly a string function but also often used in obfuscation
        $o3 = "goto" fullword nocase wide ascii
        $o4 = "\\x9" wide ascii
        $o5 = "\\x3" wide ascii
        // just picking some random numbers because they should appear often enough in a long obfuscated blob and it's faster than a regex
        $o6 = "\\61" wide ascii
        $o7 = "\\44" wide ascii
        $o8 = "\\112" wide ascii
        $o9 = "\\120" wide ascii
        $fp1 = "$goto" wide ascii

        //strings from private rule capa_php_payload
        // \([^)] to avoid matching on e.g. eval() in comments
        $cpayload1 = /\beval[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload2 = /\bexec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload3 = /\bshell_exec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload4 = /\bpassthru[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload5 = /\bsystem[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload6 = /\bpopen[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload7 = /\bproc_open[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload8 = /\bpcntl_exec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload9 = /\bassert[\n\t ]*\([^)0]/ nocase wide ascii
        $cpayload10 = /\bpreg_replace[\n\t ]*(\(.{1,|\/\*)100}\/[ismxADSUXju]{0,11}(e|\\x65)/ nocase wide ascii
        $cpayload12 = /\bmb_ereg_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
        $cpayload13 = /\bmb_eregi_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
        $cpayload20 = /\bcreate_function[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload21 = /\bReflectionFunction[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload22 = /fetchall\(PDO::FETCH_FUNC[\n\t ]*[,}\)]/ nocase wide ascii

        $m_cpayload_preg_filter1 = /\bpreg_filter[\n\t ]*(\([^\)]|\/\*)/ nocase wide ascii
        $m_cpayload_preg_filter2 = "'|.*|e'" nocase wide ascii
        // TODO backticks

    condition:
        not (
            any of ( $gfp* )
        )
        and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and (
            // allow different amounts of potential obfuscation functions depending on filesize
            not $fp1 and (
                (
                        filesize < 20KB and
                        (
                            ( #o1+#o2 ) > 50 or
                            #o3 > 10 or
                            ( #o4+#o5+#o6+#o7+#o8+#o9 ) > 20
                        )
                ) or (
                        filesize < 200KB and
                        (
                            ( #o1+#o2 ) > 200 or
                            #o3 > 30 or
                            ( #o4+#o5+#o6+#o7+#o8+#o9 ) > 30
                        )

                )
            )


        )
        and (
            any of ( $cpayload* ) or
        all of ( $m_cpayload_preg_filter* )
        )

}

rule webshell_php_obfuscated_encoding
{
    meta:
        description = "PHP webshell obfuscated by encoding"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021/04/18"
        modified = "2023-04-05"
        score = 70
        hash = "119fc058c9c5285498a47aa271ac9a27f6ada1bf4d854ccd4b01db993d61fc52"
        hash = "d5ca3e4505ea122019ea263d6433221030b3f64460d3ce2c7d0d63ed91162175"
        hash = "8a1e2d72c82f6a846ec066d249bfa0aaf392c65149d39b7b15ba19f9adc3b339"


    strings:
        // one without plain e, one without plain v, to avoid hitting on plain "eval("
        $enc_eval1 = /(e|\\x65|\\101)(\\x76|\\118)(a|\\x61|\\97)(l|\\x6c|\\108)(\(|\\x28|\\40)/ wide ascii nocase
        $enc_eval2 = /(\\x65|\\101)(v|\\x76|\\118)(a|\\x61|\\97)(l|\\x6c|\\108)(\(|\\x28|\\40)/ wide ascii nocase
        // one without plain a, one without plain s, to avoid hitting on plain "assert("
        $enc_assert1 = /(a|\\97|\\x61)(\\115|\\x73)(s|\\115|\\x73)(e|\\101|\\x65)(r|\\114|\\x72)(t|\\116|\\x74)(\(|\\x28|\\40)/ wide ascii nocase
        $enc_assert2 = /(\\97|\\x61)(s|\\115|\\x73)(s|\\115|\\x73)(e|\\101|\\x65)(r|\\114|\\x72)(t|\\116|\\x74)(\(|\\x28|\\40)/ wide ascii nocase

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

    condition:
        filesize < 700KB and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and any of ( $enc* )
}

rule webshell_php_obfuscated_encoding_mixed_dec_and_hex
{
    meta:
        description = "PHP webshell obfuscated by encoding of mixed hex and dec"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021/04/18"
        modified = "2023-04-05"
        hash = "0e21931b16f30b1db90a27eafabccc91abd757fa63594ba8a6ad3f477de1ab1c"
        hash = "929975272f0f42bf76469ed89ebf37efcbd91c6f8dac1129c7ab061e2564dd06"
        hash = "88fce6c1b589d600b4295528d3fcac161b581f739095b99cd6c768b7e16e89ff"
        hash = "883f48ed4e9646da078cabf6b8b4946d9f199660262502650f76450ecf60ddd5"
        hash = "50389c3b95a9de00220fc554258fda1fef01c62dad849e66c8a92fc749523457"
        hash = "c4ab4319a77b751a45391aa01cde2d765b095b0e3f6a92b0b8626d5c7e3ad603"
        hash = "df381f04fca2522e2ecba0f5de3f73a655d1540e1cf865970f5fa3bf52d2b297"
        hash = "401388d8b97649672d101bf55694dd175375214386253d0b4b8d8d801a89549c"
        hash = "99fc39a12856cc1a42bb7f90ffc9fe0a5339838b54a63e8f00aa98961c900618"
        hash = "fb031af7aa459ee88a9ca44013a76f6278ad5846aa20e5add4aeb5fab058d0ee"
        hash = "dd5d8a9b4bb406e0b8f868165a1714fe54ffb18e621582210f96f6e5ae850b33"
        hash = "0ff05e6695074f98b0dee6200697a997c509a652f746d2c1c92c0b0a0552ca47"

    strings:
        // "e\x4a\x48\x5a\x70\x63\62\154\x30\131\171\101\x39\111\x43\x52\x66\x51\
        //$mix = /['"]\\x?[0-9a-f]{2,3}[\\\w]{2,20}\\\d{1,3}[\\\w]{2,20}\\x[0-9a-f]{2}\\/ wide ascii nocase
        $mix = /['"](\w|\\x?[0-9a-f]{2,3})[\\x0-9a-f]{2,20}\\\d{1,3}[\\x0-9a-f]{2,20}\\x[0-9a-f]{2}\\/ wide ascii nocase

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

    condition:
        filesize < 700KB and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and any of ( $mix* )
}

rule webshell_php_obfuscated_tiny
{
    meta:
        description = "PHP webshell obfuscated"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021/01/12"
        modified = "2023-04-05"

    strings:
        // 'ev'.'al'
        $obf1 = /\w'\.'\w/ wide ascii
        $obf2 = /\w\"\.\"\w/ wide ascii
        $obf3 = "].$" wide ascii

        //strings from private rule php_false_positive
        // try to use only strings which would be flagged by themselves as suspicious by other rules, e.g. eval
        // a good choice is a string with good atom quality = ideally 4 unusual characters next to each other
        $gfp1  = "eval(\"return [$serialised_parameter" // elgg
        $gfp2  = "$this->assert(strpos($styles, $"
        $gfp3  = "$module = new $_GET['module']($_GET['scope']);"
        $gfp4  = "$plugin->$_POST['action']($_POST['id']);"
        $gfp5  = "$_POST[partition_by]($_POST["
        $gfp6  = "$object = new $_REQUEST['type']($_REQUEST['id']);"
        $gfp7  = "The above example code can be easily exploited by passing in a string such as" // ... ;)
        $gfp8  = "Smarty_Internal_Debug::start_render($_template);"
        $gfp9  = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
        $gfp10 = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
        $gfp11 = "(eval (getenv \"EPROLOG\")))"
        $gfp12 = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

        //strings from private rule capa_php_payload
        // \([^)] to avoid matching on e.g. eval() in comments
        $cpayload1 = /\beval[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload2 = /\bexec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload3 = /\bshell_exec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload4 = /\bpassthru[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload5 = /\bsystem[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload6 = /\bpopen[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload7 = /\bproc_open[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload8 = /\bpcntl_exec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload9 = /\bassert[\n\t ]*\([^)0]/ nocase wide ascii
        $cpayload10 = /\bpreg_replace[\n\t ]*(\(.{1,|\/\*)100}\/[ismxADSUXju]{0,11}(e|\\x65)/ nocase wide ascii
        $cpayload12 = /\bmb_ereg_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
        $cpayload13 = /\bmb_eregi_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
        $cpayload20 = /\bcreate_function[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload21 = /\bReflectionFunction[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload22 = /fetchall\(PDO::FETCH_FUNC[\n\t ]*[,}\)]/ nocase wide ascii

        $m_cpayload_preg_filter1 = /\bpreg_filter[\n\t ]*(\([^\)]|\/\*)/ nocase wide ascii
        $m_cpayload_preg_filter2 = "'|.*|e'" nocase wide ascii
        // TODO backticks

    condition:
        //any of them or
        filesize < 500 and not (
            any of ( $gfp* )
        )
        and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and (
            any of ( $cpayload* ) or
        all of ( $m_cpayload_preg_filter* )
        )
        and
        ( ( #obf1 + #obf2 ) > 2 or #obf3 > 10 )
}

rule webshell_php_obfuscated_str_replace
{
    meta:
        description = "PHP webshell which eval()s obfuscated string"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021/01/12"
        modified = "2023-04-05"
        hash = "691305753e26884d0f930cda0fe5231c6437de94"
        hash = "7efd463aeb5bf0120dc5f963b62463211bd9e678"
        hash = "fb655ddb90892e522ae1aaaf6cd8bde27a7f49ef"
        hash = "d1863aeca1a479462648d975773f795bb33a7af2"
        hash = "4d31d94b88e2bbd255cf501e178944425d40ee97"
        hash = "e1a2af3477d62a58f9e6431f5a4a123fb897ea80"

    strings:
        $payload1 = "str_replace" fullword wide ascii
        $payload2 = "function" fullword wide ascii
        $goto = "goto" fullword wide ascii
        //$hex  = "\\x"
        $chr1  = "\\61" wide ascii
        $chr2  = "\\112" wide ascii
        $chr3  = "\\120" wide ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

    condition:
        filesize < 300KB and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and any of ( $payload* ) and #goto > 1 and
        ( #chr1 > 10 or #chr2 > 10 or #chr3 > 10 )
}

rule webshell_php_obfuscated_fopo
{
    meta:
        description = "PHP webshell which eval()s obfuscated string"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        hash = "fbcff8ea5ce04fc91c05384e847f2c316e013207"
        hash = "6da57ad8be1c587bb5cc8a1413f07d10fb314b72"
        hash = "a698441f817a9a72908a0d93a34133469f33a7b34972af3e351bdccae0737d99"
        date = "2021/01/12"
        modified = "2023-04-05"

    strings:
        $payload = /(\beval[\t ]*\([^)]|\bassert[\t ]*\([^)])/ nocase wide ascii
        // ;@eval(
        $one1 = "7QGV2YWwo" wide ascii
        $one2 = "tAZXZhbC" wide ascii
        $one3 = "O0BldmFsK" wide ascii
        $one4 = "sAQABlAHYAYQBsACgA" wide ascii
        $one5 = "7AEAAZQB2AGEAbAAoA" wide ascii
        $one6 = "OwBAAGUAdgBhAGwAKA" wide ascii
        // ;@assert(
        $two1 = "7QGFzc2VydC" wide ascii
        $two2 = "tAYXNzZXJ0K" wide ascii
        $two3 = "O0Bhc3NlcnQo" wide ascii
        $two4 = "sAQABhAHMAcwBlAHIAdAAoA" wide ascii
        $two5 = "7AEAAYQBzAHMAZQByAHQAKA" wide ascii
        $two6 = "OwBAAGEAcwBzAGUAcgB0ACgA" wide ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

    condition:
        filesize < 3000KB and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and $payload and
        ( any of ( $one* ) or any of ( $two* ) )
}

rule webshell_php_gzinflated
{
    meta:
        description = "PHP webshell which directly eval()s obfuscated string"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021/01/12"
        modified = "2023-04-05"
        hash = "49e5bc75a1ec36beeff4fbaeb16b322b08cf192d"

    strings:
        $payload2 = /eval\s?\(\s?("\?>".)?gzinflate\s?\(\s?base64_decode\s?\(/ wide ascii nocase
        $payload4 = /eval\s?\(\s?("\?>".)?gzuncompress\s?\(\s?(base64_decode|gzuncompress)/ wide ascii nocase
        $payload6 = /eval\s?\(\s?("\?>".)?gzdecode\s?\(\s?base64_decode\s?\(/ wide ascii nocase
        $payload7 = /eval\s?\(\s?base64_decode\s?\(/ wide ascii nocase
        $payload8 = /eval\s?\(\s?pack\s?\(/ wide ascii nocase

        // api.telegram
        $fp1 = "YXBpLnRlbGVncmFtLm9"

        //strings from private rule php_false_positive
        // try to use only strings which would be flagged by themselves as suspicious by other rules, e.g. eval
        // a good choice is a string with good atom quality = ideally 4 unusual characters next to each other
        $gfp1  = "eval(\"return [$serialised_parameter" // elgg
        $gfp2  = "$this->assert(strpos($styles, $"
        $gfp3  = "$module = new $_GET['module']($_GET['scope']);"
        $gfp4  = "$plugin->$_POST['action']($_POST['id']);"
        $gfp5  = "$_POST[partition_by]($_POST["
        $gfp6  = "$object = new $_REQUEST['type']($_REQUEST['id']);"
        $gfp7  = "The above example code can be easily exploited by passing in a string such as" // ... ;)
        $gfp8  = "Smarty_Internal_Debug::start_render($_template);"
        $gfp9  = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
        $gfp10 = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
        $gfp11 = "(eval (getenv \"EPROLOG\")))"
        $gfp12 = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

    condition:
        filesize < 700KB and not (
            any of ( $gfp* )
        )
        and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and 1 of ( $payload* ) and not any of ( $fp* )
}

rule webshell_php_obfuscated_3
{
    meta:
        description = "PHP webshell which eval()s obfuscated string"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021/04/17"
        modified = "2023-04-05"

    strings:
        $obf1 = "chr(" wide ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

        //strings from private rule capa_php_callback
        // the end is 1. ( followed by anything but a direct closing ) 2. /* for the start of an obfuscation comment
        $callback1 = /\bob_start[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback2 = /\barray_diff_uassoc[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback3 = /\barray_diff_ukey[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback4 = /\barray_filter[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback5 = /\barray_intersect_uassoc[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback6 = /\barray_intersect_ukey[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback7 = /\barray_map[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback8 = /\barray_reduce[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback9 = /\barray_udiff_assoc[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback10 = /\barray_udiff_uassoc[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback11 = /\barray_udiff[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback12 = /\barray_uintersect_assoc[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback13 = /\barray_uintersect_uassoc[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback14 = /\barray_uintersect[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback15 = /\barray_walk_recursive[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback16 = /\barray_walk[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback17 = /\bassert_options[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback18 = /\buasort[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback19 = /\buksort[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback20 = /\busort[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback21 = /\bpreg_replace_callback[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback22 = /\bspl_autoload_register[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback23 = /\biterator_apply[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback24 = /\bcall_user_func[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback25 = /\bcall_user_func_array[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback26 = /\bregister_shutdown_function[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback27 = /\bregister_tick_function[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback28 = /\bset_error_handler[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback29 = /\bset_exception_handler[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback30 = /\bsession_set_save_handler[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback31 = /\bsqlite_create_aggregate[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback32 = /\bsqlite_create_function[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $callback33 = /\bmb_ereg_replace_callback[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii

        $m_callback1 = /\bfilter_var[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $m_callback2 = "FILTER_CALLBACK" fullword wide ascii

        $cfp1 = /ob_start\(['\"]ob_gzhandler/ nocase wide ascii
        $cfp2 = "IWPML_Backend_Action_Loader" ascii wide
        $cfp3 = "<?phpclass WPML" ascii

        //strings from private rule capa_php_payload
        // \([^)] to avoid matching on e.g. eval() in comments
        $cpayload1 = /\beval[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload2 = /\bexec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload3 = /\bshell_exec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload4 = /\bpassthru[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload5 = /\bsystem[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload6 = /\bpopen[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload7 = /\bproc_open[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload8 = /\bpcntl_exec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload9 = /\bassert[\n\t ]*\([^)0]/ nocase wide ascii
        $cpayload10 = /\bpreg_replace[\n\t ]*(\(.{1,|\/\*)100}\/[ismxADSUXju]{0,11}(e|\\x65)/ nocase wide ascii
        $cpayload12 = /\bmb_ereg_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
        $cpayload13 = /\bmb_eregi_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
        $cpayload20 = /\bcreate_function[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload21 = /\bReflectionFunction[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload22 = /fetchall\(PDO::FETCH_FUNC[\n\t ]*[,}\)]/ nocase wide ascii

        $m_cpayload_preg_filter1 = /\bpreg_filter[\n\t ]*(\([^\)]|\/\*)/ nocase wide ascii
        $m_cpayload_preg_filter2 = "'|.*|e'" nocase wide ascii
        // TODO backticks

        //strings from private rule capa_php_obfuscation_single
        $cobfs1 = "gzinflate" fullword nocase wide ascii
        $cobfs2 = "gzuncompress" fullword nocase wide ascii
        $cobfs3 = "gzdecode" fullword nocase wide ascii
        $cobfs4 = "base64_decode" fullword nocase wide ascii
        $cobfs5 = "pack" fullword nocase wide ascii
        $cobfs6 = "undecode" fullword nocase wide ascii

        //strings from private rule capa_gen_sus

        // these strings are just a bit suspicious, so several of them are needed, depending on filesize
        $gen_bit_sus1  = /:\s{0,20}eval}/ nocase wide ascii
        $gen_bit_sus2  = /\.replace\(\/\w\/g/ nocase wide ascii
        $gen_bit_sus6  = "self.delete"
        $gen_bit_sus9  = "\"cmd /c" nocase
        $gen_bit_sus10 = "\"cmd\"" nocase
        $gen_bit_sus11 = "\"cmd.exe" nocase
        $gen_bit_sus12 = "%comspec%" wide ascii
        $gen_bit_sus13 = "%COMSPEC%" wide ascii
        //TODO:$gen_bit_sus12 = ".UserName" nocase
        $gen_bit_sus18 = "Hklm.GetValueNames();" nocase
        // bonus string for proxylogon exploiting webshells
        $gen_bit_sus19 = "http://schemas.microsoft.com/exchange/" wide ascii
        $gen_bit_sus21 = "\"upload\"" wide ascii
        $gen_bit_sus22 = "\"Upload\"" wide ascii
        $gen_bit_sus23 = "UPLOAD" fullword wide ascii
        $gen_bit_sus24 = "fileupload" wide ascii
        $gen_bit_sus25 = "file_upload" wide ascii
        // own base64 or base32 func
        $gen_bit_sus29 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" fullword wide ascii
        $gen_bit_sus29b = "abcdefghijklmnopqrstuvwxyz234567" fullword wide ascii
        $gen_bit_sus30 = "serv-u" wide ascii
        $gen_bit_sus31 = "Serv-u" wide ascii
        $gen_bit_sus32 = "Army" fullword wide ascii
        // single letter paramweter
        $gen_bit_sus33 = /\$_(GET|POST|REQUEST)\["\w"\]/ fullword wide ascii
        $gen_bit_sus34 = "Content-Transfer-Encoding: Binary" wide ascii
        $gen_bit_sus35 = "crack" fullword wide ascii

        $gen_bit_sus44 = "<pre>" wide ascii
        $gen_bit_sus45 = "<PRE>" wide ascii
        $gen_bit_sus46 = "shell_" wide ascii
        //fp: $gen_bit_sus47 = "Shell" fullword wide ascii
        $gen_bit_sus50 = "bypass" wide ascii
        $gen_bit_sus52 = " ^ $" wide ascii
        $gen_bit_sus53 = ".ssh/authorized_keys" wide ascii
        $gen_bit_sus55 = /\w'\.'\w/ wide ascii
        $gen_bit_sus56 = /\w\"\.\"\w/ wide ascii
        $gen_bit_sus57 = "dumper" wide ascii
        $gen_bit_sus59 = "'cmd'" wide ascii
        $gen_bit_sus60 = "\"execute\"" wide ascii
        $gen_bit_sus61 = "/bin/sh" wide ascii
        $gen_bit_sus62 = "Cyber" wide ascii
        $gen_bit_sus63 = "portscan" fullword wide ascii
        //$gen_bit_sus64 = "\"command\"" fullword wide ascii
        //$gen_bit_sus65 = "'command'" fullword wide ascii
        $gen_bit_sus66 = "whoami" fullword wide ascii
        $gen_bit_sus67 = "$password='" fullword wide ascii
        $gen_bit_sus68 = "$password=\"" fullword wide ascii
        $gen_bit_sus69 = "$cmd" fullword wide ascii
        $gen_bit_sus70 = "\"?>\"." fullword wide ascii
        $gen_bit_sus71 = "Hacking" fullword wide ascii
        $gen_bit_sus72 = "hacking" fullword wide ascii
        $gen_bit_sus73 = ".htpasswd" wide ascii
        $gen_bit_sus74 = /\btouch\(\$[^,]{1,30},/ wide ascii

        // very suspicious strings, one is enough
        $gen_much_sus7  = "Web Shell" nocase
        $gen_much_sus8  = "WebShell" nocase
        $gen_much_sus3  = "hidded shell"
        $gen_much_sus4  = "WScript.Shell.1" nocase
        $gen_much_sus5  = "AspExec"
        $gen_much_sus14 = "\\pcAnywhere\\" nocase
        $gen_much_sus15 = "antivirus" nocase
        $gen_much_sus16 = "McAfee" nocase
        $gen_much_sus17 = "nishang"
        $gen_much_sus18 = "\"unsafe" fullword wide ascii
        $gen_much_sus19 = "'unsafe" fullword wide ascii
        $gen_much_sus24 = "exploit" fullword wide ascii
        $gen_much_sus25 = "Exploit" fullword wide ascii
        $gen_much_sus26 = "TVqQAAMAAA" wide ascii
        $gen_much_sus30 = "Hacker" wide ascii
        $gen_much_sus31 = "HACKED" fullword wide ascii
        $gen_much_sus32 = "hacked" fullword wide ascii
        $gen_much_sus33 = "hacker" wide ascii
        $gen_much_sus34 = "grayhat" nocase wide ascii
        $gen_much_sus35 = "Microsoft FrontPage" wide ascii
        $gen_much_sus36 = "Rootkit" wide ascii
        $gen_much_sus37 = "rootkit" wide ascii
        $gen_much_sus38 = "/*-/*-*/" wide ascii
        $gen_much_sus39 = "u\"+\"n\"+\"s" wide ascii
        $gen_much_sus40 = "\"e\"+\"v" wide ascii
        $gen_much_sus41 = "a\"+\"l\"" wide ascii
        $gen_much_sus42 = "\"+\"(\"+\"" wide ascii
        $gen_much_sus43 = "q\"+\"u\"" wide ascii
        $gen_much_sus44 = "\"u\"+\"e" wide ascii
        $gen_much_sus45 = "/*//*/" wide ascii
        $gen_much_sus46 = "(\"/*/\"" wide ascii
        $gen_much_sus47 = "eval(eval(" wide ascii
        // self remove
        $gen_much_sus48 = "unlink(__FILE__)" wide ascii
        $gen_much_sus49 = "Shell.Users" wide ascii
        $gen_much_sus50 = "PasswordType=Regular" wide ascii
        $gen_much_sus51 = "-Expire=0" wide ascii
        $gen_much_sus60 = "_=$$_" wide ascii
        $gen_much_sus61 = "_=$$_" wide ascii
        $gen_much_sus62 = "++;$" wide ascii
        $gen_much_sus63 = "++; $" wide ascii
        $gen_much_sus64 = "_.=$_" wide ascii
        $gen_much_sus70 = "-perm -04000" wide ascii
        $gen_much_sus71 = "-perm -02000" wide ascii
        $gen_much_sus72 = "grep -li password" wide ascii
        $gen_much_sus73 = "-name config.inc.php" wide ascii
        // touch without parameters sets the time to now, not malicious and gives fp
        $gen_much_sus75 = "password crack" wide ascii
        $gen_much_sus76 = "mysqlDll.dll" wide ascii
        $gen_much_sus77 = "net user" wide ascii
        $gen_much_sus80 = "fopen(\".htaccess\",\"w" wide ascii
        $gen_much_sus81 = /strrev\(['"]/ wide ascii
        $gen_much_sus82 = "PHPShell" fullword wide ascii
        $gen_much_sus821= "PHP Shell" fullword wide ascii
        $gen_much_sus83 = "phpshell" fullword wide ascii
        $gen_much_sus84 = "PHPshell" fullword wide ascii
        $gen_much_sus87 = "deface" wide ascii
        $gen_much_sus88 = "Deface" wide ascii
        $gen_much_sus89 = "backdoor" wide ascii
        $gen_much_sus90 = "r00t" fullword wide ascii
        $gen_much_sus91 = "xp_cmdshell" fullword wide ascii
        $gen_much_sus92 = "base64_decode(base64_decode(" fullword wide ascii
        $gen_much_sus93 = "eval(\"/*" wide ascii
        $gen_much_sus94 = "=$_COOKIE;" wide ascii

        $gif = { 47 49 46 38 }


    condition:
        //any of them or
        (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and
        ( (
            not any of ( $cfp* ) and
        (
            any of ( $callback* )  or
            all of ( $m_callback* )
        )
        )
        or (
            any of ( $cpayload* ) or
        all of ( $m_cpayload_preg_filter* )
        )
        ) and (
            any of ( $cobfs* )
        )
        and
        ( filesize < 1KB or
        ( filesize < 3KB and
        ( (
        $gif at 0 or
        (
            filesize < 4KB and
            (
                1 of ( $gen_much_sus* ) or
                2 of ( $gen_bit_sus* )
            )
        ) or (
            filesize < 20KB and
            (
                2 of ( $gen_much_sus* ) or
                3 of ( $gen_bit_sus* )
            )
        ) or (
            filesize < 50KB and
            (
                2 of ( $gen_much_sus* ) or
                4 of ( $gen_bit_sus* )
            )
        ) or (
            filesize < 100KB and
            (
                2 of ( $gen_much_sus* ) or
                6 of ( $gen_bit_sus* )
            )
        ) or (
            filesize < 150KB and
            (
                3 of ( $gen_much_sus* ) or
                7 of ( $gen_bit_sus* )
            )
        ) or (
            filesize < 500KB and
            (
                4 of ( $gen_much_sus* ) or
                8 of ( $gen_bit_sus* )
            )
        )
        )
        or #obf1 > 10 ) ) )
}

rule webshell_php_includer_eval
{
    meta:
        description = "PHP webshell which eval()s another included file"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        hash = "3a07e9188028efa32872ba5b6e5363920a6b2489"
        date = "2021/01/13"
        modified = "2023-04-05"

    strings:
        $payload1 = "eval" fullword wide ascii
        $payload2 = "assert" fullword wide ascii
        $include1 = "$_FILE" wide ascii
        $include2 = "include" wide ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

    condition:
        filesize < 200 and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and 1 of ( $payload* ) and 1 of ( $include* )
}

rule webshell_php_includer_tiny
{
    meta:
        description = "Suspicious: Might be PHP webshell includer, check the included file"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021/04/17"
        modified = "2023-04-05"

    strings:
        $php_include1 = /include\(\$_(GET|POST|REQUEST)\[/ nocase wide ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

    condition:
        filesize < 100 and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and any of ( $php_include* )
}

rule webshell_php_dynamic
{
    meta:
        description = "PHP webshell using function name from variable, e.g. $a='ev'.'al'; $a($code)"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021/01/13"
        modified = "2023-04-05"
        score = 60
        hash = "65dca1e652d09514e9c9b2e0004629d03ab3c3ef"
        hash = "b8ab38dc75cec26ce3d3a91cb2951d7cdd004838"
        hash = "c4765e81550b476976604d01c20e3dbd415366df"
        hash = "2e11ba2d06ebe0aa818e38e24a8a83eebbaae8877c10b704af01bf2977701e73"

    strings:
        $pd_fp1 = "whoops_add_stack_frame" wide ascii
        $pd_fp2 = "new $ec($code, $mode, $options, $userinfo);" wide ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

        //strings from private rule capa_php_dynamic
        // php variable regex from https://www.php.net/manual/en/language.variables.basics.php
        $dynamic1 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(\$/ wide ascii
        $dynamic2 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\("/ wide ascii
        $dynamic3 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\('/ wide ascii
        $dynamic4 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(str/ wide ascii
        $dynamic5 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(\)/ wide ascii
        $dynamic6 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(@/ wide ascii
        $dynamic7 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(base64_decode/ wide ascii
        // ${'_'.$_}["_"](${'_'.$_}["__"]
        $dynamic8 = /\${[^}]{1,20}}(\[[^\]]{1,20}\])?\(\${/ wide ascii

    condition:
        filesize > 20 and filesize < 200 and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and (
            any of ( $dynamic* )
        )
        and not any of ( $pd_fp* )
}

rule webshell_php_dynamic_big
{
    meta:
        description = "PHP webshell using $a($code) for kind of eval with encoded blob to decode, e.g. b374k"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021/02/07"
        modified = "2023-04-05"
        score = 50
        hash = "6559bfc4be43a55c6bb2bd867b4c9b929713d3f7f6de8111a3c330f87a9b302c"
        hash = "9e82c9c2fa64e26fd55aa18f74759454d89f968068d46b255bd4f41eb556112e"
        hash = "6def5296f95e191a9c7f64f7d8ac5c529d4a4347ae484775965442162345dc93"
        hash = "dadfdc4041caa37166db80838e572d091bb153815a306c8be0d66c9851b98c10"
        hash = "0a4a292f6e08479c04e5c4fdc3857eee72efa5cd39db52e4a6e405bf039928bd"
        hash = "4326d10059e97809fb1903eb96fd9152cc72c376913771f59fa674a3f110679e"
        hash = "b49d0f942a38a33d2b655b1c32ac44f19ed844c2479bad6e540f69b807dd3022"
        hash = "575edeb905b434a3b35732654eedd3afae81e7d99ca35848c509177aa9bf9eef"
        hash = "ee34d62e136a04e2eaf84b8daa12c9f2233a366af83081a38c3c973ab5e2c40f"

    strings:

        //strings from private rule capa_bin_files
        $dex   = { 64 65 ( 78 | 79 ) 0a 30 }
        $pack  = { 50 41 43 4b 00 00 00 02 00 }

        //strings from private rule capa_php_new_long
        // no <?=
        $new_php2 = "<?php" nocase wide ascii
        $new_php3 = "<script language=\"php" nocase wide ascii
        $php_short = "<?"

        //strings from private rule capa_php_dynamic
        // php variable regex from https://www.php.net/manual/en/language.variables.basics.php
        $dynamic1 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(\$/ wide ascii
        $dynamic2 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\("/ wide ascii
        $dynamic3 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\('/ wide ascii
        $dynamic4 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(str/ wide ascii
        $dynamic5 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(\)/ wide ascii
        $dynamic6 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(@/ wide ascii
        $dynamic7 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(base64_decode/ wide ascii
        $dynamic8 = "eval(" wide ascii

        //strings from private rule capa_gen_sus

        // these strings are just a bit suspicious, so several of them are needed, depending on filesize
        $gen_bit_sus1  = /:\s{0,20}eval}/ nocase wide ascii
        $gen_bit_sus2  = /\.replace\(\/\w\/g/ nocase wide ascii
        $gen_bit_sus6  = "self.delete"
        $gen_bit_sus9  = "\"cmd /c" nocase
        $gen_bit_sus10 = "\"cmd\"" nocase
        $gen_bit_sus11 = "\"cmd.exe" nocase
        $gen_bit_sus12 = "%comspec%" wide ascii
        $gen_bit_sus13 = "%COMSPEC%" wide ascii
        //TODO:$gen_bit_sus12 = ".UserName" nocase
        $gen_bit_sus18 = "Hklm.GetValueNames();" nocase
        // bonus string for proxylogon exploiting webshells
        $gen_bit_sus19 = "http://schemas.microsoft.com/exchange/" wide ascii
        $gen_bit_sus21 = "\"upload\"" wide ascii
        $gen_bit_sus22 = "\"Upload\"" wide ascii
        $gen_bit_sus23 = "UPLOAD" fullword wide ascii
        $gen_bit_sus24 = "fileupload" wide ascii
        $gen_bit_sus25 = "file_upload" wide ascii
        $gen_bit_sus27 = "zuncomp" wide ascii
        $gen_bit_sus28 = "ase6" wide ascii
        // own base64 or base32 func
        $gen_bit_sus29 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" fullword wide ascii
        $gen_bit_sus29b = "abcdefghijklmnopqrstuvwxyz234567" fullword wide ascii
        $gen_bit_sus30 = "serv-u" wide ascii
        $gen_bit_sus31 = "Serv-u" wide ascii
        $gen_bit_sus32 = "Army" fullword wide ascii
        // single letter paramweter
        $gen_bit_sus33 = /\$_(GET|POST|REQUEST)\["\w"\]/ fullword wide ascii
        $gen_bit_sus34 = "Content-Transfer-Encoding: Binary" wide ascii
        $gen_bit_sus35 = "crack" fullword wide ascii

        $gen_bit_sus44 = "<pre>" wide ascii
        $gen_bit_sus45 = "<PRE>" wide ascii
        $gen_bit_sus46 = "shell_" wide ascii
        //fp: $gen_bit_sus47 = "Shell" fullword wide ascii
        $gen_bit_sus50 = "bypass" wide ascii
        $gen_bit_sus52 = " ^ $" wide ascii
        $gen_bit_sus53 = ".ssh/authorized_keys" wide ascii
        $gen_bit_sus55 = /\w'\.'\w/ wide ascii
        $gen_bit_sus56 = /\w\"\.\"\w/ wide ascii
        $gen_bit_sus57 = "dumper" wide ascii
        $gen_bit_sus59 = "'cmd'" wide ascii
        $gen_bit_sus60 = "\"execute\"" wide ascii
        $gen_bit_sus61 = "/bin/sh" wide ascii
        $gen_bit_sus62 = "Cyber" wide ascii
        $gen_bit_sus63 = "portscan" fullword wide ascii
        $gen_bit_sus65 = "whoami" fullword wide ascii
        $gen_bit_sus67 = "$password='" fullword wide ascii
        $gen_bit_sus68 = "$password=\"" fullword wide ascii
        $gen_bit_sus69 = "$cmd" fullword wide ascii
        $gen_bit_sus70 = "\"?>\"." fullword wide ascii
        $gen_bit_sus71 = "Hacking" fullword wide ascii
        $gen_bit_sus72 = "hacking" fullword wide ascii
        $gen_bit_sus73 = ".htpasswd" wide ascii
        $gen_bit_sus74 = /\btouch\(\$[^,]{1,30},/ wide ascii
        $gen_bit_sus99 = "$password = " wide ascii
        $gen_bit_sus100 = "();$" wide ascii

        // very suspicious strings, one is enough
        $gen_much_sus7  = "Web Shell" nocase
        $gen_much_sus8  = "WebShell" nocase
        $gen_much_sus3  = "hidded shell"
        $gen_much_sus4  = "WScript.Shell.1" nocase
        $gen_much_sus5  = "AspExec"
        $gen_much_sus14 = "\\pcAnywhere\\" nocase
        $gen_much_sus15 = "antivirus" nocase
        $gen_much_sus16 = "McAfee" nocase
        $gen_much_sus17 = "nishang"
        $gen_much_sus18 = "\"unsafe" fullword wide ascii
        $gen_much_sus19 = "'unsafe" fullword wide ascii
        $gen_much_sus24 = "exploit" fullword wide ascii
        $gen_much_sus25 = "Exploit" fullword wide ascii
        $gen_much_sus26 = "TVqQAAMAAA" wide ascii
        $gen_much_sus30 = "Hacker" wide ascii
        $gen_much_sus31 = "HACKED" fullword wide ascii
        $gen_much_sus32 = "hacked" fullword wide ascii
        $gen_much_sus33 = "hacker" wide ascii
        $gen_much_sus34 = "grayhat" nocase wide ascii
        $gen_much_sus35 = "Microsoft FrontPage" wide ascii
        $gen_much_sus36 = "Rootkit" wide ascii
        $gen_much_sus37 = "rootkit" wide ascii
        $gen_much_sus38 = "/*-/*-*/" wide ascii
        $gen_much_sus39 = "u\"+\"n\"+\"s" wide ascii
        $gen_much_sus40 = "\"e\"+\"v" wide ascii
        $gen_much_sus41 = "a\"+\"l\"" wide ascii
        $gen_much_sus42 = "\"+\"(\"+\"" wide ascii
        $gen_much_sus43 = "q\"+\"u\"" wide ascii
        $gen_much_sus44 = "\"u\"+\"e" wide ascii
        $gen_much_sus45 = "/*//*/" wide ascii
        $gen_much_sus46 = "(\"/*/\"" wide ascii
        $gen_much_sus47 = "eval(eval(" wide ascii
        // self remove
        $gen_much_sus48 = "unlink(__FILE__)" wide ascii
        $gen_much_sus49 = "Shell.Users" wide ascii
        $gen_much_sus50 = "PasswordType=Regular" wide ascii
        $gen_much_sus51 = "-Expire=0" wide ascii
        $gen_much_sus60 = "_=$$_" wide ascii
        $gen_much_sus61 = "_=$$_" wide ascii
        $gen_much_sus62 = "++;$" wide ascii
        $gen_much_sus63 = "++; $" wide ascii
        $gen_much_sus64 = "_.=$_" wide ascii
        $gen_much_sus70 = "-perm -04000" wide ascii
        $gen_much_sus71 = "-perm -02000" wide ascii
        $gen_much_sus72 = "grep -li password" wide ascii
        $gen_much_sus73 = "-name config.inc.php" wide ascii
        // touch without parameters sets the time to now, not malicious and gives fp
        $gen_much_sus75 = "password crack" wide ascii
        $gen_much_sus76 = "mysqlDll.dll" wide ascii
        $gen_much_sus77 = "net user" wide ascii
        $gen_much_sus80 = "fopen(\".htaccess\",\"w" wide ascii
        $gen_much_sus81 = /strrev\(['"]/ wide ascii
        $gen_much_sus82 = "PHPShell" fullword wide ascii
        $gen_much_sus821= "PHP Shell" fullword wide ascii
        $gen_much_sus83 = "phpshell" fullword wide ascii
        $gen_much_sus84 = "PHPshell" fullword wide ascii
        $gen_much_sus87 = "deface" wide ascii
        $gen_much_sus88 = "Deface" wide ascii
        $gen_much_sus89 = "backdoor" wide ascii
        $gen_much_sus90 = "r00t" fullword wide ascii
        $gen_much_sus91 = "xp_cmdshell" fullword wide ascii
        $gen_much_sus92 = "DEFACE" fullword wide ascii
        $gen_much_sus93 = "Bypass" fullword wide ascii
        $gen_much_sus94 = /eval\s{2,20}\(/ nocase wide ascii
        $gen_much_sus100 = "rot13" wide ascii
        $gen_much_sus101 = "ini_set('error_log'" wide ascii
        $gen_much_sus102 = "base64_decode(base64_decode(" wide ascii
        $gen_much_sus103 = "=$_COOKIE;" wide ascii
        // ¦{1}.$ .. |{9}.$
        $gen_much_sus104 = { C0 A6 7B 3? 7D 2E 24 }
        $gen_much_sus105 = "$GLOBALS[\"__" wide ascii
        // those calculations don't make really sense :)
        $gen_much_sus106 = ")-0)" wide ascii
        $gen_much_sus107 = "-0)+" wide ascii
        $gen_much_sus108 = "+0)+" wide ascii
        $gen_much_sus109 = "+(0/" wide ascii
        $gen_much_sus110 = "+(0+" wide ascii
        $gen_much_sus111 = "extract($_REQUEST)" wide ascii
        $gen_much_sus112 = "<?php\t\t\t\t\t\t\t\t\t\t\t" wide ascii
        $gen_much_sus113 = "\t\t\t\t\t\t\t\t\t\t\textract" wide ascii
        $gen_much_sus114 = "\" .\"" wide ascii
        $gen_much_sus115 = "end($_POST" wide ascii

        $weevely1 = /';\n\$\w\s?=\s?'/ wide ascii
        $weevely2 = /';\x0d\n\$\w\s?=\s?'/ wide ascii // same with \r\n
        $weevely3 = /';\$\w{1,2}='/ wide ascii
        $weevely4 = "str_replace" fullword wide ascii

        $gif = { 47 49 46 38 }

        $fp1 = "# Some examples from obfuscated malware:" ascii
    condition:
        //any of them or
        not (
            uint16(0) == 0x5a4d or
            // <?xml
            uint32be(0) == 0x3c3f786d  or
            // <?XML
            uint32be(0) == 0x3c3f584d  or
            $dex at 0 or
            $pack at 0 or
            // fp on jar with zero compression
            uint16(0) == 0x4b50 or
            1 of ($fp*)
        )
        and (
            any of ( $new_php* ) or
            $php_short at 0
        )
        and (
            any of ( $dynamic* )
        )
        and
            (
            $gif at 0 or
        (
            (
                filesize < 1KB and
                (
                    1 of ( $gen_much_sus* )
                )
            ) or (
                filesize < 2KB and
                (
                    ( #weevely1 + #weevely2 + #weevely3 ) > 2 and
                    #weevely4 > 1
                )
            ) or (
                filesize < 4KB and
                (
                    1 of ( $gen_much_sus* ) or
                    2 of ( $gen_bit_sus* )
                )
            ) or (
                filesize < 20KB and
                (
                    2 of ( $gen_much_sus* ) or
                    4 of ( $gen_bit_sus* )
                )
            ) or (
                filesize < 50KB and
                (
                    3 of ( $gen_much_sus* ) or
                    5 of ( $gen_bit_sus* )
                )
            ) or (
                filesize < 100KB and
                (
                    3 of ( $gen_much_sus* ) or
                    6 of ( $gen_bit_sus* )
                )
            ) or (
                filesize < 160KB and
                (
                    3 of ( $gen_much_sus* ) or
                    7 of ( $gen_bit_sus* ) or
                    (
                        // php files which use strings in the full ascii8 spectrum have a much hioher deviation than normal php-code
                        // e.g. 4057005718bb18b51b02d8b807265f8df821157ac47f78ace77f21b21fc77232
                        math.deviation(500, filesize-500, 89.0) > 70
                        // uncomment and include an "and" above for debugging, also import on top of file. needs yara 4.2.0
                        //console.log("high deviation") and
                        //console.log(math.deviation(500, filesize-500, 89.0))
                    )
                    // TODO: requires yara 4.2.0 so wait a bit until that's more common
                    //or
                    //(
                        // big file and just one line = minified
                        //filesize > 10KB and
                        //math.count(0x0A) < 2
                    //)
                )
            ) or (
                filesize < 500KB and
                (
                    4 of ( $gen_much_sus* ) or
                    8 of ( $gen_bit_sus* ) or
                    #gen_much_sus104 > 4

                )
            )
        ) or (
            // file shouldn't be too small to have big enough data for math.entropy
            filesize > 2KB and filesize < 1MB and
            (
                (
                    // base64 :
                    // ignore first and last 500bytes because they usually contain code for decoding and executing
                    math.entropy(500, filesize-500) >= 5.7 and
                    // encoded text has a higher mean than text or code because it's missing the spaces and special chars with the low numbers
                    math.mean(500, filesize-500) > 80 and
                    // deviation of base64 is ~20 according to CyberChef_v9.21.0.html#recipe=Generate_Lorem_Ipsum(3,'Paragraphs')To_Base64('A-Za-z0-9%2B/%3D')To_Charcode('Space',10)Standard_Deviation('Space')
                    // lets take a bit more because it might not be pure base64 also include some xor, shift, replacement, ...
                    // 89 is the mean of the base64 chars
                    math.deviation(500, filesize-500, 89.0) < 23
                ) or (
                    // gzinflated binary sometimes used in php webshells
                    // ignore first and last 500bytes because they usually contain code for decoding and executing
                    math.entropy(500, filesize-500) >= 7.7 and
                    // encoded text has a higher mean than text or code because it's missing the spaces and special chars with the low numbers
                    math.mean(500, filesize-500) > 120 and
                    math.mean(500, filesize-500) < 136 and
                    // deviation of base64 is ~20 according to CyberChef_v9.21.0.html#recipe=Generate_Lorem_Ipsum(3,'Paragraphs')To_Base64('A-Za-z0-9%2B/%3D')To_Charcode('Space',10)Standard_Deviation('Space')
                    // lets take a bit more because it might not be pure base64 also include some xor, shift, replacement, ...
                    // 89 is the mean of the base64 chars
                    math.deviation(500, filesize-500, 89.0) > 65
                )
            )
        )
        )
}

rule webshell_php_encoded_big
{
    meta:
        description = "PHP webshell using some kind of eval with encoded blob to decode"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021/02/07"
        modified = "2023-04-05"
        score = 50
        hash = "1d4b374d284c12db881ba42ee63ebce2759e0b14"

    strings:

        //strings from private rule capa_php_new
        $new_php1 = /<\?=[\w\s@$]/ wide ascii
        $new_php2 = "<?php" nocase wide ascii
        $new_php3 = "<script language=\"php" nocase wide ascii
        $php_short = "<?"

        //strings from private rule capa_php_payload
        // \([^)] to avoid matching on e.g. eval() in comments
        $cpayload1 = /\beval[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload2 = /\bexec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload3 = /\bshell_exec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload4 = /\bpassthru[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload5 = /\bsystem[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload6 = /\bpopen[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload7 = /\bproc_open[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload8 = /\bpcntl_exec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload9 = /\bassert[\n\t ]*\([^)0]/ nocase wide ascii
        $cpayload10 = /\bpreg_replace[\n\t ]*(\(.{1,|\/\*)100}\/[ismxADSUXju]{0,11}(e|\\x65)/ nocase wide ascii
        $cpayload12 = /\bmb_ereg_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
        $cpayload13 = /\bmb_eregi_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
        $cpayload20 = /\bcreate_function[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload21 = /\bReflectionFunction[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload22 = /fetchall\(PDO::FETCH_FUNC[\n\t ]*[,}\)]/ nocase wide ascii

        $m_cpayload_preg_filter1 = /\bpreg_filter[\n\t ]*(\([^\)]|\/\*)/ nocase wide ascii
        $m_cpayload_preg_filter2 = "'|.*|e'" nocase wide ascii
        // TODO backticks

    condition:
        //console.log(math.entropy(500, filesize-500)) and
        //console.log(math.mean(500, filesize-500)) and
        //console.log(math.deviation(500, filesize-500, 89.0)) and
        //any of them or
        filesize < 1000KB and (
            any of ( $new_php* ) or
        $php_short at 0
        )
        and (
            any of ( $cpayload* ) or
        all of ( $m_cpayload_preg_filter* )
        )
        and (
            // file shouldn't be too small to have big enough data for math.entropy
            filesize > 2KB and
        (
            // base64 :
            // ignore first and last 500bytes because they usually contain code for decoding and executing
            math.entropy(500, filesize-500) >= 5.7 and
            // encoded text has a higher mean than text or code because it's missing the spaces and special chars with the low numbers
            math.mean(500, filesize-500) > 80 and
            // deviation of base64 is ~20 according to CyberChef_v9.21.0.html#recipe=Generate_Lorem_Ipsum(3,'Paragraphs')To_Base64('A-Za-z0-9%2B/%3D')To_Charcode('Space',10)Standard_Deviation('Space')
            // lets take a bit more because it might not be pure base64 also include some xor, shift, replacement, ...
            // 89 is the mean of the base64 chars
            math.deviation(500, filesize-500, 89.0) < 24
        ) or (
            // gzinflated binary sometimes used in php webshells
            // ignore first and last 500bytes because they usually contain code for decoding and executing
            math.entropy(500, filesize-500) >= 7.7 and
            // encoded text has a higher mean than text or code because it's missing the spaces and special chars with the low numbers
            math.mean(500, filesize-500) > 120 and
            math.mean(500, filesize-500) < 136 and
            // deviation of base64 is ~20 according to CyberChef_v9.21.0.html#recipe=Generate_Lorem_Ipsum(3,'Paragraphs')To_Base64('A-Za-z0-9%2B/%3D')To_Charcode('Space',10)Standard_Deviation('Space')
            // lets take a bit more because it might not be pure base64 also include some xor, shift, replacement, ...
            // 89 is the mean of the base64 chars
            math.deviation(500, filesize-500, 89.0) > 65
        )
        )

}

rule webshell_php_generic_backticks
{
    meta:
        description = "Generic PHP webshell which uses backticks directly on user input"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021/01/07"
        modified = "2023-04-05"
        hash = "339f32c883f6175233f0d1a30510caa52fdcaa37"
        hash = "8db86ad90883cd208cf86acd45e67c03f994998804441705d690cb6526614d00"
        hash = "af987b0eade03672c30c095cee0c7c00b663e4b3c6782615fb7e430e4a7d1d75"
        hash = "67339f9e70a17af16cf51686918cbe1c0604e129950129f67fe445eaff4b4b82"
        hash = "144e242a9b219c5570973ca26d03e82e9fbe7ba2773305d1713288ae3540b4ad"
        hash = "8db86ad90883cd208cf86acd45e67c03f994998804441705d690cb6526614d00"

    strings:
        $backtick = /`\s*{?\$(_POST\[|_GET\[|_REQUEST\[|_SERVER\['HTTP_)/ wide ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

    condition:
        (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and $backtick and filesize < 200
}

rule webshell_php_generic_backticks_obfuscated
{
    meta:
        description = "Generic PHP webshell which uses backticks directly on user input"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021/01/07"
        modified = "2023-04-05"
        hash = "23dc299f941d98c72bd48659cdb4673f5ba93697"
        hash = "e3f393a1530a2824125ecdd6ac79d80cfb18fffb89f470d687323fb5dff0eec1"
        hash = "1e75914336b1013cc30b24d76569542447833416516af0d237c599f95b593f9b"
        hash = "8db86ad90883cd208cf86acd45e67c03f994998804441705d690cb6526614d00"

    strings:
        $s1 = /echo[\t ]*\(?`\$/ wide ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

    condition:
        filesize < 500 and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and $s1
}

rule webshell_php_by_string_known_webshell
{
    meta:
        description = "Known PHP Webshells which contain unique strings, lousy rule for low hanging fruits. Most are catched by other rules in here but maybe these catch different versions."
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021-01-09"
        modified = "2023-04-05"
        score = 70
        hash = "d889da22893536d5965541c30896f4ed4fdf461d"
        hash = "10f4988a191774a2c6b85604344535ee610b844c1708602a355cf7e9c12c3605"
        hash = "7b6471774d14510cf6fa312a496eed72b614f6fc"
        hash = "decda94d40c3fd13dab21e197c8d05f48020fa498f4d0af1f60e29616009e9bf"
        hash = "ef178d332a4780e8b6db0e772aded71ac1a6ed09b923cc359ba3c4efdd818acc"
        hash = "a7a937c766029456050b22fa4218b1f2b45eef0db59b414f79d10791feca2c0b"
        hash = "e7edd380a1a2828929fbde8e7833d6e3385f7652ea6b352d26b86a1e39130ee8"
        hash = "0038946739956c80d75fa9eeb1b5c123b064bbb9381d164d812d72c7c5d13cac"
        hash = "3a7309bad8a5364958081042b5602d82554b97eca04ee8fdd8b671b5d1ddb65d"
        hash = "a78324b9dc0b0676431af40e11bd4e26721a960c55e272d718932bdbb755a098"
        hash = "a27f8cd10cedd20bff51e9a8e19e69361cc8a6a1a700cc64140e66d160be1781"
        hash = "9bbd3462993988f9865262653b35b4151386ed2373592a1e2f8cf0f0271cdb00"
        hash = "459ed1d6f87530910361b1e6065c05ef0b337d128f446253b4e29ae8cc1a3915"
        hash = "12b34d2562518d339ed405fb2f182f95dce36d08fefb5fb67cc9386565f592d1"
        hash = "96d8ca3d269e98a330bdb7583cccdc85eab3682f9b64f98e4f42e55103a71636"
        hash = "312ee17ec9bed4278579443b805c0eb75283f54483d12f9add7d7d9e5f9f6105"
        hash = "15c4e5225ff7811e43506f0e123daee869a8292fc8a38030d165cc3f6a488c95"
        hash = "0c845a031e06925c22667e101a858131bbeb681d78b5dbf446fdd5bca344d765"
        hash = "d52128bcfff5e9a121eab3d76382420c3eebbdb33cd0879fbef7c3426e819695"

        //TODO regex für 96d8ca3d269e98a330bdb7583cccdc85eab3682f9b64f98e4f42e55103a71636 schnell genug?

    strings:
        $pbs1 = "b374k shell" wide ascii
        $pbs2 = "b374k/b374k" wide ascii
        $pbs3 = "\"b374k" wide ascii
        $pbs4 = "$b374k(\"" wide ascii
        $pbs5 = "b374k " wide ascii
        $pbs6 = "0de664ecd2be02cdd54234a0d1229b43" wide ascii
        $pbs7 = "pwnshell" wide ascii
        $pbs8 = "reGeorg" fullword wide ascii
        $pbs9 = "Georg says, 'All seems fine" fullword wide ascii
        $pbs10 = "My PHP Shell - A very simple web shell" wide ascii
        $pbs11 = "<title>My PHP Shell <?echo VERSION" wide ascii
        $pbs12 = "F4ckTeam" fullword wide ascii
        $pbs15 = "MulCiShell" fullword wide ascii
        // crawler avoid string
        $pbs30 = "bot|spider|crawler|slurp|teoma|archive|track|snoopy|java|lwp|wget|curl|client|python|libwww" wide ascii
        // <?=($pbs_=@$_GET[2]).@$_($_GET[1])?>
        $pbs35 = /@\$_GET\s?\[\d\]\)\.@\$_\(\$_GET\s?\[\d\]\)/ wide ascii
        $pbs36 = /@\$_GET\s?\[\d\]\)\.@\$_\(\$_POST\s?\[\d\]\)/ wide ascii
        $pbs37 = /@\$_POST\s?\[\d\]\)\.@\$_\(\$_GET\s?\[\d\]\)/ wide ascii
        $pbs38 = /@\$_POST\[\d\]\)\.@\$_\(\$_POST\[\d\]\)/ wide ascii
        $pbs39 = /@\$_REQUEST\[\d\]\)\.@\$_\(\$_REQUEST\[\d\]\)/ wide ascii
        $pbs42 = "array(\"find config.inc.php files\", \"find / -type f -name config.inc.php\")" wide ascii
        $pbs43 = "$_SERVER[\"\\x48\\x54\\x54\\x50" wide ascii
        $pbs52 = "preg_replace(\"/[checksql]/e\""
        $pbs53 = "='http://www.zjjv.com'"
        $pbs54 = "=\"http://www.zjjv.com\""

        $pbs60 = /setting\["AccountType"\]\s?=\s?3/
        $pbs61 = "~+d()\"^\"!{+{}"
        $pbs62 = "use function \\eval as "
        $pbs63 = "use function \\assert as "
        $pbs64 = "eval(`/*" wide ascii
        $pbs65 = "/* Reverse engineering of this file is strictly prohibited. File protected by copyright law and provided under license. */" wide ascii
        $pbs66 = "Tas9er" fullword wide ascii
        $pbs67 = "\"TSOP_\";" fullword wide ascii // reverse _POST
        $pbs68 = "str_rot13('nffreg')" wide ascii // rot13(assert)
        $pbs69 = "<?=`{$'" wide ascii
        $pbs70 = "{'_'.$_}[\"_\"](${'_'.$_}[\"_" wide ascii
        $pbs71 = "\"e45e329feb5d925b\"" wide ascii
        $pbs72 = "| PHP FILE MANAGER" wide ascii
        $pbs73 = "\neval(htmlspecialchars_decode(gzinflate(base64_decode($" wide ascii
        $pbs74 = "/*\n\nShellindir.org\n\n*/" wide ascii
        $pbs75 = "$shell = 'uname -a; w; id; /bin/sh -i';" wide ascii
        $pbs76 = "'password' . '/' . 'id' . '/' . " wide ascii
        $pbs77 = "= create_function /*" wide ascii
        $pbs78 = "W3LL M!N! SH3LL" wide ascii
        $pbs79 = "extract($_REQUEST)&&@$" wide ascii
        $pbs80 = "\"P-h-p-S-p-y\"" wide ascii
        $pbs81 = "\\x5f\\x72\\x6f\\x74\\x31\\x33" wide ascii
        $pbs82 = "\\x62\\x61\\x73\\x65\\x36\\x34\\x5f" wide ascii
        $pbs83 = "*/base64_decode/*" wide ascii
        $pbs84 = "\n@eval/*" wide ascii
        $pbs85 = "*/eval/*" wide ascii
        $pbs86 = "*/ array /*" wide ascii
        $pbs87 = "2jtffszJe" wide ascii
        $pbs88 = "edocne_46esab" wide ascii
        $pbs89 = "eval($_HEADERS" wide ascii
        $pbs90 = ">Infinity-Sh3ll<" ascii

        $front1 = "<?php eval(" nocase wide ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

        //strings from private rule capa_bin_files
        $dex   = { 64 65 ( 78 | 79 ) 0a 30 }
        $pack  = { 50 41 43 4b 00 00 00 02 00 }

    condition:
        filesize < 1000KB and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and not (
        uint16(0) == 0x5a4d or
        $dex at 0 or
        $pack at 0 or
        // fp on jar with zero compression
        uint16(0) == 0x4b50
        )
        and
        ( any of ( $pbs* ) or $front1 in ( 0 .. 60 ) )
}

rule webshell_php_strings_susp
{
    meta:
        description = "typical webshell strings, suspicious"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021/01/12"
        modified = "2023-04-05"
        hash = "0dd568dbe946b5aa4e1d33eab1decbd71903ea04"
        score = 50

    strings:
        $sstring1 = "eval(\"?>\"" nocase wide ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

        //strings from private rule php_false_positive
        // try to use only strings which would be flagged by themselves as suspicious by other rules, e.g. eval
        // a good choice is a string with good atom quality = ideally 4 unusual characters next to each other
        $gfp1  = "eval(\"return [$serialised_parameter" // elgg
        $gfp2  = "$this->assert(strpos($styles, $"
        $gfp3  = "$module = new $_GET['module']($_GET['scope']);"
        $gfp4  = "$plugin->$_POST['action']($_POST['id']);"
        $gfp5  = "$_POST[partition_by]($_POST["
        $gfp6  = "$object = new $_REQUEST['type']($_REQUEST['id']);"
        $gfp7  = "The above example code can be easily exploited by passing in a string such as" // ... ;)
        $gfp8  = "Smarty_Internal_Debug::start_render($_template);"
        $gfp9  = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
        $gfp10 = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
        $gfp11 = "(eval (getenv \"EPROLOG\")))"
        $gfp12 = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"

        //strings from private rule capa_php_input
        $inp1 = "php://input" wide ascii
        $inp2 = /_GET\s?\[/ wide ascii
        // for passing $_GET to a function
        $inp3 = /\(\s?\$_GET\s?\)/ wide ascii
        $inp4 = /_POST\s?\[/ wide ascii
        $inp5 = /\(\s?\$_POST\s?\)/ wide ascii
        $inp6 = /_REQUEST\s?\[/ wide ascii
        $inp7 = /\(\s?\$_REQUEST\s?\)/ wide ascii
        // PHP automatically adds all the request headers into the $_SERVER global array, prefixing each header name by the "HTTP_" string, so e.g. @eval($_SERVER['HTTP_CMD']) will run any code in the HTTP header CMD
        $inp15 = "_SERVER['HTTP_" wide ascii
        $inp16 = "_SERVER[\"HTTP_" wide ascii
        $inp17 = /getenv[\t ]{0,20}\([\t ]{0,20}['"]HTTP_/ wide ascii
        $inp18 = "array_values($_SERVER)" wide ascii
        $inp19 = /file_get_contents\("https?:\/\// wide ascii

    condition:
        filesize < 700KB and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and not (
            any of ( $gfp* )
        )
        and
        ( 1 of ( $sstring* ) and (
            any of ( $inp* )
        )
        )
}

rule webshell_php_in_htaccess
{
    meta:
        description = "Use Apache .htaccess to execute php code inside .htaccess"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021/01/07"
        modified = "2023-04-05"
        hash = "c026d4512a32d93899d486c6f11d1e13b058a713"

    strings:
        $hta = "AddType application/x-httpd-php .htaccess" wide ascii

    condition:
        filesize <100KB and $hta
}

rule webshell_php_function_via_get
{
    meta:
        description = "Webshell which sends eval/assert via GET"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021/01/09"
        modified = "2023-04-05"
        hash = "ce739d65c31b3c7ea94357a38f7bd0dc264da052d4fd93a1eabb257f6e3a97a6"
        hash = "d870e971511ea3e082662f8e6ec22e8a8443ca79"
        hash = "73fa97372b3bb829835270a5e20259163ecc3fdbf73ef2a99cb80709ea4572be"

    strings:
        $sr0 = /\$_GET\s?\[.{1,30}\]\(\$_GET\s?\[/ wide ascii
        $sr1 = /\$_POST\s?\[.{1,30}\]\(\$_GET\s?\[/ wide ascii
        $sr2 = /\$_POST\s?\[.{1,30}\]\(\$_POST\s?\[/ wide ascii
        $sr3 = /\$_GET\s?\[.{1,30}\]\(\$_POST\s?\[/ wide ascii
        $sr4 = /\$_REQUEST\s?\[.{1,30}\]\(\$_REQUEST\s?\[/ wide ascii
        $sr5 = /\$_SERVER\s?\[HTTP_.{1,30}\]\(\$_SERVER\s?\[HTTP_/ wide ascii

        //strings from private rule php_false_positive
        // try to use only strings which would be flagged by themselves as suspicious by other rules, e.g. eval
        // a good choice is a string with good atom quality = ideally 4 unusual characters next to each other
        $gfp1  = "eval(\"return [$serialised_parameter" // elgg
        $gfp2  = "$this->assert(strpos($styles, $"
        $gfp3  = "$module = new $_GET['module']($_GET['scope']);"
        $gfp4  = "$plugin->$_POST['action']($_POST['id']);"
        $gfp5  = "$_POST[partition_by]($_POST["
        $gfp6  = "$object = new $_REQUEST['type']($_REQUEST['id']);"
        $gfp7  = "The above example code can be easily exploited by passing in a string such as" // ... ;)
        $gfp8  = "Smarty_Internal_Debug::start_render($_template);"
        $gfp9  = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
        $gfp10 = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
        $gfp11 = "(eval (getenv \"EPROLOG\")))"
        $gfp12 = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"

    condition:
        filesize < 500KB and not (
            any of ( $gfp* )
        )
        and any of ( $sr* )
}

rule webshell_php_writer
{
    meta:
        description = "PHP webshell which only writes an uploaded file to disk"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021/04/17"
        modified = "2023-04-05"
        score = 50
        hash = "ec83d69512aa0cc85584973f5f0850932fb1949fb5fb2b7e6e5bbfb121193637"
        hash = "407c15f94a33232c64ddf45f194917fabcd2e83cf93f38ee82f9720e2635fa64"

    strings:
        $sus3 = "'upload'" wide ascii
        $sus4 = "\"upload\"" wide ascii
        $sus5 = "\"Upload\"" wide ascii
        $sus6 = "gif89" wide ascii
        //$sus13= "<textarea " wide ascii
        $sus16= "Army" fullword wide ascii
        $sus17= "error_reporting( 0 )" wide ascii
        $sus18= "' . '" wide ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

        //strings from private rule capa_php_input
        $inp1 = "php://input" wide ascii
        $inp2 = /_GET\s?\[/ wide ascii
        // for passing $_GET to a function
        $inp3 = /\(\s?\$_GET\s?\)/ wide ascii
        $inp4 = /_POST\s?\[/ wide ascii
        $inp5 = /\(\s?\$_POST\s?\)/ wide ascii
        $inp6 = /_REQUEST\s?\[/ wide ascii
        $inp7 = /\(\s?\$_REQUEST\s?\)/ wide ascii
        // PHP automatically adds all the request headers into the $_SERVER global array, prefixing each header name by the "HTTP_" string, so e.g. @eval($_SERVER['HTTP_CMD']) will run any code in the HTTP header CMD
        $inp15 = "_SERVER['HTTP_" wide ascii
        $inp16 = "_SERVER[\"HTTP_" wide ascii
        $inp17 = /getenv[\t ]{0,20}\([\t ]{0,20}['"]HTTP_/ wide ascii
        $inp18 = "array_values($_SERVER)" wide ascii
        $inp19 = /file_get_contents\("https?:\/\// wide ascii

        //strings from private rule capa_php_write_file
        $php_multi_write1 = "fopen(" wide ascii
        $php_multi_write2 = "fwrite(" wide ascii
        $php_write1 = "move_uploaded_file" fullword wide ascii
        $php_write2 = "copy" fullword wide ascii

    condition:
        //any of them or
        (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and (
            any of ( $inp* )
        )
        and (
        any of ( $php_write* ) or
        all of ( $php_multi_write* )
        )
        and
        (
            filesize < 400 or
            (
                filesize < 4000 and 1 of ( $sus* )
            )
        )
}

rule webshell_asp_writer
{
    meta:
        description = "ASP webshell which only writes an uploaded file to disk"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021/03/07"
        modified = "2023-04-05"
        score = 60

    strings:
        $sus1 = "password" fullword wide ascii
        $sus2 = "pwd" fullword wide ascii
        $sus3 = "<asp:TextBox" fullword nocase wide ascii
        $sus4 = "\"upload\"" wide ascii
        $sus5 = "\"Upload\"" wide ascii
        $sus6 = "gif89" wide ascii
        $sus7 = "\"&\"" wide ascii
        $sus8 = "authkey" fullword wide ascii
        $sus9 = "AUTHKEY" fullword wide ascii
        $sus10= "test.asp" fullword wide ascii
        $sus11= "cmd.asp" fullword wide ascii
        $sus12= ".Write(Request." wide ascii
        $sus13= "<textarea " wide ascii
        $sus14= "\"unsafe" fullword wide ascii
        $sus15= "'unsafe" fullword wide ascii
        $sus16= "Army" fullword wide ascii

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword


        //strings from private rule capa_asp_input
        // Request.BinaryRead
        // Request.Form
        $asp_input1 = "request" fullword nocase wide ascii
        $asp_input2 = "Page_Load" fullword nocase wide ascii
        // base64 of Request.Form(
        $asp_input3 = "UmVxdWVzdC5Gb3JtK" fullword wide ascii
        $asp_xml_http = "Microsoft.XMLHTTP" fullword nocase wide ascii
        $asp_xml_method1 = "GET" fullword wide ascii
        $asp_xml_method2 = "POST" fullword wide ascii
        $asp_xml_method3 = "HEAD" fullword wide ascii
        // dynamic form
        $asp_form1 = "<form " wide ascii
        $asp_form2 = "<Form " wide ascii
        $asp_form3 = "<FORM " wide ascii
        $asp_asp   = "<asp:" wide ascii
        $asp_text1 = ".text" wide ascii
        $asp_text2 = ".Text" wide ascii

        //strings from private rule capa_asp_write_file
        // $asp_write1 = "ADODB.Stream" wide ascii # just a string, can be easily obfuscated
        $asp_always_write1 = /\.write/ nocase wide ascii
        $asp_always_write2 = /\.swrite/ nocase wide ascii
        //$asp_write_way_one1 = /\.open\b/ nocase wide ascii
        $asp_write_way_one2 = "SaveToFile" fullword nocase wide ascii
        $asp_write_way_one3 = "CREAtEtExtFiLE" fullword nocase wide ascii
        $asp_cr_write1 = "CreateObject(" nocase wide ascii
        $asp_cr_write2 = "CreateObject (" nocase wide ascii
        $asp_streamwriter1 = "streamwriter" fullword nocase wide ascii
        $asp_streamwriter2 = "filestream" fullword nocase wide ascii

    condition:
        (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        and (
            any of ( $asp_input* ) or
        (
            $asp_xml_http and
            any of ( $asp_xml_method* )
        ) or
        (
            any of ( $asp_form* ) and
            any of ( $asp_text* ) and
            $asp_asp
        )
        )
        and (
        any of ( $asp_always_write* ) and
        (
            any of ( $asp_write_way_one* ) and
            any of ( $asp_cr_write* )
        ) or (
            any of ( $asp_streamwriter* )
        )
        )
        and
        ( filesize < 400 or
        ( filesize < 6000 and 1 of ( $sus* ) ) )
}

rule webshell_asp_obfuscated
{
    meta:
        description = "ASP webshell obfuscated"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021/01/12"
        modified = "2023-04-05"
        hash = "ad597eee256de51ffb36518cd5f0f4aa0f254f27517d28fb7543ae313b15e112"
        hash = "e0d21fdc16e0010b88d0197ebf619faa4aeca65243f545c18e10859469c1805a"

    strings:
        $asp_obf1 = "/*-/*-*/" wide ascii
        $asp_obf2 = "u\"+\"n\"+\"s" wide ascii
        $asp_obf3 = "\"e\"+\"v" wide ascii
        $asp_obf4 = "a\"+\"l\"" wide ascii
        $asp_obf5 = "\"+\"(\"+\"" wide ascii
        $asp_obf6 = "q\"+\"u\"" wide ascii
        $asp_obf7 = "\"u\"+\"e" wide ascii
        $asp_obf8 = "/*//*/" wide ascii

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword


        //strings from private rule capa_asp_payload
        $asp_payload0  = "eval_r" fullword nocase wide ascii
        $asp_payload1  = /\beval\s/ nocase wide ascii
        $asp_payload2  = /\beval\(/ nocase wide ascii
        $asp_payload3  = /\beval\"\"/ nocase wide ascii
        // var Fla = {'E':eval};  Fla.E(code)
        $asp_payload4  = /:\s{0,10}eval\b/ nocase wide ascii
        $asp_payload8  = /\bexecute\s?\(/ nocase wide ascii
        $asp_payload9  = /\bexecute\s[\w"]/ nocase wide ascii
        $asp_payload11 = "WSCRIPT.SHELL" fullword nocase wide ascii
        $asp_payload13 = "ExecuteGlobal" fullword nocase wide ascii
        $asp_payload14 = "ExecuteStatement" fullword nocase wide ascii
        $asp_payload15 = "ExecuteStatement" fullword nocase wide ascii
        $asp_multi_payload_one1 = "CreateObject" nocase fullword wide ascii
        $asp_multi_payload_one2 = "addcode" fullword wide ascii
        $asp_multi_payload_one3 = /\.run\b/ wide ascii
        $asp_multi_payload_two1 = "CreateInstanceFromVirtualPath" fullword wide ascii
        $asp_multi_payload_two2 = "ProcessRequest" fullword wide ascii
        $asp_multi_payload_two3 = "BuildManager" fullword wide ascii
        $asp_multi_payload_three1 = "System.Diagnostics" wide ascii
        $asp_multi_payload_three2 = "Process" fullword wide ascii
        $asp_multi_payload_three3 = ".Start" wide ascii
        // this is about "MSXML2.DOMDocument" but since that's easily obfuscated, lets not search for it
        $asp_multi_payload_four1 = "CreateObject" fullword nocase wide ascii
        $asp_multi_payload_four2 = "TransformNode" fullword nocase wide ascii
        $asp_multi_payload_four3 = "loadxml" fullword nocase wide ascii

        // execute cmd.exe /c with arguments using ProcessStartInfo
        $asp_multi_payload_five1 = "ProcessStartInfo" fullword nocase wide ascii
        $asp_multi_payload_five2 = ".Start" nocase wide ascii
        $asp_multi_payload_five3 = ".Filename" nocase wide ascii
        $asp_multi_payload_five4 = ".Arguments" nocase wide ascii


        //strings from private rule capa_asp_write_file
        // $asp_write1 = "ADODB.Stream" wide ascii # just a string, can be easily obfuscated
        $asp_always_write1 = /\.write/ nocase wide ascii
        $asp_always_write2 = /\.swrite/ nocase wide ascii
        //$asp_write_way_one1 = /\.open\b/ nocase wide ascii
        $asp_write_way_one2 = "SaveToFile" fullword nocase wide ascii
        $asp_write_way_one3 = "CREAtEtExtFiLE" fullword nocase wide ascii
        $asp_cr_write1 = "CreateObject(" nocase wide ascii
        $asp_cr_write2 = "CreateObject (" nocase wide ascii
        $asp_streamwriter1 = "streamwriter" fullword nocase wide ascii
        $asp_streamwriter2 = "filestream" fullword nocase wide ascii

        //strings from private rule capa_asp_obfuscation_multi
        // many Chr or few and a loop????
        //$loop1 = "For "
        //$o1 = "chr(" nocase wide ascii
        //$o2 = "chr (" nocase wide ascii
        // not excactly a string function but also often used in obfuscation
        $o4 = "\\x8" wide ascii
        $o5 = "\\x9" wide ascii
        // just picking some random numbers because they should appear often enough in a long obfuscated blob and it's faster than a regex
        $o6 = "\\61" wide ascii
        $o7 = "\\44" wide ascii
        $o8 = "\\112" wide ascii
        $o9 = "\\120" wide ascii
        //$o10 = " & \"" wide ascii
        //$o11 = " += \"" wide ascii
        // used for e.g. "scr"&"ipt"

        $m_multi_one1 = "Replace(" wide ascii
        $m_multi_one2 = "Len(" wide ascii
        $m_multi_one3 = "Mid(" wide ascii
        $m_multi_one4 = "mid(" wide ascii
        $m_multi_one5 = ".ToString(" wide ascii

        /*
        $m_multi_one5 = "InStr(" wide ascii
        $m_multi_one6 = "Function" wide ascii

        $m_multi_two1 = "for each" wide ascii
        $m_multi_two2 = "split(" wide ascii
        $m_multi_two3 = " & chr(" wide ascii
        $m_multi_two4 = " & Chr(" wide ascii
        $m_multi_two5 = " & Chr (" wide ascii

        $m_multi_three1 = "foreach" fullword wide ascii
        $m_multi_three2 = "(char" wide ascii

        $m_multi_four1 = "FromBase64String(" wide ascii
        $m_multi_four2 = ".Replace(" wide ascii
        $m_multi_five1 = "String.Join(\"\"," wide ascii
        $m_multi_five2 = ".Trim(" wide ascii
        $m_any1 = " & \"2" wide ascii
        $m_any2 = " += \"2" wide ascii
        */

        $m_fp1 = "Author: Andre Teixeira - andret@microsoft.com" /* FPs with 0227f4c366c07c45628b02bae6b4ad01 */


        //strings from private rule capa_asp_obfuscation_obviously
        $oo1 = /\w\"&\"\w/ wide ascii
        $oo2 = "*/\").Replace(\"/*" wide ascii

    condition:
        filesize < 100KB and (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        and
        ( ( (
            any of ( $asp_payload* ) or
        all of ( $asp_multi_payload_one* ) or
        all of ( $asp_multi_payload_two* ) or
        all of ( $asp_multi_payload_three* ) or
        all of ( $asp_multi_payload_four* ) or
        all of ( $asp_multi_payload_five* )
        )
        or (
        any of ( $asp_always_write* ) and
        (
            any of ( $asp_write_way_one* ) and
            any of ( $asp_cr_write* )
        ) or (
            any of ( $asp_streamwriter* )
        )
        )
        ) and
        ( (
        (
            filesize < 100KB and
            not any of ( $m_fp* ) and
            (
                //( #o1+#o2 ) > 50 or
                ( #o4+#o5+#o6+#o7+#o8+#o9 ) > 20
            )
        ) or (
            filesize < 5KB and
            (
                //( #o1+#o2 ) > 10 or
                ( #o4+#o5+#o6+#o7+#o8+#o9 ) > 5 or
                (
                    //( #o1+#o2 ) > 1 and
                    ( #m_multi_one1 + #m_multi_one2 + #m_multi_one3 + #m_multi_one4 + #m_multi_one5 ) > 3
                )

            )
        ) or (
            filesize < 700 and
            (
                //( #o1+#o2 ) > 1 or
                ( #o4+#o5+#o6+#o7+#o8+#o9 ) > 3 or
                ( #m_multi_one1 + #m_multi_one2 + #m_multi_one3 + #m_multi_one4 + #m_multi_one5 ) > 2
            )
        )
        )
        or any of ( $asp_obf* ) ) or (
        (
            filesize < 100KB and
            (
                ( #oo1 ) > 2 or
                $oo2
            )
        ) or (
            filesize < 25KB and
            (
                ( #oo1 ) > 1
            )
        ) or (
            filesize < 1KB and
            (
                ( #oo1 ) > 0
            )
        )
        )
        )
}

rule webshell_asp_generic_eval_on_input
{
    meta:
        description = "Generic ASP webshell which uses any eval/exec function directly on user input"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021/01/07"
        modified = "2023-04-05"
        hash = "d6b96d844ac395358ee38d4524105d331af42ede"
        hash = "9be2088d5c3bfad9e8dfa2d7d7ba7834030c7407"
        hash = "a1df4cfb978567c4d1c353e988915c25c19a0e4a"
        hash = "069ea990d32fc980939fffdf1aed77384bf7806bc57c0a7faaff33bd1a3447f6"

    strings:
        $payload_and_input0 = /\beval_r\s{0,20}\(Request\(/ nocase wide ascii
        $payload_and_input1 = /\beval[\s\(]{1,20}request[.\(\[]/ nocase wide ascii
        $payload_and_input2 = /\bexecute[\s\(]{1,20}request\(/ nocase wide ascii
        $payload_and_input4 = /\bExecuteGlobal\s{1,20}request\(/ nocase wide ascii

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword


    condition:
        ( filesize < 1100KB and (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        and any of ( $payload_and_input* ) ) or
        ( filesize < 100 and any of ( $payload_and_input* ) )
}

rule webshell_asp_nano
{
    meta:
        description = "Generic ASP webshell which uses any eval/exec function"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021/01/13"
        modified = "2023-04-05"
        hash = "3b7910a499c603715b083ddb6f881c1a0a3a924d"
        hash = "990e3f129b8ba409a819705276f8fa845b95dad0"
        hash = "22345e956bce23304f5e8e356c423cee60b0912c"
        hash = "c84a6098fbd89bd085526b220d0a3f9ab505bcba"
        hash = "b977c0ad20dc738b5dacda51ec8da718301a75d7"
        hash = "c69df00b57fd127c7d4e0e2a40d2f6c3056e0af8bfb1925938060b7e0d8c630f"
        hash = "f3b39a5da1cdde9acde077208e8e5b27feb973514dab7f262c7c6b2f8f11eaa7"
        hash = "0e9d92807d990144c637d8b081a6a90a74f15c7337522874cf6317092ea2d7c1"
        hash = "ebbc485e778f8e559ef9c66f55bb01dc4f5dcce9c31ccdd150e2c702c4b5d9e1"
        hash = "44b4068bfbbb8961e16bae238ad23d181ac9c8e4fcb4b09a66bbcd934d2d39ee"
        hash = "c5a4e188780b5513f34824904d56bf6e364979af6782417ccc5e5a8a70b4a95a"
        hash = "41a3cc668517ec207c990078bccfc877e239b12a7ff2abe55ff68352f76e819c"
        hash = "2faad5944142395794e5e6b90a34a6204412161f45e130aeb9c00eff764f65fc"
        hash = "d0c5e641120b8ea70a363529843d9f393074c54af87913b3ab635189fb0c84cb"
        hash = "28cfcfe28419a399c606bf96505bc68d6fe05624dba18306993f9fe0d398fbe1"

    strings:
        $susasp1  = "/*-/*-*/"
        $susasp2  = "(\"%1"
        $susasp3  = /[Cc]hr\([Ss]tr\(/
        $susasp4  = "cmd.exe"
        $susasp5  = "cmd /c"
        $susasp7  = "FromBase64String"
        // Request and request in b64:
        $susasp8  = "UmVxdWVzdC"
        $susasp9  = "cmVxdWVzdA"
        $susasp10 = "/*//*/"
        $susasp11 = "(\"/*/\""
        $susasp12 = "eval(eval("
        $fp1      = "eval a"
        $fp2      = "'Eval'"
        $fp3      = "Eval(\""

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword


        //strings from private rule capa_asp_payload
        $asp_payload0  = "eval_r" fullword nocase wide ascii
        $asp_payload1  = /\beval\s/ nocase wide ascii
        $asp_payload2  = /\beval\(/ nocase wide ascii
        $asp_payload3  = /\beval\"\"/ nocase wide ascii
        // var Fla = {'E':eval};  Fla.E(code)
        $asp_payload4  = /:\s{0,10}eval\b/ nocase wide ascii
        $asp_payload8  = /\bexecute\s?\(/ nocase wide ascii
        $asp_payload9  = /\bexecute\s[\w"]/ nocase wide ascii
        $asp_payload11 = "WSCRIPT.SHELL" fullword nocase wide ascii
        $asp_payload13 = "ExecuteGlobal" fullword nocase wide ascii
        $asp_payload14 = "ExecuteStatement" fullword nocase wide ascii
        $asp_payload15 = "ExecuteStatement" fullword nocase wide ascii
        $asp_multi_payload_one1 = "CreateObject" nocase fullword wide ascii
        $asp_multi_payload_one2 = "addcode" fullword wide ascii
        $asp_multi_payload_one3 = /\.run\b/ wide ascii
        $asp_multi_payload_two1 = "CreateInstanceFromVirtualPath" fullword wide ascii
        $asp_multi_payload_two2 = "ProcessRequest" fullword wide ascii
        $asp_multi_payload_two3 = "BuildManager" fullword wide ascii
        $asp_multi_payload_three1 = "System.Diagnostics" wide ascii
        $asp_multi_payload_three2 = "Process" fullword wide ascii
        $asp_multi_payload_three3 = ".Start" wide ascii
        // this is about "MSXML2.DOMDocument" but since that's easily obfuscated, lets not search for it
        $asp_multi_payload_four1 = "CreateObject" fullword nocase wide ascii
        $asp_multi_payload_four2 = "TransformNode" fullword nocase wide ascii
        $asp_multi_payload_four3 = "loadxml" fullword nocase wide ascii

        // execute cmd.exe /c with arguments using ProcessStartInfo
        $asp_multi_payload_five1 = "ProcessStartInfo" fullword nocase wide ascii
        $asp_multi_payload_five2 = ".Start" nocase wide ascii
        $asp_multi_payload_five3 = ".Filename" nocase wide ascii
        $asp_multi_payload_five4 = ".Arguments" nocase wide ascii


        //strings from private rule capa_asp_write_file
        // $asp_write1 = "ADODB.Stream" wide ascii # just a string, can be easily obfuscated
        $asp_always_write1 = /\.write/ nocase wide ascii
        $asp_always_write2 = /\.swrite/ nocase wide ascii
        //$asp_write_way_one1 = /\.open\b/ nocase wide ascii
        $asp_write_way_one2 = "SaveToFile" fullword nocase wide ascii
        $asp_write_way_one3 = "CREAtEtExtFiLE" fullword nocase wide ascii
        $asp_cr_write1 = "CreateObject(" nocase wide ascii
        $asp_cr_write2 = "CreateObject (" nocase wide ascii
        $asp_streamwriter1 = "streamwriter" fullword nocase wide ascii
        $asp_streamwriter2 = "filestream" fullword nocase wide ascii

    condition:
        (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        and
        ( (
            any of ( $asp_payload* ) or
        all of ( $asp_multi_payload_one* ) or
        all of ( $asp_multi_payload_two* ) or
        all of ( $asp_multi_payload_three* ) or
        all of ( $asp_multi_payload_four* ) or
        all of ( $asp_multi_payload_five* )
        )
        or (
        any of ( $asp_always_write* ) and
        (
            any of ( $asp_write_way_one* ) and
            any of ( $asp_cr_write* )
        ) or (
            any of ( $asp_streamwriter* )
        )
        )
        ) and not any of ( $fp* ) and
        ( filesize < 200 or
        ( filesize < 1000 and any of ( $susasp* ) ) )
}

rule webshell_asp_encoded
{
    meta:
        description = "Webshell in VBscript or JScript encoded using *.Encode plus a suspicious string"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021/03/14"
        modified = "2023-04-05"

    strings:
        $encoded1 = "VBScript.Encode" nocase wide ascii
        $encoded2 = "JScript.Encode" nocase wide ascii
        $data1 = "#@~^" wide ascii
        $sus1 = "shell" nocase wide ascii
        $sus2 = "cmd" fullword wide ascii
        $sus3 = "password" fullword wide ascii
        $sus4 = "UserPass" fullword wide ascii

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword


    condition:
        filesize < 500KB and (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        and any of ( $encoded* ) and any of ( $data* ) and
        ( any of ( $sus* ) or
        ( filesize < 20KB and #data1 > 4 ) or
        ( filesize < 700 and #data1 > 0 ) )
}

rule webshell_asp_encoded_aspcoding
{
    meta:
        description = "ASP Webshell encoded using ASPEncodeDLL.AspCoding"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021/03/14"
        modified = "2023-04-05"
        score = 60

    strings:
        $encoded1 = "ASPEncodeDLL" fullword nocase wide ascii
        $encoded2 = ".Runt" nocase wide ascii
        $encoded3 = "Request" fullword nocase wide ascii
        $encoded4 = "Response" fullword nocase wide ascii
        $data1 = "AspCoding.EnCode" wide ascii
        //$sus1 = "shell" nocase wide ascii
        //$sus2 = "cmd" fullword wide ascii
        //$sus3 = "password" fullword wide ascii
        //$sus4 = "UserPass" fullword wide ascii

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword


    condition:
        filesize < 500KB and (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        and all of ( $encoded* ) and any of ( $data* )
}

rule webshell_asp_by_string
{
    meta:
        description = "Known ASP Webshells which contain unique strings, lousy rule for low hanging fruits. Most are catched by other rules in here but maybe these catch different versions."
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021-01-13"
        modified = "2023-04-05"
        hash = "f72252b13d7ded46f0a206f63a1c19a66449f216"
        hash = "bd75ac9a1d1f6bcb9a2c82b13ea28c0238360b3a7be909b2ed19d3c96e519d3d"
        hash = "56a54fe1f8023455800fd0740037d806709ffb9ece1eb9e7486ad3c3e3608d45"
        hash = "4ef5d8b51f13b36ce7047e373159d7bb42ca6c9da30fad22e083ab19364c9985"
        hash = "e90c3c270a44575c68d269b6cf78de14222f2cbc5fdfb07b9995eb567d906220"
        hash = "8a38835f179e71111663b19baade78cc3c9e1f6fcc87eb35009cbd09393cbc53"
        hash = "f2883e9461393b33feed4139c0fc10fcc72ff92924249eb7be83cb5b76f0f4ee"
        hash = "10cca59c7112dfb1c9104d352e0504f842efd4e05b228b6f34c2d4e13ffd0eb6"
        hash = "ed179e5d4d365b0332e9ffca83f66ee0afe1f1b5ac3c656ccd08179170a4d9f7"
        hash = "ce3273e98e478a7e95fccce0a3d3e8135c234a46f305867f2deacd4f0efa7338"
        hash = "65543373b8bd7656478fdf9ceeacb8490ff8976b1fefc754cd35c89940225bcf"
        hash = "de173ea8dcef777368089504a4af0804864295b75e51794038a6d70f2bcfc6f5"


    strings:
        // reversed
        $asp_string1  = "tseuqer lave" wide ascii
        $asp_string2  = ":eval request(" wide ascii
        $asp_string3  = ":eval request(" wide ascii
        $asp_string4  = "SItEuRl=\"http://www.zjjv.com\"" wide ascii
        $asp_string5  = "ServerVariables(\"HTTP_HOST\"),\"gov.cn\"" wide ascii
        // e+k-v+k-a+k-l
        // e+x-v+x-a+x-l
        $asp_string6  = /e\+.-v\+.-a\+.-l/ wide ascii
        $asp_string7  = "r+x-e+x-q+x-u" wide ascii
        $asp_string8  = "add6bb58e139be10" fullword wide ascii
        $asp_string9  = "WebAdmin2Y.x.y(\"" wide ascii
        $asp_string10 = "<%if (Request.Files.Count!=0) { Request.Files[0].SaveAs(Server.MapPath(Request[" wide ascii
        $asp_string11 = "<% If Request.Files.Count <> 0 Then Request.Files(0).SaveAs(Server.MapPath(Request(" wide ascii
        // Request.Item["
        $asp_string12 = "UmVxdWVzdC5JdGVtWyJ" wide ascii

        // eval( in utf7 in base64 all 3 versions
        $asp_string13 = "UAdgBhAGwAKA" wide ascii
        $asp_string14 = "lAHYAYQBsACgA" wide ascii
        $asp_string15 = "ZQB2AGEAbAAoA" wide ascii
        // request in utf7 in base64 all 3 versions
        $asp_string16 = "IAZQBxAHUAZQBzAHQAKA" wide ascii
        $asp_string17 = "yAGUAcQB1AGUAcwB0ACgA" wide ascii
        $asp_string18 = "cgBlAHEAdQBlAHMAdAAoA" wide ascii

        $asp_string19 = "\"ev\"&\"al" wide ascii
        $asp_string20 = "\"Sc\"&\"ri\"&\"p" wide ascii
        $asp_string21 = "C\"&\"ont\"&\"" wide ascii
        $asp_string22 = "\"vb\"&\"sc" wide ascii
        $asp_string23 = "\"A\"&\"do\"&\"d" wide ascii
        $asp_string24 = "St\"&\"re\"&\"am\"" wide ascii
        $asp_string25 = "*/eval(" wide ascii
        $asp_string26 = "\"e\"&\"v\"&\"a\"&\"l" nocase
        $asp_string27 = "<%eval\"\"&(\"" nocase wide ascii
        $asp_string28 = "6877656D2B736972786677752B237E232C2A"  wide ascii
        $asp_string29 = "ws\"&\"cript.shell" wide ascii
        $asp_string30 = "SerVer.CreAtEoBjECT(\"ADODB.Stream\")" wide ascii
        $asp_string31 = "ASPShell - web based shell" wide ascii
        $asp_string32 = "<++ CmdAsp.asp ++>" wide ascii
        $asp_string33 = "\"scr\"&\"ipt\"" wide ascii
        $asp_string34 = "Regex regImg = new Regex(\"[a-z|A-Z]{1}:\\\\\\\\[a-z|A-Z| |0-9|\\u4e00-\\u9fa5|\\\\~|\\\\\\\\|_|{|}|\\\\.]*\");" wide ascii
        $asp_string35 = "\"she\"&\"ll." wide ascii
        $asp_string36 = "LH\"&\"TTP" wide ascii
        $asp_string37 = "<title>Web Sniffer</title>" wide ascii
        $asp_string38 = "<title>WebSniff" wide ascii
        $asp_string39 = "cript\"&\"ing" wide ascii
        $asp_string40 = "tcejbOmetsySeliF.gnitpircS" wide ascii
        $asp_string41 = "tcejbOetaerC.revreS" wide ascii
        $asp_string42 = "This file is part of A Black Path Toward The Sun (\"ABPTTS\")" wide ascii
        $asp_string43 = "if ((Request.Headers[headerNameKey] != null) && (Request.Headers[headerNameKey].Trim() == headerValueKey.Trim()))" wide ascii
        $asp_string44 = "if (request.getHeader(headerNameKey).toString().trim().equals(headerValueKey.trim()))" wide ascii
        $asp_string45 = "Response.Write(Server.HtmlEncode(ExcutemeuCmd(txtArg.Text)));" wide ascii
        $asp_string46 = "\"c\" + \"m\" + \"d\"" wide ascii
        $asp_string47 = "\".\"+\"e\"+\"x\"+\"e\"" wide ascii
        $asp_string48 = "Tas9er" fullword wide ascii
        $asp_string49 = "<%@ Page Language=\"\\u" wide ascii
        $asp_string50 = "BinaryRead(\\u" wide ascii
        $asp_string51 = "Request.\\u" wide ascii
        $asp_string52 = "System.Buffer.\\u" wide ascii
        $asp_string53 = "System.Net.\\u" wide ascii
        $asp_string54 = ".\\u0052\\u0065\\u0066\\u006c\\u0065\\u0063\\u0074\\u0069\\u006f\\u006e\"" wide ascii
        $asp_string55 = "\\u0041\\u0073\\u0073\\u0065\\u006d\\u0062\\u006c\\u0079.\\u004c\\u006f\\u0061\\u0064" wide ascii
        $asp_string56 = "\\U00000052\\U00000065\\U00000071\\U00000075\\U00000065\\U00000073\\U00000074[\"" wide ascii
        $asp_string57 = "*/\\U0000" wide ascii
        $asp_string58 = "\\U0000FFFA" wide ascii
        $asp_string59 = "\"e45e329feb5d925b\"" wide ascii
        $asp_string60 = ">POWER!shelled<" wide ascii
        $asp_string61 = "@requires xhEditor" wide ascii


        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword


    condition:
        filesize < 200KB and (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        and any of ( $asp_string* )
}

rule webshell_asp_sniffer
{
    meta:
        description = "ASP webshell which can sniff local traffic"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021/03/14"
        modified = "2023-04-05"

    strings:
        $sniff1 = "Socket(" wide ascii
        $sniff2 = ".Bind(" wide ascii
        $sniff3 = ".SetSocketOption(" wide ascii
        $sniff4 = ".IOControl(" wide ascii
        $sniff5 = "PacketCaptureWriter" fullword wide ascii

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword


        //strings from private rule capa_asp_input
        // Request.BinaryRead
        // Request.Form
        $asp_input1 = "request" fullword nocase wide ascii
        $asp_input2 = "Page_Load" fullword nocase wide ascii
        // base64 of Request.Form(
        $asp_input3 = "UmVxdWVzdC5Gb3JtK" fullword wide ascii
        $asp_xml_http = "Microsoft.XMLHTTP" fullword nocase wide ascii
        $asp_xml_method1 = "GET" fullword wide ascii
        $asp_xml_method2 = "POST" fullword wide ascii
        $asp_xml_method3 = "HEAD" fullword wide ascii
        // dynamic form
        $asp_form1 = "<form " wide ascii
        $asp_form2 = "<Form " wide ascii
        $asp_form3 = "<FORM " wide ascii
        $asp_asp   = "<asp:" wide ascii
        $asp_text1 = ".text" wide ascii
        $asp_text2 = ".Text" wide ascii

    condition:
        (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        and (
            any of ( $asp_input* ) or
        (
            $asp_xml_http and
            any of ( $asp_xml_method* )
        ) or
        (
            any of ( $asp_form* ) and
            any of ( $asp_text* ) and
            $asp_asp
        )
        )
        and filesize < 30KB and all of ( $sniff* )
}

rule webshell_asp_generic_tiny
{
    meta:
        description = "Generic tiny ASP webshell which uses any eval/exec function indirectly on user input or writes a file"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021/01/07"
        modified = "2023-04-05"
        hash = "990e3f129b8ba409a819705276f8fa845b95dad0"
        hash = "52ce724580e533da983856c4ebe634336f5fd13a"

    strings:
        $fp1 = "net.rim.application.ipproxyservice.AdminCommand.execute"

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword


        //strings from private rule capa_asp_input
        // Request.BinaryRead
        // Request.Form
        $asp_input1 = "request" fullword nocase wide ascii
        $asp_input2 = "Page_Load" fullword nocase wide ascii
        // base64 of Request.Form(
        $asp_input3 = "UmVxdWVzdC5Gb3JtK" fullword wide ascii
        $asp_xml_http = "Microsoft.XMLHTTP" fullword nocase wide ascii
        $asp_xml_method1 = "GET" fullword wide ascii
        $asp_xml_method2 = "POST" fullword wide ascii
        $asp_xml_method3 = "HEAD" fullword wide ascii
        // dynamic form
        $asp_form1 = "<form " wide ascii
        $asp_form2 = "<Form " wide ascii
        $asp_form3 = "<FORM " wide ascii
        $asp_asp   = "<asp:" wide ascii
        $asp_text1 = ".text" wide ascii
        $asp_text2 = ".Text" wide ascii

        //strings from private rule capa_bin_files
        $dex   = { 64 65 ( 78 | 79 ) 0a 30 }
        $pack  = { 50 41 43 4b 00 00 00 02 00 }

        //strings from private rule capa_asp_payload
        $asp_payload0  = "eval_r" fullword nocase wide ascii
        $asp_payload1  = /\beval\s/ nocase wide ascii
        $asp_payload2  = /\beval\(/ nocase wide ascii
        $asp_payload3  = /\beval\"\"/ nocase wide ascii
        // var Fla = {'E':eval};  Fla.E(code)
        $asp_payload4  = /:\s{0,10}eval\b/ nocase wide ascii
        $asp_payload8  = /\bexecute\s?\(/ nocase wide ascii
        $asp_payload9  = /\bexecute\s[\w"]/ nocase wide ascii
        $asp_payload11 = "WSCRIPT.SHELL" fullword nocase wide ascii
        $asp_payload13 = "ExecuteGlobal" fullword nocase wide ascii
        $asp_payload14 = "ExecuteStatement" fullword nocase wide ascii
        $asp_payload15 = "ExecuteStatement" fullword nocase wide ascii
        $asp_multi_payload_one1 = "CreateObject" nocase fullword wide ascii
        $asp_multi_payload_one2 = "addcode" fullword wide ascii
        $asp_multi_payload_one3 = /\.run\b/ wide ascii
        $asp_multi_payload_two1 = "CreateInstanceFromVirtualPath" fullword wide ascii
        $asp_multi_payload_two2 = "ProcessRequest" fullword wide ascii
        $asp_multi_payload_two3 = "BuildManager" fullword wide ascii
        $asp_multi_payload_three1 = "System.Diagnostics" wide ascii
        $asp_multi_payload_three2 = "Process" fullword wide ascii
        $asp_multi_payload_three3 = ".Start" wide ascii
        // this is about "MSXML2.DOMDocument" but since that's easily obfuscated, lets not search for it
        $asp_multi_payload_four1 = "CreateObject" fullword nocase wide ascii
        $asp_multi_payload_four2 = "TransformNode" fullword nocase wide ascii
        $asp_multi_payload_four3 = "loadxml" fullword nocase wide ascii

        // execute cmd.exe /c with arguments using ProcessStartInfo
        $asp_multi_payload_five1 = "ProcessStartInfo" fullword nocase wide ascii
        $asp_multi_payload_five2 = ".Start" nocase wide ascii
        $asp_multi_payload_five3 = ".Filename" nocase wide ascii
        $asp_multi_payload_five4 = ".Arguments" nocase wide ascii


        //strings from private rule capa_asp_write_file
        // $asp_write1 = "ADODB.Stream" wide ascii # just a string, can be easily obfuscated
        $asp_always_write1 = /\.write/ nocase wide ascii
        $asp_always_write2 = /\.swrite/ nocase wide ascii
        //$asp_write_way_one1 = /\.open\b/ nocase wide ascii
        $asp_write_way_one2 = "SaveToFile" fullword nocase wide ascii
        $asp_write_way_one3 = "CREAtEtExtFiLE" fullword nocase wide ascii
        $asp_cr_write1 = "CreateObject(" nocase wide ascii
        $asp_cr_write2 = "CreateObject (" nocase wide ascii
        $asp_streamwriter1 = "streamwriter" fullword nocase wide ascii
        $asp_streamwriter2 = "filestream" fullword nocase wide ascii

    condition:
        (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        and (
            any of ( $asp_input* ) or
        (
            $asp_xml_http and
            any of ( $asp_xml_method* )
        ) or
        (
            any of ( $asp_form* ) and
            any of ( $asp_text* ) and
            $asp_asp
        )
        )
        and not 1 of ( $fp* ) and not (
        uint16(0) == 0x5a4d or
        $dex at 0 or
        $pack at 0 or
        // fp on jar with zero compression
        uint16(0) == 0x4b50
        )
        and
        ( filesize < 700 and
        ( (
            any of ( $asp_payload* ) or
        all of ( $asp_multi_payload_one* ) or
        all of ( $asp_multi_payload_two* ) or
        all of ( $asp_multi_payload_three* ) or
        all of ( $asp_multi_payload_four* ) or
        all of ( $asp_multi_payload_five* )
        )
        or (
        any of ( $asp_always_write* ) and
        (
            any of ( $asp_write_way_one* ) and
            any of ( $asp_cr_write* )
        ) or (
            any of ( $asp_streamwriter* )
        )
        )
        ) )
}

rule WEBSHELL_asp_generic : FILE {
    meta:
        description = "Generic ASP webshell which uses any eval/exec function indirectly on user input or writes a file"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021-03-07"
        modified = "2023-04-05"
        score = 60
        hash = "a8c63c418609c1c291b3e731ca85ded4b3e0fba83f3489c21a3199173b176a75"
        hash = "4cf6fbad0411b7d33e38075f5e00d4c8ae9ce2f6f53967729974d004a183b25c"
    strings:
        $asp_much_sus7  = "Web Shell" nocase
        $asp_much_sus8  = "WebShell" nocase
        $asp_much_sus3  = "hidded shell"
        $asp_much_sus4  = "WScript.Shell.1" nocase
        $asp_much_sus5  = "AspExec"
        $asp_much_sus14 = "\\pcAnywhere\\" nocase
        $asp_much_sus15 = "antivirus" nocase
        $asp_much_sus16 = "McAfee" nocase
        $asp_much_sus17 = "nishang"
        $asp_much_sus18 = "\"unsafe" fullword wide ascii
        $asp_much_sus19 = "'unsafe" fullword wide ascii
        $asp_much_sus28 = "exploit" fullword wide ascii
        $asp_much_sus30 = "TVqQAAMAAA" wide ascii
        $asp_much_sus31 = "HACKED" fullword wide ascii
        $asp_much_sus32 = "hacked" fullword wide ascii
        $asp_much_sus33 = "hacker" wide ascii
        $asp_much_sus34 = "grayhat" nocase wide ascii
        $asp_much_sus35 = "Microsoft FrontPage" wide ascii
        $asp_much_sus36 = "Rootkit" wide ascii
        $asp_much_sus37 = "rootkit" wide ascii
        $asp_much_sus38 = "/*-/*-*/" wide ascii
        $asp_much_sus39 = "u\"+\"n\"+\"s" wide ascii
        $asp_much_sus40 = "\"e\"+\"v" wide ascii
        $asp_much_sus41 = "a\"+\"l\"" wide ascii
        $asp_much_sus42 = "\"+\"(\"+\"" wide ascii
        $asp_much_sus43 = "q\"+\"u\"" wide ascii
        $asp_much_sus44 = "\"u\"+\"e" wide ascii
        $asp_much_sus45 = "/*//*/" wide ascii
        $asp_much_sus46 = "(\"/*/\"" wide ascii
        $asp_much_sus47 = "eval(eval(" wide ascii
        $asp_much_sus48 = "Shell.Users" wide ascii
        $asp_much_sus49 = "PasswordType=Regular" wide ascii
        $asp_much_sus50 = "-Expire=0" wide ascii
        $asp_much_sus51 = "sh\"&\"el" wide ascii

        $asp_gen_sus1  = /:\s{0,20}eval}/ nocase wide ascii
        $asp_gen_sus2  = /\.replace\(\/\w\/g/ nocase wide ascii
        $asp_gen_sus6  = "self.delete"
        $asp_gen_sus9  = "\"cmd /c" nocase
        $asp_gen_sus10 = "\"cmd\"" nocase
        $asp_gen_sus11 = "\"cmd.exe" nocase
        $asp_gen_sus12 = "%comspec%" wide ascii
        $asp_gen_sus13 = "%COMSPEC%" wide ascii
        //TODO:$asp_gen_sus12 = ".UserName" nocase
        $asp_gen_sus18 = "Hklm.GetValueNames();" nocase
        // bonus string for proxylogon exploiting webshells
        $asp_gen_sus19 = "http://schemas.microsoft.com/exchange/" wide ascii
        $asp_gen_sus21 = "\"upload\"" wide ascii
        $asp_gen_sus22 = "\"Upload\"" wide ascii
        $asp_gen_sus25 = "shell_" wide ascii
        //$asp_gen_sus26 = "password" fullword wide ascii
        //$asp_gen_sus27 = "passw" fullword wide ascii
        // own base64 or base 32 func
        $asp_gen_sus29 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" fullword wide ascii
        $asp_gen_sus30 = "abcdefghijklmnopqrstuvwxyz234567" fullword wide ascii
        $asp_gen_sus31 = "serv-u" wide ascii
        $asp_gen_sus32 = "Serv-u" wide ascii
        $asp_gen_sus33 = "Army" fullword wide ascii

        $asp_slightly_sus1 = "<pre>" wide ascii
        $asp_slightly_sus2 = "<PRE>" wide ascii


        // "e"+"x"+"e"
        $asp_gen_obf1 = "\"+\"" wide ascii

        $fp1 = "DataBinder.Eval"
        $fp2 = "B2BTools"
        $fp3 = "<b>Failed to execute cache update. See the log file for more information" ascii
        $fp4 = "Microsoft. All rights reserved."

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword


        //strings from private rule capa_bin_files
        $dex   = { 64 65 ( 78 | 79 ) 0a 30 }
        $pack  = { 50 41 43 4b 00 00 00 02 00 }

        //strings from private rule capa_asp_input
        // Request.BinaryRead
        // Request.Form
        $asp_input1 = "request" fullword nocase wide ascii
        $asp_input2 = "Page_Load" fullword nocase wide ascii
        // base64 of Request.Form(
        $asp_input3 = "UmVxdWVzdC5Gb3JtK" fullword wide ascii
        $asp_xml_http = "Microsoft.XMLHTTP" fullword nocase wide ascii
        $asp_xml_method1 = "GET" fullword wide ascii
        $asp_xml_method2 = "POST" fullword wide ascii
        $asp_xml_method3 = "HEAD" fullword wide ascii
        // dynamic form
        $asp_form1 = "<form " wide ascii
        $asp_form2 = "<Form " wide ascii
        $asp_form3 = "<FORM " wide ascii
        $asp_asp   = "<asp:" wide ascii
        $asp_text1 = ".text" wide ascii
        $asp_text2 = ".Text" wide ascii

        //strings from private rule capa_asp_payload
        $asp_payload0  = "eval_r" fullword nocase wide ascii
        $asp_payload1  = /\beval\s/ nocase wide ascii
        $asp_payload2  = /\beval\(/ nocase wide ascii
        $asp_payload3  = /\beval\"\"/ nocase wide ascii
        // var Fla = {'E':eval};  Fla.E(code)
        $asp_payload4  = /:\s{0,10}eval\b/ nocase wide ascii
        $asp_payload8  = /\bexecute\s?\(/ nocase wide ascii
        $asp_payload9  = /\bexecute\s[\w"]/ nocase wide ascii
        $asp_payload11 = "WSCRIPT.SHELL" fullword nocase wide ascii
        $asp_payload13 = "ExecuteGlobal" fullword nocase wide ascii
        $asp_payload14 = "ExecuteStatement" fullword nocase wide ascii
        $asp_payload15 = "ExecuteStatement" fullword nocase wide ascii
        $asp_multi_payload_one1 = "CreateObject" nocase fullword wide ascii
        $asp_multi_payload_one2 = "addcode" fullword wide ascii
        $asp_multi_payload_one3 = /\.run\b/ wide ascii
        $asp_multi_payload_two1 = "CreateInstanceFromVirtualPath" fullword wide ascii
        $asp_multi_payload_two2 = "ProcessRequest" fullword wide ascii
        $asp_multi_payload_two3 = "BuildManager" fullword wide ascii
        $asp_multi_payload_three1 = "System.Diagnostics" wide ascii
        $asp_multi_payload_three2 = "Process" fullword wide ascii
        $asp_multi_payload_three3 = "Start" fullword wide ascii
        // this is about "MSXML2.DOMDocument" but since that's easily obfuscated, lets not search for it
        $asp_multi_payload_four1 = "CreateObject" fullword nocase wide ascii
        $asp_multi_payload_four2 = "TransformNode" fullword nocase wide ascii
        $asp_multi_payload_four3 = "loadxml" fullword nocase wide ascii

        // execute cmd.exe /c with arguments using ProcessStartInfo
        $asp_multi_payload_five1 = "ProcessStartInfo" fullword nocase wide ascii
        $asp_multi_payload_five2 = ".Start" nocase wide ascii
        $asp_multi_payload_five3 = ".Filename" nocase wide ascii
        $asp_multi_payload_five4 = ".Arguments" nocase wide ascii


        //strings from private rule capa_asp_write_file
        // $asp_write1 = "ADODB.Stream" wide ascii # just a string, can be easily obfuscated
        $asp_always_write1 = /\.write/ nocase wide ascii
        $asp_always_write2 = /\.swrite/ nocase wide ascii
        //$asp_write_way_one1 = /\.open\b/ nocase wide ascii
        $asp_write_way_one2 = "SaveToFile" fullword nocase wide ascii
        $asp_write_way_one3 = "CREAtEtExtFiLE" fullword nocase wide ascii
        $asp_cr_write1 = "CreateObject(" nocase wide ascii
        $asp_cr_write2 = "CreateObject (" nocase wide ascii
        $asp_streamwriter1 = "streamwriter" fullword nocase wide ascii
        $asp_streamwriter2 = "filestream" fullword nocase wide ascii

        //strings from private rule capa_asp_classid
        $tagasp_capa_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_capa_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_capa_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_capa_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_capa_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii

    condition:
        //any of them or
        (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        and not (
        uint16(0) == 0x5a4d or
        $dex at 0 or
        $pack at 0 or
        // fp on jar with zero compression
        uint16(0) == 0x4b50
        )
        and (
            any of ( $asp_input* ) or
        (
            $asp_xml_http and
            any of ( $asp_xml_method* )
        ) or
        (
            any of ( $asp_form* ) and
            any of ( $asp_text* ) and
            $asp_asp
        )
        )
        and (
            any of ( $asp_payload* ) or
        all of ( $asp_multi_payload_one* ) or
        all of ( $asp_multi_payload_two* ) or
        all of ( $asp_multi_payload_three* ) or
        all of ( $asp_multi_payload_four* ) or
        all of ( $asp_multi_payload_five* )
        )
        and not any of ( $fp* ) and
        ( ( filesize < 3KB and
        ( 1 of ( $asp_slightly_sus* ) ) ) or
        ( filesize < 25KB and
        ( 1 of ( $asp_much_sus* ) or 1 of ( $asp_gen_sus* ) or
        ( #asp_gen_obf1 > 2 ) ) ) or
        ( filesize < 50KB and
        ( 1 of ( $asp_much_sus* ) or 3 of ( $asp_gen_sus* ) or
        ( #asp_gen_obf1 > 6 ) ) ) or
        ( filesize < 150KB and
        ( 1 of ( $asp_much_sus* ) or 4 of ( $asp_gen_sus* ) or
        ( #asp_gen_obf1 > 6 ) or
        ( (
        any of ( $asp_always_write* ) and
        (
            any of ( $asp_write_way_one* ) and
            any of ( $asp_cr_write* )
        ) or (
            any of ( $asp_streamwriter* )
        )
        )
        and
        ( 1 of ( $asp_much_sus* ) or 2 of ( $asp_gen_sus* ) or
        ( #asp_gen_obf1 > 3 ) ) ) ) ) or
        ( filesize < 100KB and (
        any of ( $tagasp_capa_classid* )
        )
        ) )
}

rule webshell_asp_generic_registry_reader
{
    meta:
        description = "Generic ASP webshell which reads the registry (might look for passwords, license keys, database settings, general recon, ..."
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021/03/14"
        modified = "2023-04-05"
        score = 50

    strings:
        /* $asp_reg1  = "Registry" fullword wide ascii */ /* too many matches issues */
        $asp_reg2  = "LocalMachine" fullword wide ascii
        $asp_reg3  = "ClassesRoot" fullword wide ascii
        $asp_reg4  = "CurrentUser" fullword wide ascii
        $asp_reg5  = "Users" fullword wide ascii
        $asp_reg6  = "CurrentConfig" fullword wide ascii
        $asp_reg7  = "Microsoft.Win32" fullword wide ascii
        $asp_reg8  = "OpenSubKey" fullword wide ascii

        $sus1 = "shell" fullword nocase wide ascii
        $sus2 = "cmd.exe" fullword wide ascii
        $sus3 = "<form " wide ascii
        $sus4 = "<table " wide ascii
        $sus5 = "System.Security.SecurityException" wide ascii

        $fp1 = "Avira Operations GmbH" wide

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword


        //strings from private rule capa_asp_input
        // Request.BinaryRead
        // Request.Form
        $asp_input1 = "request" fullword nocase wide ascii
        $asp_input2 = "Page_Load" fullword nocase wide ascii
        // base64 of Request.Form(
        $asp_input3 = "UmVxdWVzdC5Gb3JtK" fullword wide ascii
        $asp_xml_http = "Microsoft.XMLHTTP" fullword nocase wide ascii
        $asp_xml_method1 = "GET" fullword wide ascii
        $asp_xml_method2 = "POST" fullword wide ascii
        $asp_xml_method3 = "HEAD" fullword wide ascii
        // dynamic form
        $asp_form1 = "<form " wide ascii
        $asp_form2 = "<Form " wide ascii
        $asp_form3 = "<FORM " wide ascii
        $asp_asp   = "<asp:" wide ascii
        $asp_text1 = ".text" wide ascii
        $asp_text2 = ".Text" wide ascii

    condition:
        (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        and all of ( $asp_reg* ) and any of ( $sus* ) and not any of ( $fp* ) and
        ( filesize < 10KB or
        ( filesize < 150KB and (
            any of ( $asp_input* ) or
        (
            $asp_xml_http and
            any of ( $asp_xml_method* )
        ) or
        (
            any of ( $asp_form* ) and
            any of ( $asp_text* ) and
            $asp_asp
        )
        )
        ) )
}

rule webshell_aspx_regeorg_csharp
{
    meta:
        description = "Webshell regeorg aspx c# version"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        reference = "https://github.com/sensepost/reGeorg"
        hash = "c1f43b7cf46ba12cfc1357b17e4f5af408740af7ae70572c9cf988ac50260ce1"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021/01/11"
        modified = "2023-04-05"

    strings:
        $input_sa1 = "Request.QueryString.Get" fullword nocase wide ascii
        $input_sa2 = "Request.Headers.Get" fullword nocase wide ascii
        $sa1 = "AddressFamily.InterNetwork" fullword nocase wide ascii
        $sa2 = "Response.AddHeader" fullword nocase wide ascii
        $sa3 = "Request.InputStream.Read" nocase wide ascii
        $sa4 = "Response.BinaryWrite" nocase wide ascii
        $sa5 = "Socket" nocase wide ascii
        $georg = "Response.Write(\"Georg says, 'All seems fine'\")"

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword


    condition:
        filesize < 300KB and (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        and
        ( $georg or
        ( all of ( $sa* ) and any of ( $input_sa* ) ) )
}

rule webshell_csharp_generic
{
    meta:
        description = "Webshell in c#"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        hash = "b6721683aadc4b4eba4f081f2bc6bc57adfc0e378f6d80e2bfa0b1e3e57c85c7"
        date = "2021/01/11"
        modified = "2023-04-05"

    strings:
        $input_http = "Request." nocase wide ascii
        $input_form1 = "<asp:" nocase wide ascii
        $input_form2 = ".text" nocase wide ascii
        $exec_proc1 = "new Process" nocase wide ascii
        $exec_proc2 = "start(" nocase wide ascii
        $exec_shell1 = "cmd.exe" nocase wide ascii
        $exec_shell2 = "powershell.exe" nocase wide ascii

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword


    condition:
        (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        and filesize < 300KB and
        ( $input_http or all of ( $input_form* ) ) and all of ( $exec_proc* ) and any of ( $exec_shell* )
}

rule webshell_asp_runtime_compile : FILE {
    meta:
        description = "ASP webshell compiling payload in memory at runtime, e.g. sharpyshell"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "https://github.com/antonioCoco/SharPyShell"
        date = "2021/01/11"
        modified = "2023-04-05"
        hash = "e826c4139282818d38dcccd35c7ae6857b1d1d01"
        hash = "e20e078d9fcbb209e3733a06ad21847c5c5f0e52"
        hash = "57f758137aa3a125e4af809789f3681d1b08ee5b"
        hash = "bd75ac9a1d1f6bcb9a2c82b13ea28c0238360b3a7be909b2ed19d3c96e519d3d"
        hash = "e44058dd1f08405e59d411d37d2ebc3253e2140385fa2023f9457474031b48ee"
        hash = "f6092ab5c8d491ae43c9e1838c5fd79480055033b081945d16ff0f1aaf25e6c7"
        hash = "dfd30139e66cba45b2ad679c357a1e2f565e6b3140a17e36e29a1e5839e87c5e"
        hash = "89eac7423dbf86eb0b443d8dd14252b4208e7462ac2971c99f257876388fccf2"
        hash = "8ce4eaf111c66c2e6c08a271d849204832713f8b66aceb5dadc293b818ccca9e"
    strings:
        $payload_reflection1 = "System" fullword nocase wide ascii
        $payload_reflection2 = "Reflection" fullword nocase wide ascii
        $payload_reflection3 = "Assembly" fullword nocase wide ascii
        $payload_load_reflection1 = /[."']Load\b/ nocase wide ascii
        // only match on "load" or variable which might contain "load"
        $payload_load_reflection2 = /\bGetMethod\(("load|\w)/ nocase wide ascii
        $payload_compile1 = "GenerateInMemory" nocase wide ascii
        $payload_compile2 = "CompileAssemblyFromSource" nocase wide ascii
        $payload_invoke1 = "Invoke" fullword nocase wide ascii
        $payload_invoke2 = "CreateInstance" fullword nocase wide ascii
        $payload_xamlreader1 = "XamlReader" fullword nocase wide ascii
        $payload_xamlreader2 = "Parse" fullword nocase wide ascii
        $payload_xamlreader3 = "assembly=" nocase wide ascii
        $payload_powershell1 = "PSObject" fullword nocase wide ascii
        $payload_powershell2 = "Invoke" fullword nocase wide ascii
        $payload_powershell3 = "CreateRunspace" fullword nocase wide ascii
        $rc_fp1 = "Request.MapPath"
        $rc_fp2 = "<body><mono:MonoSamplesHeader runat=\"server\"/>" wide ascii

        //strings from private rule capa_asp_input
        // Request.BinaryRead
        // Request.Form
        $asp_input1 = "request" fullword nocase wide ascii
        $asp_input2 = "Page_Load" fullword nocase wide ascii
        // base64 of Request.Form(
        $asp_input3 = "UmVxdWVzdC5Gb3JtK" fullword wide ascii
        $asp_input4 = "\\u0065\\u0071\\u0075" wide ascii // equ of Request
        $asp_input5 = "\\u0065\\u0073\\u0074" wide ascii // est of Request
        $asp_xml_http = "Microsoft.XMLHTTP" fullword nocase wide ascii
        $asp_xml_method1 = "GET" fullword wide ascii
        $asp_xml_method2 = "POST" fullword wide ascii
        $asp_xml_method3 = "HEAD" fullword wide ascii
        // dynamic form
        $asp_form1 = "<form " wide ascii
        $asp_form2 = "<Form " wide ascii
        $asp_form3 = "<FORM " wide ascii
        $asp_asp   = "<asp:" wide ascii
        $asp_text1 = ".text" wide ascii
        $asp_text2 = ".Text" wide ascii

        $sus_refl1 = " ^= " wide ascii
        $sus_refl2 = "SharPy" wide ascii

    condition:
        //any of them or
        (
            (
                filesize < 50KB and
                any of ( $sus_refl* )
            ) or
            filesize < 10KB
        ) and
        (
                any of ( $asp_input* ) or
            (
                $asp_xml_http and
                any of ( $asp_xml_method* )
            ) or
            (
                any of ( $asp_form* ) and
                any of ( $asp_text* ) and
                $asp_asp
            )
        )
        and not any of ( $rc_fp* ) and
        (
            (
                all of ( $payload_reflection* ) and
                any of ( $payload_load_reflection* )
            )
            or
            (
                all of ( $payload_compile* ) and
                any of ( $payload_invoke* )
            )
            or all of ( $payload_xamlreader* )
            or all of ( $payload_powershell* )
        )
}

rule webshell_asp_sql
{
    meta:
        description = "ASP webshell giving SQL access. Might also be a dual use tool."
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021/03/14"
        modified = "2023-04-05"

    strings:
        $sql1 = "SqlConnection" fullword wide ascii
        $sql2 = "SQLConnection" fullword wide ascii
        $sql3 = "System" fullword wide ascii
        $sql4 = "Data" fullword wide ascii
        $sql5 = "SqlClient" fullword wide ascii
        $sql6 = "SQLClient" fullword wide ascii
        $sql7 = "Open" fullword wide ascii
        $sql8 = "SqlCommand" fullword wide ascii
        $sql9 = "SQLCommand" fullword wide ascii

        $o_sql1 = "SQLOLEDB" fullword wide ascii
        $o_sql2 = "CreateObject" fullword wide ascii
        $o_sql3 = "open" fullword wide ascii

        $a_sql1 = "ADODB.Connection" fullword wide ascii
        $a_sql2 = "adodb.connection" fullword wide ascii
        $a_sql3 = "CreateObject" fullword wide ascii
        $a_sql4 = "createobject" fullword wide ascii
        $a_sql5 = "open" fullword wide ascii

        $c_sql1 = "System.Data.SqlClient" fullword wide ascii
        $c_sql2 = "sqlConnection" fullword wide ascii
        $c_sql3 = "open" fullword wide ascii

        $sus1 = "shell" fullword nocase wide ascii
        $sus2 = "xp_cmdshell" fullword nocase wide ascii
        $sus3 = "aspxspy" fullword nocase wide ascii
        $sus4 = "_KillMe" wide ascii
        $sus5 = "cmd.exe" fullword wide ascii
        $sus6 = "cmd /c" fullword wide ascii
        $sus7 = "net user" fullword wide ascii
        $sus8 = "\\x2D\\x3E\\x7C" wide ascii
        $sus9 = "Hacker" fullword wide ascii
        $sus10 = "hacker" fullword wide ascii
        $sus11 = "HACKER" fullword wide ascii
        $sus12 = "webshell" wide ascii
        $sus13 = "equest[\"sql\"]" wide ascii
        $sus14 = "equest(\"sql\")" wide ascii
        $sus15 = { e5 bc 80 e5 a7 8b e5 af bc e5 }
        $sus16 = "\"sqlCommand\"" wide ascii
        $sus17 = "\"sqlcommand\"" wide ascii

        //$slightly_sus1 = "select * from " wide ascii
        //$slightly_sus2 = "SELECT * FROM " wide ascii
        $slightly_sus3 = "SHOW COLUMNS FROM " wide ascii
        $slightly_sus4 = "show columns from " wide ascii


        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword


        //strings from private rule capa_asp_input
        // Request.BinaryRead
        // Request.Form
        $asp_input1 = "request" fullword nocase wide ascii
        $asp_input2 = "Page_Load" fullword nocase wide ascii
        // base64 of Request.Form(
        $asp_input3 = "UmVxdWVzdC5Gb3JtK" fullword wide ascii
        $asp_xml_http = "Microsoft.XMLHTTP" fullword nocase wide ascii
        $asp_xml_method1 = "GET" fullword wide ascii
        $asp_xml_method2 = "POST" fullword wide ascii
        $asp_xml_method3 = "HEAD" fullword wide ascii
        // dynamic form
        $asp_form1 = "<form " wide ascii
        $asp_form2 = "<Form " wide ascii
        $asp_form3 = "<FORM " wide ascii
        $asp_asp   = "<asp:" wide ascii
        $asp_text1 = ".text" wide ascii
        $asp_text2 = ".Text" wide ascii

    condition:
        (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        and (
            any of ( $asp_input* ) or
        (
            $asp_xml_http and
            any of ( $asp_xml_method* )
        ) or
        (
            any of ( $asp_form* ) and
            any of ( $asp_text* ) and
            $asp_asp
        )
        )
        and
        ( 6 of ( $sql* ) or all of ( $o_sql* ) or 3 of ( $a_sql* ) or all of ( $c_sql* ) ) and
        ( ( filesize < 150KB and any of ( $sus* ) ) or
        ( filesize < 5KB and any of ( $slightly_sus* ) ) )
}

rule webshell_asp_scan_writable
{
    meta:
        description = "ASP webshell searching for writable directories (to hide more webshells ...)"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021/03/14"
        modified = "2023-04-05"
        hash = "2409eda9047085baf12e0f1b9d0b357672f7a152"
        hash = "af1c00696243f8b062a53dad9fb8b773fa1f0395631ffe6c7decc42c47eedee7"

    strings:
        $scan1 = "DirectoryInfo" nocase fullword wide ascii
        $scan2 = "GetDirectories" nocase fullword wide ascii
        $scan3 = "Create" nocase fullword wide ascii
        $scan4 = "File" nocase fullword wide ascii
        $scan5 = "System.IO" nocase fullword wide ascii
        // two methods: check permissions or write and delete:
        $scan6 = "CanWrite" nocase fullword wide ascii
        $scan7 = "Delete" nocase fullword wide ascii


        $sus1 = "upload" nocase fullword wide ascii
        $sus2 = "shell" nocase wide ascii
        $sus3 = "orking directory" nocase fullword wide ascii
        $sus4 = "scan" nocase wide ascii


        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword


        //strings from private rule capa_asp_input
        // Request.BinaryRead
        // Request.Form
        $asp_input1 = "request" fullword nocase wide ascii
        $asp_input2 = "Page_Load" fullword nocase wide ascii
        // base64 of Request.Form(
        $asp_input3 = "UmVxdWVzdC5Gb3JtK" fullword wide ascii
        $asp_xml_http = "Microsoft.XMLHTTP" fullword nocase wide ascii
        $asp_xml_method1 = "GET" fullword wide ascii
        $asp_xml_method2 = "POST" fullword wide ascii
        $asp_xml_method3 = "HEAD" fullword wide ascii
        // dynamic form
        $asp_form1 = "<form " wide ascii
        $asp_form2 = "<Form " wide ascii
        $asp_form3 = "<FORM " wide ascii
        $asp_asp   = "<asp:" wide ascii
        $asp_text1 = ".text" wide ascii
        $asp_text2 = ".Text" wide ascii

    condition:
        filesize < 10KB and (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        and (
            any of ( $asp_input* ) or
        (
            $asp_xml_http and
            any of ( $asp_xml_method* )
        ) or
        (
            any of ( $asp_form* ) and
            any of ( $asp_text* ) and
            $asp_asp
        )
        )
        and 6 of ( $scan* ) and any of ( $sus* )
}

rule webshell_jsp_regeorg
{
    meta:
        description = "Webshell regeorg JSP version"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        reference = "https://github.com/sensepost/reGeorg"
        hash = "6db49e43722080b5cd5f07e058a073ba5248b584"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021/01/24"
        modified = "2023-04-05"

    strings:
        $jgeorg1 = "request" fullword wide ascii
        $jgeorg2 = "getHeader" fullword wide ascii
        $jgeorg3 = "X-CMD" fullword wide ascii
        $jgeorg4 = "X-STATUS" fullword wide ascii
        $jgeorg5 = "socket" fullword wide ascii
        $jgeorg6 = "FORWARD" fullword wide ascii

        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii wide
        $cjsp_short2 = "%>" wide ascii
        $cjsp_long1 = "<jsp:" ascii wide
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
        // JSF
        $cjsp_long3 = "/jstl/core" ascii wide
        $cjsp_long4 = "<%@p" nocase ascii wide
        $cjsp_long5 = "<%@ " nocase ascii wide
        $cjsp_long6 = "<% " ascii wide
        $cjsp_long7 = "< %" ascii wide

    condition:
        filesize < 300KB and (
        $cjsp_short1 at 0 or
            any of ( $cjsp_long* ) or
            $cjsp_short2 in ( filesize-100..filesize ) or
        (
            $cjsp_short2 and (
                $cjsp_short1 in ( 0..1000 ) or
                $cjsp_short1 in ( filesize-1000..filesize )
            )
        )
        )
        and all of ( $jgeorg* )
}

rule webshell_jsp_http_proxy
{
    meta:
        description = "Webshell JSP HTTP proxy"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        hash = "2f9b647660923c5262636a5344e2665512a947a4"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021/01/24"
        modified = "2023-04-05"

    strings:
        $jh1 = "OutputStream" fullword wide ascii
        $jh2 = "InputStream"  wide ascii
        $jh3 = "BufferedReader" fullword wide ascii
        $jh4 = "HttpRequest" fullword wide ascii
        $jh5 = "openConnection" fullword wide ascii
        $jh6 = "getParameter" fullword wide ascii

        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii wide
        $cjsp_short2 = "%>" wide ascii
        $cjsp_long1 = "<jsp:" ascii wide
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
        // JSF
        $cjsp_long3 = "/jstl/core" ascii wide
        $cjsp_long4 = "<%@p" nocase ascii wide
        $cjsp_long5 = "<%@ " nocase ascii wide
        $cjsp_long6 = "<% " ascii wide
        $cjsp_long7 = "< %" ascii wide

    condition:
        filesize < 10KB and (
        $cjsp_short1 at 0 or
            any of ( $cjsp_long* ) or
            $cjsp_short2 in ( filesize-100..filesize ) or
        (
            $cjsp_short2 and (
                $cjsp_short1 in ( 0..1000 ) or
                $cjsp_short1 in ( filesize-1000..filesize )
            )
        )
        )
        and all of ( $jh* )
}

rule webshell_jsp_writer_nano
{
    meta:
        description = "JSP file writer"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021/01/24"
        modified = "2023-04-05"
        hash = "ac91e5b9b9dcd373eaa9360a51aa661481ab9429"
        hash = "c718c885b5d6e29161ee8ea0acadb6e53c556513"
        hash = "9f1df0249a6a491cdd5df598d83307338daa4c43"
        hash = "5e241d9d3a045d3ade7b6ff6af6c57b149fa356e"

    strings:
        // writting file to disk
        $payload1 = ".write" wide ascii
        $payload2 = "getBytes" fullword wide ascii
        $payload3 = ".decodeBuffer" wide ascii
        $payload4 = "FileOutputStream" fullword wide ascii

        // writting using java logging, e.g 9f1df0249a6a491cdd5df598d83307338daa4c43
        $logger1 = "getLogger" fullword ascii wide
        $logger2 = "FileHandler" fullword ascii wide
        $logger3 = "addHandler" fullword ascii wide

        //strings from private rule capa_jsp_input
        // request.getParameter
        $input1 = "getParameter" fullword ascii wide
        // request.getHeaders
        $input2 = "getHeaders" fullword ascii wide
        $input3 = "getInputStream" fullword ascii wide
        $input4 = "getReader" fullword ascii wide
        $req1 = "request" fullword ascii wide
        $req2 = "HttpServletRequest" fullword ascii wide
        $req3 = "getRequest" fullword ascii wide

        $jw_sus1 = /getParameter\("."\)/ ascii wide // one char param
        $jw_sus4 = "yoco" fullword ascii wide // webshell coder

        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii wide
        $cjsp_short2 = "%>" wide ascii
        $cjsp_long1 = "<jsp:" ascii wide
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
        // JSF
        $cjsp_long3 = "/jstl/core" ascii wide
        $cjsp_long4 = "<%@p" nocase ascii wide
        $cjsp_long5 = "<%@ " nocase ascii wide
        $cjsp_long6 = "<% " ascii wide
        $cjsp_long7 = "< %" ascii wide

    condition:
        //any of them or
        (
            any of ( $input* ) and
            any of ( $req* )
        ) and (
            filesize < 200 or
            (
                filesize < 1000 and
                any of ( $jw_sus* )
            )
        )
        and (
        $cjsp_short1 at 0 or
            any of ( $cjsp_long* ) or
            $cjsp_short2 in ( filesize-100..filesize ) or
        (
            $cjsp_short2 and (
                $cjsp_short1 in ( 0..1000 ) or
                $cjsp_short1 in ( filesize-1000..filesize )
            )
        )
        )
        and (
            2 of ( $payload* ) or
            all of ( $logger* )
            )
}

rule webshell_jsp_generic_tiny
{
    meta:
        description = "Generic JSP webshell tiny"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021/01/07"
        modified = "2023-04-05"
        hash = "8fd343db0442136e693e745d7af1018a99b042af"
        hash = "87c3ac9b75a72187e8bc6c61f50659435dbdc4fde6ed720cebb93881ba5989d8"
        hash = "1aa6af726137bf261849c05d18d0a630d95530588832aadd5101af28acc034b5"

    strings:
        $payload1 = "ProcessBuilder" fullword wide ascii
        $payload2 = "URLClassLoader" fullword wide ascii
        // Runtime.getRuntime().exec(
        $payload_rt1 = "Runtime" fullword wide ascii
        $payload_rt2 = "getRuntime" fullword wide ascii
        $payload_rt3 = "exec" fullword wide ascii

        $jg_sus1 = "xe /c" ascii wide // of cmd.exe /c
        $jg_sus2 = /getParameter\("."\)/ ascii wide // one char param
        $jg_sus3 = "</pre>" ascii wide // webshells like fixed font wide
        $jg_sus4 = "BASE64Decoder" fullword ascii wide

        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii wide
        $cjsp_short2 = "%>" wide ascii
        $cjsp_long1 = "<jsp:" ascii wide
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
        // JSF
        $cjsp_long3 = "/jstl/core" ascii wide
        $cjsp_long4 = "<%@p" nocase ascii wide
        $cjsp_long5 = "<%@ " nocase ascii wide
        $cjsp_long6 = "<% " ascii wide
        $cjsp_long7 = "< %" ascii wide

        //strings from private rule capa_jsp_input
        // request.getParameter
        $input1 = "getParameter" fullword ascii wide
        // request.getHeaders
        $input2 = "getHeaders" fullword ascii wide
        $input3 = "getInputStream" fullword ascii wide
        $input4 = "getReader" fullword ascii wide
        $req1 = "request" fullword ascii wide
        $req2 = "HttpServletRequest" fullword ascii wide
        $req3 = "getRequest" fullword ascii wide

        // no web input but fixed command to create reverse shell
        $fixed_cmd1 = "bash -i >& /dev/" ascii wide

    condition:
        //any of them or
        (
            (
                filesize < 1000 and
                any of ( $jg_sus* )
            ) or
            filesize < 250
        ) and (
            $cjsp_short1 at 0 or
            any of ( $cjsp_long* ) or
            $cjsp_short2 in ( filesize-100..filesize ) or
        (
            $cjsp_short2 and (
                $cjsp_short1 in ( 0..1000 ) or
                $cjsp_short1 in ( filesize-1000..filesize )
            )
        )
        )
        and (
                (
                    any of ( $input* ) and
                    any of ( $req* )
                ) or (
                    any of ( $fixed_cmd* )
                )
        )
        and
        ( 1 of ( $payload* ) or all of ( $payload_rt* ) )
}

rule webshell_jsp_generic
{
    meta:
        description = "Generic JSP webshell"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021/01/07"
        modified = "2023-04-05"
        hash = "4762f36ca01fb9cda2ab559623d2206f401fc0b1"
        hash = "bdaf9279b3d9e07e955d0ce706d9c42e4bdf9aa1"
        hash = "ee9408eb923f2d16f606a5aaac7e16b009797a07"

    strings:
        $susp0 = "cmd" fullword nocase ascii wide
        $susp1 = "command" fullword nocase ascii wide
        $susp2 = "shell" fullword nocase ascii wide
        $susp3 = "download" fullword nocase ascii wide
        $susp4 = "upload" fullword nocase ascii wide
        $susp5 = "Execute" fullword nocase ascii wide
        $susp6 = "\"pwd\"" ascii wide
        $susp7 = "\"</pre>" ascii wide
        $susp8 = /\\u00\d\d\\u00\d\d\\u00\d\d\\u00\d\d/ ascii wide
        $susp9 = "*/\\u00" ascii wide // perfect match of 2 obfuscation methods: /**/\u00xx :)

        $fp1 = "command = \"cmd.exe /c set\";"

        //strings from private rule capa_bin_files
        $dex   = { 64 65 ( 78 | 79 ) 0a 30 }
        $pack  = { 50 41 43 4b 00 00 00 02 00 }

        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii wide
        $cjsp_short2 = "%>" wide ascii
        $cjsp_long1 = "<jsp:" ascii wide
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
        // JSF
        $cjsp_long3 = "/jstl/core" ascii wide
        $cjsp_long4 = "<%@p" nocase ascii wide
        $cjsp_long5 = "<%@ " nocase ascii wide
        $cjsp_long6 = "<% " ascii wide
        $cjsp_long7 = "< %" ascii wide

        //strings from private rule capa_jsp_input
        // request.getParameter
        $input1 = "getParameter" fullword ascii wide
        // request.getHeaders
        $input2 = "getHeaders" fullword ascii wide
        $input3 = "getInputStream" fullword ascii wide
        $input4 = "getReader" fullword ascii wide
        $req1 = "request" fullword ascii wide
        $req2 = "HttpServletRequest" fullword ascii wide
        $req3 = "getRequest" fullword ascii wide

        //strings from private rule capa_jsp_payload
        $payload1 = "ProcessBuilder" fullword ascii wide
        $payload2 = "processCmd" fullword ascii wide
        // Runtime.getRuntime().exec(
        $rt_payload1 = "Runtime" fullword ascii wide
        $rt_payload2 = "getRuntime" fullword ascii wide
        $rt_payload3 = "exec" fullword ascii wide

    condition:
        filesize < 300KB and not (
        uint16(0) == 0x5a4d or
        $dex at 0 or
        $pack at 0 or
        // fp on jar with zero compression
        uint16(0) == 0x4b50
        )
        and (
        $cjsp_short1 at 0 or
            any of ( $cjsp_long* ) or
            $cjsp_short2 in ( filesize-100..filesize ) or
        (
            $cjsp_short2 and (
                $cjsp_short1 in ( 0..1000 ) or
                $cjsp_short1 in ( filesize-1000..filesize )
            )
        )
        )
        and (
            any of ( $input* ) and
            any of ( $req* )
        )
        and (
        1 of ( $payload* ) or
        all of ( $rt_payload* )
        )
        and not any of ( $fp* ) and any of ( $susp* )
}

rule webshell_jsp_generic_base64
{
    meta:
        description = "Generic JSP webshell with base64 encoded payload"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021/01/24"
        modified = "2023-04-05"
        hash = "8b5fe53f8833df3657ae2eeafb4fd101c05f0db0"
        hash = "1b916afdd415dfa4e77cecf47321fd676ba2184d"

    strings:
        // Runtime
        $one1 = "SdW50aW1l" wide ascii
        $one2 = "J1bnRpbW" wide ascii
        $one3 = "UnVudGltZ" wide ascii
        $one4 = "IAdQBuAHQAaQBtAGUA" wide ascii
        $one5 = "SAHUAbgB0AGkAbQBlA" wide ascii
        $one6 = "UgB1AG4AdABpAG0AZQ" wide ascii
        // exec
        $two1 = "leGVj" wide ascii
        $two2 = "V4ZW" wide ascii
        $two3 = "ZXhlY" wide ascii
        $two4 = "UAeABlAGMA" wide ascii
        $two5 = "lAHgAZQBjA" wide ascii
        $two6 = "ZQB4AGUAYw" wide ascii
        // ScriptEngineFactory
        $three1 = "TY3JpcHRFbmdpbmVGYWN0b3J5" wide ascii
        $three2 = "NjcmlwdEVuZ2luZUZhY3Rvcn" wide ascii
        $three3 = "U2NyaXB0RW5naW5lRmFjdG9ye" wide ascii
        $three4 = "MAYwByAGkAcAB0AEUAbgBnAGkAbgBlAEYAYQBjAHQAbwByAHkA" wide ascii
        $three5 = "TAGMAcgBpAHAAdABFAG4AZwBpAG4AZQBGAGEAYwB0AG8AcgB5A" wide ascii
        $three6 = "UwBjAHIAaQBwAHQARQBuAGcAaQBuAGUARgBhAGMAdABvAHIAeQ" wide ascii


        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii wide
        $cjsp_short2 = "%>" wide ascii
        $cjsp_long1 = "<jsp:" ascii wide
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
        // JSF
        $cjsp_long3 = "/jstl/core" ascii wide
        $cjsp_long4 = "<%@p" nocase ascii wide
        $cjsp_long5 = "<%@ " nocase ascii wide
        $cjsp_long6 = "<% " ascii wide
        $cjsp_long7 = "< %" ascii wide

        //strings from private rule capa_bin_files
        $dex   = { 64 65 ( 78 | 79 ) 0a 30 }
        $pack  = { 50 41 43 4b 00 00 00 02 00 }

    condition:
        (
        $cjsp_short1 at 0 or
            any of ( $cjsp_long* ) or
            $cjsp_short2 in ( filesize-100..filesize ) or
        (
            $cjsp_short2 and (
                $cjsp_short1 in ( 0..1000 ) or
                $cjsp_short1 in ( filesize-1000..filesize )
            )
        )
        )
        and not (
        uint16(0) == 0x5a4d or
        $dex at 0 or
        $pack at 0 or
        // fp on jar with zero compression
        uint16(0) == 0x4b50
        )
        and filesize < 300KB and
        ( any of ( $one* ) and any of ( $two* ) or any of ( $three* ) )
}

rule webshell_jsp_generic_processbuilder
{
    meta:
        description = "Generic JSP webshell which uses processbuilder to execute user input"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021/01/07"
        modified = "2023-04-05"
        hash = "82198670ac2072cd5c2853d59dcd0f8dfcc28923"
        hash = "c05a520d96e4ebf9eb5c73fc0fa446ceb5caf343"
        hash = "347a55c174ee39ec912d9107e971d740f3208d53af43ea480f502d177106bbe8"
        hash = "d0ba29b646274e8cda5be1b940a38d248880d9e2bba11d994d4392c80d6b65bd"

    strings:
        $exec = "ProcessBuilder" fullword wide ascii
        $start = "start" fullword wide ascii

        //strings from private rule capa_jsp_input
        // request.getParameter
        $input1 = "getParameter" fullword ascii wide
        // request.getHeaders
        $input2 = "getHeaders" fullword ascii wide
        $input3 = "getInputStream" fullword ascii wide
        $input4 = "getReader" fullword ascii wide
        $req1 = "request" fullword ascii wide
        $req2 = "HttpServletRequest" fullword ascii wide
        $req3 = "getRequest" fullword ascii wide

    condition:
        filesize < 2000 and (
            any of ( $input* ) and
            any of ( $req* )
        )
        and $exec and $start
}

rule webshell_jsp_generic_reflection
{
    meta:
        description = "Generic JSP webshell which uses reflection to execute user input"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021/01/07"
        modified = "2023-04-05"
        hash = "62e6c6065b5ca45819c1fc049518c81d7d165744"
        hash = "bf0ff88cbb72c719a291c722ae3115b91748d5c4920afe7a00a0d921d562e188"

    strings:
        $ws_exec = "invoke" fullword wide ascii
        $ws_class = "Class" fullword wide ascii
        $fp = "SOAPConnection"

        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii wide
        $cjsp_short2 = "%>" wide ascii
        $cjsp_long1 = "<jsp:" ascii wide
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
        // JSF
        $cjsp_long3 = "/jstl/core" ascii wide
        $cjsp_long4 = "<%@p" nocase ascii wide
        $cjsp_long5 = "<%@ " nocase ascii wide
        $cjsp_long6 = "<% " ascii wide
        $cjsp_long7 = "< %" ascii wide

        //strings from private rule capa_jsp_input
        // request.getParameter
        $input1 = "getParameter" fullword ascii wide
        // request.getHeaders
        $input2 = "getHeaders" fullword ascii wide
        $input3 = "getInputStream" fullword ascii wide
        $input4 = "getReader" fullword ascii wide
        $req1 = "request" fullword ascii wide
        $req2 = "HttpServletRequest" fullword ascii wide
        $req3 = "getRequest" fullword ascii wide

        $cj_encoded1 = "\"java.util.Base64$Decoder\"" ascii wide
    condition:
        //any of them or
        all of ( $ws_* ) and (
        $cjsp_short1 at 0 or
            any of ( $cjsp_long* ) or
            $cjsp_short2 in ( filesize-100..filesize ) or
        (
            $cjsp_short2 and (
                $cjsp_short1 in ( 0..1000 ) or
                $cjsp_short1 in ( filesize-1000..filesize )
            )
        )
        )
        and not $fp and
        (
            // either some kind of code input from the a web request ...
            filesize < 10KB and
            (
                any of ( $input* ) and
                any of ( $req* )
            )
            or
            (
                // ... or some encoded payload (which might get code input from a web request)
                filesize < 30KB and
                any of ( $cj_encoded* ) and
                // base64 :
                // ignore first and last 500bytes because they usually contain code for decoding and executing
                math.entropy(500, filesize-500) >= 5.5 and
                // encoded text has a higher mean than text or code because it's missing the spaces and special chars with the low numbers
                math.mean(500, filesize-500) > 80 and
                // deviation of base64 is ~20 according to CyberChef_v9.21.0.html#recipe=Generate_Lorem_Ipsum(3,'Paragraphs')To_Base64('A-Za-z0-9%2B/%3D')To_Charcode('Space',10)Standard_Deviation('Space')
                // lets take a bit more because it might not be pure base64 also include some xor, shift, replacement, ...
                // 89 is the mean of the base64 chars
                math.deviation(500, filesize-500, 89.0) < 23
            )
        )

}

rule webshell_jsp_generic_classloader
{
    meta:
        description = "Generic JSP webshell which uses classloader to execute user input"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        hash = "6b546e78cc7821b63192bb8e087c133e8702a377d17baaeb64b13f0dd61e2347"
        date = "2021/01/07"
        modified = "2023-04-05"
        hash = "f3a7e28e1c38fa5d37811bdda1d6b0893ab876023d3bd696747a35c04141dcf0"
        hash = "8ea2a25344e6094fa82dfc097bbec5f1675f6058f2b7560deb4390bcbce5a0e7"
        hash = "b9ea1e9f91c70160ee29151aa35f23c236d220c72709b2b75123e6fa1da5c86c"
        hash = "80211c97f5b5cd6c3ab23ae51003fd73409d273727ba502d052f6c2bd07046d6"
        hash = "8e544a5f0c242d1f7be503e045738369405d39731fcd553a38b568e0889af1f2"

    strings:
        $exec = "extends ClassLoader" wide ascii
        $class = "defineClass" fullword wide ascii

        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii wide
        $cjsp_short2 = "%>" wide ascii
        $cjsp_long1 = "<jsp:" ascii wide
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
        // JSF
        $cjsp_long3 = "/jstl/core" ascii wide
        $cjsp_long4 = "<%@p" nocase ascii wide
        $cjsp_long5 = "<%@ " nocase ascii wide
        $cjsp_long6 = "<% " ascii wide
        $cjsp_long7 = "< %" ascii wide

        //strings from private rule capa_jsp_input
        // request.getParameter
        $input1 = "getParameter" fullword ascii wide
        // request.getHeaders
        $input2 = "getHeaders" fullword ascii wide
        $input3 = "getInputStream" fullword ascii wide
        $input4 = "getReader" fullword ascii wide
        $req1 = "request" fullword ascii wide
        $req2 = "HttpServletRequest" fullword ascii wide
        $req3 = "getRequest" fullword ascii wide

    condition:
        //any of them or
        (
            (
                $cjsp_short1 at 0 or
                    any of ( $cjsp_long* ) or
                    $cjsp_short2 in ( filesize-100..filesize ) or
                (
                    $cjsp_short2 and (
                        $cjsp_short1 in ( 0..1000 ) or
                        $cjsp_short1 in ( filesize-1000..filesize )
                    )
                )
            )
            and (
                any of ( $input* ) and
                any of ( $req* )
            )
            and $exec and $class
        ) and
        (
            filesize < 10KB or
            (
                filesize < 50KB and
                (
                    // filled with same characters
                    math.entropy(500, filesize-500) <= 1 or
                    // filled with random garbage
                    math.entropy(500, filesize-500) >= 7.7
                )
            )
        )
}

rule webshell_jsp_generic_encoded_shell
{
    meta:
        description = "Generic JSP webshell which contains cmd or /bin/bash encoded in ascii ord"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021/01/07"
        modified = "2023-04-05"
        hash = "3eecc354390d60878afaa67a20b0802ce5805f3a9bb34e74dd8c363e3ca0ea5c"

    strings:
        $sj0 = /{ ?47, 98, 105, 110, 47, 98, 97, 115, 104/ wide ascii
        $sj1 = /{ ?99, 109, 100}/ wide ascii
        $sj2 = /{ ?99, 109, 100, 46, 101, 120, 101/ wide ascii
        $sj3 = /{ ?47, 98, 105, 110, 47, 98, 97/ wide ascii
        $sj4 = /{ ?106, 97, 118, 97, 46, 108, 97, 110/ wide ascii
        $sj5 = /{ ?101, 120, 101, 99 }/ wide ascii
        $sj6 = /{ ?103, 101, 116, 82, 117, 110/ wide ascii

    condition:
        filesize <300KB and any of ($sj*)
}

rule webshell_jsp_netspy
{
    meta:
        description = "JSP netspy webshell"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021/01/24"
        modified = "2023-04-05"
        hash = "94d1aaabde8ff9b4b8f394dc68caebf981c86587"
        hash = "3870b31f26975a7cb424eab6521fc9bffc2af580"

    strings:
        $scan1 = "scan" nocase wide ascii
        $scan2 = "port" nocase wide ascii
        $scan3 = "web" fullword nocase wide ascii
        $scan4 = "proxy" fullword nocase wide ascii
        $scan5 = "http" fullword nocase wide ascii
        $scan6 = "https" fullword nocase wide ascii
        $write1 = "os.write" fullword wide ascii
        $write2 = "FileOutputStream" fullword wide ascii
        $write3 = "PrintWriter" fullword wide ascii
        $http = "java.net.HttpURLConnection" fullword wide ascii

        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii wide
        $cjsp_short2 = "%>" wide ascii
        $cjsp_long1 = "<jsp:" ascii wide
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
        // JSF
        $cjsp_long3 = "/jstl/core" ascii wide
        $cjsp_long4 = "<%@p" nocase ascii wide
        $cjsp_long5 = "<%@ " nocase ascii wide
        $cjsp_long6 = "<% " ascii wide
        $cjsp_long7 = "< %" ascii wide

        //strings from private rule capa_jsp_input
        // request.getParameter
        $input1 = "getParameter" fullword ascii wide
        // request.getHeaders
        $input2 = "getHeaders" fullword ascii wide
        $input3 = "getInputStream" fullword ascii wide
        $input4 = "getReader" fullword ascii wide
        $req1 = "request" fullword ascii wide
        $req2 = "HttpServletRequest" fullword ascii wide
        $req3 = "getRequest" fullword ascii wide

    condition:
        filesize < 30KB and (
        $cjsp_short1 at 0 or
            any of ( $cjsp_long* ) or
            $cjsp_short2 in ( filesize-100..filesize ) or
        (
            $cjsp_short2 and (
                $cjsp_short1 in ( 0..1000 ) or
                $cjsp_short1 in ( filesize-1000..filesize )
            )
        )
        )
        and (
            any of ( $input* ) and
            any of ( $req* )
        )
        and 4 of ( $scan* ) and 1 of ( $write* ) and $http
}

rule webshell_jsp_by_string
{
    meta:
        description = "JSP Webshells which contain unique strings, lousy rule for low hanging fruits. Most are catched by other rules in here but maybe these catch different versions."
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021/01/09"
        modified = "2023-04-05"
        hash = "e9060aa2caf96be49e3b6f490d08b8a996c4b084"
        hash = "4c2464503237beba54f66f4a099e7e75028707aa"
        hash = "06b42d4707e7326aff402ecbb585884863c6351a"
        hash = "dada47c052ec7fcf11d5cfb25693bc300d3df87de182a254f9b66c7c2c63bf2e"
        hash = "f9f6c696c1f90df6421cd9878a1dec51a62e91b4b4f7eac4920399cb39bc3139"
        hash = "f1d8360dc92544cce301949e23aad6eb49049bacf9b7f54c24f89f7f02d214bb"
        hash = "1d1f26b1925a9d0caca3fdd8116629bbcf69f37f751a532b7096a1e37f4f0076"
        hash = "850f998753fde301d7c688b4eca784a045130039512cf51292fcb678187c560b"

    strings:
        $jstring1 = "<title>Boot Shell</title>" wide ascii
        $jstring2 = "String oraPWD=\"" wide ascii
        $jstring3 = "Owned by Chinese Hackers!" wide ascii
        $jstring4 = "AntSword JSP" wide ascii
        $jstring5 = "JSP Webshell</" wide ascii
        $jstring6 = "motoME722remind2012" wide ascii
        $jstring7 = "EC(getFromBase64(toStringHex(request.getParameter(\"password" wide ascii
        $jstring8 = "http://jmmm.com/web/index.jsp" wide ascii
        $jstring9 = "list.jsp = Directory & File View" wide ascii
        $jstring10 = "jdbcRowSet.setDataSourceName(request.getParameter(" wide ascii
        $jstring11 = "Mr.Un1k0d3r RingZer0 Team" wide ascii
        $jstring12 = "MiniWebCmdShell" fullword wide ascii
        $jstring13 = "pwnshell.jsp" fullword wide ascii
        $jstring14 = "session set &lt;key&gt; &lt;value&gt; [class]<br>"  wide ascii
        $jstring15 = "Runtime.getRuntime().exec(request.getParameter(" nocase wide ascii
        $jstring16 = "GIF98a<%@page" wide ascii
        $jstring17 = "Tas9er" fullword wide ascii
        $jstring18 = "uu0028\\u" wide ascii //obfuscated /
        $jstring19 = "uu0065\\u" wide ascii //obfuscated e
        $jstring20 = "uu0073\\u" wide ascii //obfuscated s
        $jstring21 = /\\uuu{0,50}00/ wide ascii //obfuscated via javas unlimited amount of u in \uuuuuu
        $jstring22 = /[\w\.]\\u(FFFB|FEFF|FFF9|FFFA|200C|202E|202D)[\w\.]/ wide ascii // java ignores the unicode Interlinear Annotation Terminator inbetween any command
        $jstring23 = "\"e45e329feb5d925b\"" wide ascii
        $jstring24 = "u<![CDATA[n" wide ascii

        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii wide
        $cjsp_short2 = "%>" wide ascii
        $cjsp_long1 = "<jsp:" ascii wide
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
        // JSF
        $cjsp_long3 = "/jstl/core" ascii wide
        $cjsp_long4 = "<%@p" nocase ascii wide
        $cjsp_long5 = "<%@ " nocase ascii wide
        $cjsp_long6 = "<% " ascii wide
        $cjsp_long7 = "< %" ascii wide

        //strings from private rule capa_bin_files
        $dex   = { 64 65 ( 78 | 79 ) 0a 30 }
        $pack  = { 50 41 43 4b 00 00 00 02 00 }

    condition:
        //any of them or
        not (
            uint16(0) == 0x5a4d or
            $dex at 0 or
            $pack at 0 or
            // fp on jar with zero compression
            uint16(0) == 0x4b50
        ) and
        (
            (
                filesize < 100KB and
                (
                    $cjsp_short1 at 0 or
                    any of ( $cjsp_long* ) or
                    $cjsp_short2 in ( filesize-100..filesize ) or
                    (
                        $cjsp_short2 and (
                            $cjsp_short1 in ( 0..1000 ) or
                            $cjsp_short1 in ( filesize-1000..filesize )
                        )
                    )
                )
                and any of ( $jstring* )
            ) or (
                filesize < 500KB and
                (
                    #jstring21 > 20 or
                    $jstring18 or
                    $jstring19 or
                    $jstring20

                )
            )
        )
}

rule webshell_jsp_input_upload_write
{
    meta:
        description = "JSP uploader which gets input, writes files and contains \"upload\""
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021/01/24"
        modified = "2023-04-05"
        hash = "ef98ca135dfb9dcdd2f730b18e883adf50c4ab82"
        hash = "583231786bc1d0ecca7d8d2b083804736a3f0a32"
        hash = "19eca79163259d80375ebebbc440b9545163e6a3"

    strings:
        $upload = "upload" nocase wide ascii
        $write1 = "os.write" fullword wide ascii
        $write2 = "FileOutputStream" fullword wide ascii

        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii wide
        $cjsp_short2 = "%>" wide ascii
        $cjsp_long1 = "<jsp:" ascii wide
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
        // JSF
        $cjsp_long3 = "/jstl/core" ascii wide
        $cjsp_long4 = "<%@p" nocase ascii wide
        $cjsp_long5 = "<%@ " nocase ascii wide
        $cjsp_long6 = "<% " ascii wide
        $cjsp_long7 = "< %" ascii wide

        //strings from private rule capa_jsp_input
        // request.getParameter
        $input1 = "getParameter" fullword ascii wide
        // request.getHeaders
        $input2 = "getHeaders" fullword ascii wide
        $input3 = "getInputStream" fullword ascii wide
        $input4 = "getReader" fullword ascii wide
        $req1 = "request" fullword ascii wide
        $req2 = "HttpServletRequest" fullword ascii wide
        $req3 = "getRequest" fullword ascii wide

    condition:
        filesize < 10KB and (
        $cjsp_short1 at 0 or
            any of ( $cjsp_long* ) or
            $cjsp_short2 in ( filesize-100..filesize ) or
        (
            $cjsp_short2 and (
                $cjsp_short1 in ( 0..1000 ) or
                $cjsp_short1 in ( filesize-1000..filesize )
            )
        )
        )
        and (
            any of ( $input* ) and
            any of ( $req* )
        )
        and $upload and 1 of ( $write* )
}

rule WEBSHELL_generic_os_strings : FILE {
    meta:
        description = "typical webshell strings"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021/01/12"
        modified = "2023-04-05"
        score = 50
    strings:
        $fp1 = "http://evil.com/" wide ascii
        $fp2 = "denormalize('/etc/shadow" wide ascii
      $fp3 = "vim.org>"

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii wide
        $cjsp_short2 = "%>" wide ascii
        $cjsp_long1 = "<jsp:" ascii wide
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
        // JSF
        $cjsp_long3 = "/jstl/core" ascii wide
        $cjsp_long4 = "<%@p" nocase ascii wide
        $cjsp_long5 = "<%@ " nocase ascii wide
        $cjsp_long6 = "<% " ascii wide
        $cjsp_long7 = "< %" ascii wide

        //strings from private rule capa_os_strings
        // windows = nocase
        $w1 = "net localgroup administrators" nocase wide ascii
        $w2 = "net user" nocase wide ascii
        $w3 = "/add" nocase wide ascii
        // linux stuff, case sensitive:
        $l1 = "/etc/shadow" wide ascii
        $l2 = "/etc/ssh/sshd_config" wide ascii
        $take_two1 = "net user" nocase wide ascii
        $take_two2 = "/add" nocase wide ascii

    condition:
        filesize < 70KB and
        ( (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        or (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        or (
        $cjsp_short1 at 0 or
            any of ( $cjsp_long* ) or
            $cjsp_short2 in ( filesize-100..filesize ) or
        (
            $cjsp_short2 and (
                $cjsp_short1 in ( 0..1000 ) or
                $cjsp_short1 in ( filesize-1000..filesize )
            )
        )
        )
        ) and (
            filesize < 300KB and
        not uint16(0) == 0x5a4d and (
            all of ( $w* ) or
            all of ( $l* ) or
            2 of ( $take_two* )
        )
        )
        and not any of ( $fp* )
}

rule webshell_in_image
{
    meta:
        description = "Webshell in GIF, PNG or JPG"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        hash = "d4fde4e691db3e70a6320e78657480e563a9f87935af873a99db72d6a9a83c78"
        hash = "84938133ee6e139a2816ab1afc1c83f27243c8ae76746ceb2e7f20649b5b16a4"
        hash = "52b918a64afc55d28cd491de451bb89c57bce424f8696d6a94ec31fb99b17c11"
        date = "2021/02/27"
        modified = "2023-04-05"
        score = 55

    strings:
        $png = { 89 50 4E 47 }
        $jpg = { FF D8 FF E0 }
        $gif = "GIF8" wide ascii // doesn't make sense for a GIF but some webshells are utf8 :)
        $gif2 = "gif89" // not a valid gif but used in webshells
        $gif3 = "Gif89" // not a valid gif but used in webshells
        // MS access
        $mdb = { 00 01 00 00 53 74 }
        //$mdb = { 00 01 00 00 53 74 61 6E 64 61 72 64 20 4A 65 74 20 44 42 }

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

        //strings from private rule capa_php_payload
        // \([^)] to avoid matching on e.g. eval() in comments
        $cpayload1 = /\beval[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload2 = /\bexec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload3 = /\bshell_exec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload4 = /\bpassthru[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload5 = /\bsystem[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload6 = /\bpopen[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload7 = /\bproc_open[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload8 = /\bpcntl_exec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload9 = /\bassert[\n\t ]*\([^)0]/ nocase wide ascii
        $cpayload10 = /\bpreg_replace[\n\t ]*(\(.{1,|\/\*)100}\/[ismxADSUXju]{0,11}(e|\\x65)/ nocase wide ascii
        $cpayload12 = /\bmb_ereg_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
        $cpayload13 = /\bmb_eregi_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
        $cpayload20 = /\bcreate_function[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload21 = /\bReflectionFunction[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
        $cpayload22 = /fetchall\(PDO::FETCH_FUNC[\n\t ]*[,}\)]/ nocase wide ascii

        $m_cpayload_preg_filter1 = /\bpreg_filter[\n\t ]*(\([^\)]|\/\*)/ nocase wide ascii
        $m_cpayload_preg_filter2 = "'|.*|e'" nocase wide ascii
        // TODO backticks

        //strings from private rule capa_php_write_file
        $php_multi_write1 = "fopen(" wide ascii
        $php_multi_write2 = "fwrite(" wide ascii
        $php_write1 = "move_uploaded_file" fullword wide ascii

        //strings from private rule capa_jsp
        $cjsp1 = "<%" ascii wide
        $cjsp2 = "<jsp:" ascii wide
        $cjsp3 = /language=[\"']java[\"\']/ ascii wide
        // JSF
        $cjsp4 = "/jstl/core" ascii wide

        //strings from private rule capa_jsp_payload
        $payload1 = "ProcessBuilder" fullword ascii wide
        $payload2 = "processCmd" fullword ascii wide
        // Runtime.getRuntime().exec(
        $rt_payload1 = "Runtime" fullword ascii wide
        $rt_payload2 = "getRuntime" fullword ascii wide
        $rt_payload3 = "exec" fullword ascii wide

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword


        //strings from private rule capa_asp_payload
        $asp_payload0  = "eval_r" fullword nocase wide ascii
        $asp_payload1  = /\beval\s/ nocase wide ascii
        $asp_payload2  = /\beval\(/ nocase wide ascii
        $asp_payload3  = /\beval\"\"/ nocase wide ascii
        // var Fla = {'E':eval};  Fla.E(code)
        $asp_payload4  = /:\s{0,10}eval\b/ nocase wide ascii
        $asp_payload8  = /\bexecute\s?\(/ nocase wide ascii
        $asp_payload9  = /\bexecute\s[\w"]/ nocase wide ascii
        $asp_payload11 = "WSCRIPT.SHELL" fullword nocase wide ascii
        $asp_payload13 = "ExecuteGlobal" fullword nocase wide ascii
        $asp_payload14 = "ExecuteStatement" fullword nocase wide ascii
        $asp_payload15 = "ExecuteStatement" fullword nocase wide ascii
        $asp_multi_payload_one1 = "CreateObject" nocase fullword wide ascii
        $asp_multi_payload_one2 = "addcode" fullword wide ascii
        $asp_multi_payload_one3 = /\.run\b/ wide ascii
        $asp_multi_payload_two1 = "CreateInstanceFromVirtualPath" fullword wide ascii
        $asp_multi_payload_two2 = "ProcessRequest" fullword wide ascii
        $asp_multi_payload_two3 = "BuildManager" fullword wide ascii
        $asp_multi_payload_three1 = "System.Diagnostics" wide ascii
        $asp_multi_payload_three2 = "Process" fullword wide ascii
        $asp_multi_payload_three3 = ".Start" wide ascii
        // this is about "MSXML2.DOMDocument" but since that's easily obfuscated, lets not search for it
        $asp_multi_payload_four1 = "CreateObject" fullword nocase wide ascii
        $asp_multi_payload_four2 = "TransformNode" fullword nocase wide ascii
        $asp_multi_payload_four3 = "loadxml" fullword nocase wide ascii

        // execute cmd.exe /c with arguments using ProcessStartInfo
        $asp_multi_payload_five1 = "ProcessStartInfo" fullword nocase wide ascii
        $asp_multi_payload_five2 = ".Start" nocase wide ascii
        $asp_multi_payload_five3 = ".Filename" nocase wide ascii
        $asp_multi_payload_five4 = ".Arguments" nocase wide ascii


        //strings from private rule capa_asp_write_file
        // $asp_write1 = "ADODB.Stream" wide ascii # just a string, can be easily obfuscated
        $asp_always_write1 = /\.write/ nocase wide ascii
        $asp_always_write2 = /\.swrite/ nocase wide ascii
        //$asp_write_way_one1 = /\.open\b/ nocase wide ascii
        $asp_write_way_one2 = "SaveToFile" fullword nocase wide ascii
        $asp_write_way_one3 = "CREAtEtExtFiLE" fullword nocase wide ascii
        $asp_cr_write1 = "CreateObject(" nocase wide ascii
        $asp_cr_write2 = "CreateObject (" nocase wide ascii
        $asp_streamwriter1 = "streamwriter" fullword nocase wide ascii
        $asp_streamwriter2 = "filestream" fullword nocase wide ascii

    condition:
        // reduce fp
        //any of them or
        filesize < 5MB and
        // also check for GIF8 at 0x3 because some folks write their webshell in a text editor and have a BOM in front of GIF8 (which probably wouldn't be a valif GIF anymore :)
        ( $png at 0 or $jpg at 0 or $gif at 0 or $gif at 3 or $gif2 at 0 or $gif2 at 3 or $gif3 at 0 or $mdb at 0 ) and
        ( ( (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and
        ( (
            any of ( $cpayload* ) or
        all of ( $m_cpayload_preg_filter* )
        )
        or (
        any of ( $php_write* ) or
        all of ( $php_multi_write* )
        )
        ) ) or
        ( (
            any of ( $cjsp* )
        )
        and (
        1 of ( $payload* ) or
        all of ( $rt_payload* )
        )
        ) or
        ( (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        and
        ( (
            any of ( $asp_payload* ) or
        all of ( $asp_multi_payload_one* ) or
        all of ( $asp_multi_payload_two* ) or
        all of ( $asp_multi_payload_three* ) or
        all of ( $asp_multi_payload_four* ) or
        all of ( $asp_multi_payload_five* )
        )
        or (
        any of ( $asp_always_write* ) and
        (
            any of ( $asp_write_way_one* ) and
            any of ( $asp_cr_write* )
        ) or (
            any of ( $asp_streamwriter* )
        )
        )
        ) ) )
}

rule WEBSHELL_Mixed_Obfuscations {
   meta:
      description = "Detects webshell with mixed obfuscation commands"
      author = "Arnim Rupp (https://github.com/ruppde)"
      reference = "https://github.com/Neo23x0/yarGen"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      date = "2023-01-28"
        modified = "2023-04-05"
      hash1 = "8c4e5c6bdfcc86fa27bdfb075a7c9a769423ec6d53b73c80cbc71a6f8dd5aace"
      hash2 = "78f2086b6308315f5f0795aeaa75544128f14889a794205f5fc97d7ca639335b"
      hash3 = "3bca764d44074820618e1c831449168f220121698a7c82e9909f8eab2e297cbd"
      hash4 = "b26b5e5cba45482f486ff7c75b54c90b7d1957fd8e272ddb4b2488ec65a2936e"
      hash5 = "e217be2c533bfddbbdb6dc6a628e0d8756a217c3ddc083894e07fd3a7408756c"
      score = 50
   strings:
      $s1 = "rawurldecode/*" ascii
      $s2 = "preg_replace/*" ascii
      $s3 = " __FILE__/*" ascii
      $s4 = "strlen/*" ascii
      $s5 = "str_repeat/*" ascii
      $s6 = "basename/*" ascii
   condition:
      ( uint16(0) == 0x3f3c and filesize < 200KB and ( 4 of them ))
}

rule WEBSHELL_Cookie_Post_Obfuscation {
    meta:
        description = "Detects webshell using cookie POST"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2023-01-28"
        modified = "2023-04-05"
        license = "https://github.com/SigmaHQ/Detection-Rule-License/blob/main/LICENSE.Detection.Rules.md"
        hash = "d08a00e56feb78b7f6599bad6b9b1d8626ce9a6ea1dfdc038358f4c74e6f65c9"
        hash = "2ce5c4d31682a5a59b665905a6f698c280451117e4aa3aee11523472688edb31"
        hash = "ff732d91a93dfd1612aed24bbb4d13edb0ab224d874f622943aaeeed4356c662"
        hash = "a3b64e9e065602d2863fcab641c75f5d8ec67c8632db0f78ca33ded0f4cea257"
        hash = "d41abce305b0dc9bd3a9feb0b6b35e8e39db9e75efb055d0b1205a9f0c89128e"
        hash = "333560bdc876fb0186fae97a58c27dd68123be875d510f46098fc5a61615f124"
        hash = "2efdb79cdde9396ff3dd567db8876607577718db692adf641f595626ef64d3a4"
        hash = "e1bd3be0cf525a0d61bf8c18e3ffaf3330c1c27c861aede486fd0f1b6930f69a"
        hash = "f8cdedd21b2cc29497896ec5b6e5863cd67cc1a798d929fd32cdbb654a69168a"

    strings:
        $s1 = "]($_COOKIE, $_POST) as $"
        $s2 = "function"
        $s3 = "Array"
    condition:
    ( uint16(0) == 0x3f3c and filesize < 100KB and ( all of them ))
}
=======
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

import "pe"
private rule SentinelLabs_SUPERNOVA
{
    meta:
        description = "Identifies potential versions of App_Web_logoimagehandler.ashx.b6031896.dll weaponized with SUPERNOVA"
        date = "2020-12-22"
        author = "SentinelLabs"
        source = "https://labs.sentinelone.com/solarwinds-understanding-detecting-the-supernova-webshell-trojan/"
        
    strings:
        $ = "clazz"
        $ = "codes"
        $ = "args"
        $ = "ProcessRequest"
        $ = "DynamicRun"
        $ = "get_IsReusable"
        $ = "logoimagehandler.ashx" wide
        $ = "SiteNoclogoImage" wide
        $ = "SitelogoImage" wide

    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and pe.imports("mscoree.dll")) and all of them
}

rule SolarWindsArtifacts
{
    meta:
        author = "NSA Cybersecurity"
        description = "Artifacts common to the SolarWinds compromise."

    condition:
        APT_Backdoor_MSIL_SUNBURST_1 
        or APT_Backdoor_MSIL_SUNBURST_2 
        or APT_Backdoor_MSIL_SUNBURST_3 
        or APT_Backdoor_MSIL_SUNBURST_4 
        or APT_Dropper_Raw64_TEARDROP_1 
        or APT_Dropper_Win64_TEARDROP_2
        or SentinelLabs_SUPERNOVA
}

rule reGeorg_Variant_Web_shell {
    meta:
        description = "Matches the reGeorg variant web shell used by the actors."
        date = "2021-07-01"
        author = "National Security Agency"
        source = "https://media.defense.gov/2021/Jul/01/2002753896/-1/-1/1/CSA_GRU_GLOBAL_BRUTE_FORCE_CAMPAIGN_UOO158036-21.PDF"
        
    strings:
        $pageLanguage = "<%@ Page Language=\"C#\""
        $obfuscationFunction = "StrTr"
        $target = "target_str"
        $IPcomms = "System.Net.IPEndPoint"
        $addHeader = "Response.AddHeader"
        $socket = "Socket"
        
    condition:
        5 of them
}

