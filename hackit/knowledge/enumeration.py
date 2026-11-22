from hackit.knowledge import RiskLevel, ToolInfo

TOOLS: list[ToolInfo] = [
    ToolInfo(
        name="enum4linux-ng",
        category="enumeration",
        package="enum4linux-ng",
        summary="Enumerates users, groups, shares, and policies from Windows/Samba hosts via SMB.",
        description=(
            "enum4linux-ng (a modernized rewrite of enum4linux) wraps several "
            "SMB/RPC probing techniques to pull domain/workgroup info, users, "
            "groups, shares, password policy, and OS details from a Windows "
            "or Samba host."
        ),
        when_to_use="Use after nmap shows SMB (port 445/139) open, to enumerate what the host will tell you.",
        risk=RiskLevel.LOW,
        requires_target_auth=True,
        command_template="enum4linux-ng -A <target>",
        args_explained={
            "-A": "Run all the standard enumeration checks",
            "-u/-p": "Provide credentials for authenticated (vs. anonymous/null-session) enumeration",
            "-oY": "Output as YAML",
        },
        example="enum4linux-ng -A 10.10.10.5",
        expected_output="Workgroup/domain name, SMB shares, users/groups (if accessible), and password policy.",
        common_errors=["Null sessions are disabled on modern Windows by default — authenticated enum may be needed"],
        next_steps=["List accessible shares with smbclient -L", "Password-spray discovered usernames (authorized only)"],
        tags=["smb", "windows", "samba", "enumeration", "shares", "users", "null session"],
        alternatives=["smbclient", "smbmap", "crackmapexec"],
    ),
    ToolInfo(
        name="smbclient",
        category="enumeration",
        package="smbclient",
        summary="Lists and interacts with SMB shares, FTP-style.",
        description=(
            "smbclient is an FTP-like client for SMB/CIFS shares — list "
            "available shares, connect to one, and browse/download files, "
            "either anonymously or with credentials."
        ),
        when_to_use="Use to actually browse into SMB shares that enum4linux-ng revealed.",
        risk=RiskLevel.LOW,
        requires_target_auth=True,
        command_template="smbclient -L //<target> -N",
        args_explained={
            "-L": "List shares on the target",
            "-N": "No password / attempt a null session",
            "-U": "Specify a username (will prompt for password)",
            "//<target>/<share>": "Connect directly into a specific share",
        },
        example="smbclient -L //10.10.10.5 -N",
        expected_output="A list of share names (e.g. ADMIN$, C$, IPC$, any custom shares) if listing is permitted.",
        common_errors=["NT_STATUS_ACCESS_DENIED — anonymous listing is disabled; try valid credentials"],
        next_steps=["Connect to an interesting share and 'get' files of interest"],
        tags=["smb", "shares", "windows", "enumeration", "ftp-like"],
        alternatives=["enum4linux-ng", "smbmap"],
    ),
    ToolInfo(
        name="snmp-check",
        category="enumeration",
        package="snmpcheck",
        summary="Enumerates system, network, and process info via SNMP.",
        description=(
            "snmp-check queries an SNMP-enabled device (often with the "
            "common default 'public' community string) for a large amount "
            "of information: system description, network interfaces, "
            "running processes, installed software, routing tables, and more."
        ),
        when_to_use="Use when nmap shows UDP/161 (SNMP) open — it's frequently left with weak/default community strings.",
        risk=RiskLevel.LOW,
        requires_target_auth=True,
        command_template="snmp-check -c <community> <target>",
        args_explained={
            "-c": "Community string to try (default 'public')",
            "-v": "SNMP version (1, 2c, or 3)",
        },
        example="snmp-check -c public 10.10.10.5",
        expected_output="System info, interfaces, open ports it reports, sometimes user accounts and processes.",
        common_errors=["Timeout: SNMP likely isn't exposed or the community string is wrong"],
        next_steps=["Try snmpwalk for raw OID walking if you need specific MIBs"],
        tags=["snmp", "enumeration", "community string", "network devices"],
        alternatives=["snmpwalk"],
    ),
    ToolInfo(
        name="gobuster",
        category="enumeration",
        package="gobuster",
        summary="Brute-forces directories, files, DNS subdomains, and vhosts.",
        description=(
            "Gobuster is a fast, Go-based brute-forcing tool with several "
            "modes: 'dir' for web paths/files, 'dns' for subdomains, and "
            "'vhost' for virtual hosts — all driven by a wordlist."
        ),
        when_to_use="Use in both enumeration and web-app testing: discovering hidden directories/files on a web server, or subdomains on a domain.",
        risk=RiskLevel.MEDIUM,
        requires_target_auth=True,
        command_template="gobuster dir -u <url> -w <wordlist>",
        args_explained={
            "dir": "Directory/file brute-force mode",
            "dns": "Subdomain brute-force mode",
            "vhost": "Virtual host brute-force mode",
            "-u": "Target URL (dir/vhost) or domain (dns)",
            "-w": "Path to the wordlist to use, e.g. /usr/share/wordlists/dirb/common.txt",
            "-x": "File extensions to also try, e.g. -x php,txt,bak",
            "-t": "Number of concurrent threads",
        },
        example="gobuster dir -u http://10.10.10.5 -w /usr/share/wordlists/dirb/common.txt -x php,txt",
        expected_output="A live-updating list of discovered paths/files with their HTTP status codes.",
        common_errors=["Lots of false-positive 200s on sites with custom 404 pages — check response size/wording"],
        next_steps=["Manually inspect any interesting discovered paths in a browser or with curl"],
        tags=["directory bruteforce", "subdomain", "vhost", "web", "enumeration", "wordlist"],
        alternatives=["ffuf", "dirb", "feroxbuster"],
    ),
]
