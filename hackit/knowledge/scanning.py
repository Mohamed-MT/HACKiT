from hackit.knowledge import RiskLevel, ToolInfo

TOOLS: list[ToolInfo] = [
    ToolInfo(
        name="nmap",
        category="scanning",
        package="nmap",
        summary="The standard network mapper — host discovery, port scanning, service/version and OS detection.",
        description=(
            "Nmap sends crafted packets to hosts and interprets the responses "
            "to determine which hosts are up, which ports are open/closed/"
            "filtered, what service and version is listening on each, and "
            "often the target's OS. Its NSE scripting engine extends this to "
            "vulnerability checks, enumeration, and more."
        ),
        when_to_use=(
            "This is the default answer to 'scan a network/host for open "
            "ports'. Start broad (fast TCP scan) to find what's alive, then "
            "narrow to a detailed scan of discovered hosts."
        ),
        risk=RiskLevel.LOW,
        requires_target_auth=True,
        command_template="nmap -sV -sC -p- <target>",
        args_explained={
            "-sS": "TCP SYN scan ('half-open') — fast and the default privileged scan type",
            "-sT": "TCP connect scan — use when you don't have raw-socket privileges",
            "-sU": "UDP scan — slower, but needed to find UDP services (DNS, SNMP, etc.)",
            "-sV": "Probe open ports to determine service/version info",
            "-sC": "Run the default set of safe NSE scripts (equivalent to --script=default)",
            "-O": "Attempt OS detection",
            "-p-": "Scan all 65535 TCP ports (default is the top 1000)",
            "-p 80,443": "Scan only the specified ports",
            "-A": "Aggressive: enables -sV -sC -O and traceroute in one flag",
            "-T4": "Timing template 4 (faster) — good default on reliable networks",
            "-oA <basename>": "Save output in normal, XML, and grepable formats simultaneously",
            "-Pn": "Skip host discovery and treat the target as up (useful if ICMP is blocked)",
        },
        example="nmap -sV -sC -T4 -p- -oA full_scan 10.10.10.5",
        expected_output=(
            "A per-host list of open/closed/filtered ports, each with the "
            "detected service and version, plus any default-script findings."
        ),
        common_errors=[
            "'Permission denied' on SYN scan: run with sudo or use -sT",
            "Scan appears to hang on -p- : it's just slow — add -T4 or narrow the port range",
            "No response / all filtered: a firewall may be dropping probes — try -Pn or -sA",
        ],
        next_steps=[
            "Run targeted NSE vuln scripts: nmap --script vuln <target>",
            "Enumerate any discovered services with protocol-specific tools (enum4linux for SMB, etc.)",
            "Feed open web ports into nikto/gobuster for web app testing",
        ],
        tags=["port scan", "network scan", "scanning", "host discovery", "service detection", "os detection", "nse"],
        alternatives=["masscan", "rustscan"],
    ),
    ToolInfo(
        name="masscan",
        category="scanning",
        package="masscan",
        summary="Extremely fast, asynchronous port scanner for huge IP ranges.",
        description=(
            "Masscan scans at a self-defined packet rate (not bound by "
            "per-host timing like nmap) and can sweep the entire IPv4 space "
            "for a handful of ports in minutes. It trades depth for raw speed."
        ),
        when_to_use=(
            "Use when the target scope is large (whole subnets/CIDR ranges) "
            "and you just need to know which hosts have a given port open, "
            "before running nmap for detail on the hits."
        ),
        risk=RiskLevel.MEDIUM,
        requires_target_auth=True,
        command_template="masscan -p<ports> <cidr> --rate <pps>",
        args_explained={
            "-p": "Ports to scan, e.g. -p80,443 or -p1-65535",
            "<cidr>": "Target range, e.g. 10.10.0.0/16",
            "--rate": "Packets per second to send — high rates can saturate links, so size this to the network",
            "-oJ / -oL": "Output as JSON / list format",
        },
        example="masscan -p1-1000 10.10.0.0/16 --rate 1000 -oL masscan_results.txt",
        expected_output="A stream of 'discovered open port' lines as results come in.",
        common_errors=[
            "Running too high a --rate on a fragile network can look like a DoS — size it conservatively",
            "Requires root/raw-socket capability",
        ],
        next_steps=["Pipe live hosts/ports into nmap -sV for service detail"],
        tags=["fast scan", "port scan", "cidr", "subnet", "large scope", "scanning"],
        alternatives=["nmap", "rustscan"],
    ),
    ToolInfo(
        name="rustscan",
        category="scanning",
        package="rustscan",
        summary="Very fast port scanner that pipes results into nmap for detail.",
        description=(
            "RustScan scans all 65535 ports quickly using an adaptive "
            "scanning strategy, then automatically hands the open ports to "
            "nmap to do the detailed service/version work — combining speed "
            "with nmap's depth."
        ),
        when_to_use="Use as a faster front-end when you want nmap-quality detail but don't want to wait on -p-.",
        risk=RiskLevel.LOW,
        requires_target_auth=True,
        command_template="rustscan -a <target> -- -sV -sC",
        args_explained={
            "-a": "Target address/CIDR",
            "-- -sV -sC": "Arguments after -- are passed straight through to nmap",
            "-b": "Batch size (parallelism) — lower it on unstable connections",
        },
        example="rustscan -a 10.10.10.5 -- -sV -sC",
        expected_output="Open ports found quickly, followed by nmap's detailed scan of just those ports.",
        common_errors=["File-descriptor limits on some systems — lower batch size with -b"],
        next_steps=["Proceed with the printed nmap results as you would after a normal nmap scan"],
        tags=["fast scan", "scanning", "nmap", "port scan"],
        alternatives=["nmap", "masscan"],
    ),
]
