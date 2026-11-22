from hackit.knowledge import RiskLevel, ToolInfo

TOOLS: list[ToolInfo] = [
    ToolInfo(
        name="nikto",
        category="vuln_assessment",
        package="nikto",
        summary="Scans a web server for thousands of known-dangerous files, misconfigurations, and outdated software.",
        description=(
            "Nikto checks a web server against a large, regularly updated "
            "database of known vulnerable files/CGIs, outdated server "
            "software, dangerous default files, and common misconfigurations, "
            "and flags anything matching."
        ),
        when_to_use="Use as a quick first vulnerability pass on any discovered web server.",
        risk=RiskLevel.MEDIUM,
        requires_target_auth=True,
        command_template="nikto -h <target>",
        args_explained={
            "-h": "Target host/URL",
            "-p": "Port, if not 80/443",
            "-ssl": "Force SSL/TLS",
            "-o": "Output file",
            "-Tuning": "Restrict to specific test categories (e.g. 9 = SQL injection checks)",
        },
        example="nikto -h https://10.10.10.5 -o nikto_report.txt",
        expected_output="A line per finding: server header info, outdated versions, interesting/dangerous files found.",
        common_errors=["Noisy and easily logged/detected by IDS/WAFs — expect it to show up in target logs"],
        next_steps=["Manually verify interesting findings before treating them as confirmed vulnerabilities"],
        tags=["web", "vulnerability", "scanner", "misconfiguration", "cgi"],
        alternatives=["nessus", "openvas"],
    ),
    ToolInfo(
        name="openvas",
        category="vuln_assessment",
        package="gvm",
        summary="Full-scale, CVE-driven network vulnerability scanner with a web UI.",
        description=(
            "OpenVAS/GVM (the apt package is named 'gvm' — Greenbone "
            "Vulnerability Management, OpenVAS's current project name) runs "
            "thousands of vulnerability-detection tests (NVTs) against "
            "hosts, cross-referencing findings with CVEs and CVSS scores, "
            "and produces a prioritized report — closer to a commercial "
            "vuln-management product than a single CLI tool."
        ),
        when_to_use="Use for a broad, authoritative vulnerability assessment across many hosts, when you need CVE-level reporting.",
        risk=RiskLevel.MEDIUM,
        requires_target_auth=True,
        command_template="gvm-setup",
        args_explained={
            "gvm-setup": "First-time install/initialization of feeds and services",
            "gvm-start / gvm-stop": "Start/stop the GVM services",
            "gvm-check-setup": "Diagnose a broken setup",
        },
        example="gvm-setup",
        expected_output="A scan report in the web UI listing findings by severity, each mapped to CVEs where applicable.",
        common_errors=[
            "Initial feed sync can take hours the first time",
            "Needs real RAM/disk — can be heavy for a VM",
        ],
        next_steps=["After setup and feed synchronization finish, start the services separately with gvm-start", "Open the Greenbone web interface at https://127.0.0.1:9392, create a Target and Task, then review the report", "Export the report and prioritize remediation by CVSS score"],
        tags=["vulnerability scanner", "cve", "cvss", "network", "greenbone", "gvm"],
        alternatives=["nessus", "nikto"],
    ),
    ToolInfo(
        name="lynis",
        category="vuln_assessment",
        package="lynis",
        summary="Local security auditing and hardening-assessment tool for Unix/Linux systems.",
        description=(
            "Lynis runs entirely on the host it's auditing (no network "
            "scanning) and checks hundreds of configuration items — file "
            "permissions, installed packages, kernel settings, auth config, "
            "logging — against security best practice, then gives a hardening "
            "score and a list of suggestions."
        ),
        when_to_use="Use for a local/host-based assessment, e.g. after gaining access to a box, or auditing your own systems.",
        risk=RiskLevel.PASSIVE,
        requires_target_auth=False,
        command_template="sudo lynis audit system",
        args_explained={
            "audit system": "Run a full local audit",
            "--pentest": "A lighter, non-privileged scan profile suited to pentest engagements",
        },
        example="sudo lynis audit system",
        expected_output="A categorized list of warnings/suggestions and a 'hardening index' score at the end.",
        common_errors=["Some checks are skipped without root — rerun with sudo for full coverage"],
        next_steps=["Review the full log at /var/log/lynis.log for details behind each finding"],
        tags=["local audit", "hardening", "linux", "configuration", "host-based"],
        alternatives=[],
    ),
    ToolInfo(
        name="searchsploit",
        category="vuln_assessment",
        package="exploitdb",
        summary="Offline command-line search of the Exploit-DB archive.",
        description=(
            "searchsploit searches a local mirror of Exploit-DB by keyword, "
            "software name, or version, to see whether known public exploits "
            "or proof-of-concept code exist for something you've identified "
            "(e.g. a specific service version from nmap)."
        ),
        when_to_use="Use right after identifying a service/version to quickly check for known public exploits.",
        risk=RiskLevel.PASSIVE,
        requires_target_auth=False,
        command_template="searchsploit <software> <version>",
        args_explained={
            "-w": "Show the Exploit-DB web URL instead of the local path",
            "-m": "Copy (mirror) a specific exploit by its EDB-ID to the current directory",
            "--nmap": "Parse an nmap XML file and search for each identified service automatically",
        },
        example="searchsploit vsftpd 2.3.4",
        expected_output="A table of matching exploit titles with their Exploit-DB path/ID.",
        common_errors=["Database can be stale — run 'searchsploit -u' to update it"],
        next_steps=["Read the exploit code carefully before use; verify applicability and get authorization"],
        tags=["exploit-db", "known exploits", "cve", "search", "offline"],
        alternatives=[],
    ),
]
