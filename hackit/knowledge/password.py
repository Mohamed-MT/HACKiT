from hackit.knowledge import RiskLevel, ToolInfo

TOOLS: list[ToolInfo] = [
    ToolInfo(
        name="hydra",
        category="password",
        package="hydra",
        summary="Fast network login brute-forcer across dozens of protocols.",
        description=(
            "Hydra tries username/password combinations against a network "
            "service (SSH, FTP, HTTP forms, SMB, RDP, databases, and many "
            "more) in parallel, stopping on success or exhausting the list."
        ),
        when_to_use=(
            "Use for authorized password-strength testing of a specific "
            "login service — never against production/third-party systems "
            "without explicit, written authorization, since this is loud, "
            "easily detected, and can lock out accounts."
        ),
        risk=RiskLevel.HIGH,
        requires_target_auth=True,
        command_template="hydra -L <userlist> -P <passlist> <target> <service>",
        args_explained={
            "-l / -L": "A single username, or a file of usernames",
            "-p / -P": "A single password, or a file of passwords",
            "-t": "Number of parallel connection threads",
            "-f": "Stop as soon as the first valid pair is found",
            "<service>": "Protocol module to use, e.g. ssh, ftp, rdp, http-post-form",
        },
        example="hydra -L users.txt -P /usr/share/wordlists/rockyou.txt ssh://10.10.10.5 -t 4",
        expected_output="Lines like 'host: 10.10.10.5  login: admin  password: ...' for each hit, tagged with the port and service (22/ssh).",
        common_errors=[
            "Account lockout policies can lock out real users — confirm lockout thresholds are in scope/understood",
            "Too many threads can crash fragile services — start low (-t 4) and increase cautiously",
        ],
        next_steps=["Use any valid credentials found to continue enumeration/access, within agreed scope"],
        tags=["brute force", "password", "login", "ssh", "ftp", "http form", "credential"],
        alternatives=["medusa", "crackmapexec"],
    ),
    ToolInfo(
        name="john",
        category="password",
        package="john",
        summary="Offline password-hash cracker (John the Ripper).",
        description=(
            "John the Ripper cracks password hashes you already possess "
            "(e.g. dumped from a compromised system or extracted from a file) "
            "using wordlists, rules-based mangling, or brute force — entirely "
            "offline, with no traffic to any target."
        ),
        when_to_use="Use once you have hash values (e.g. from /etc/shadow, a SAM dump, or an app's database) to recover plaintext passwords.",
        risk=RiskLevel.PASSIVE,
        requires_target_auth=False,
        command_template="john --wordlist=<wordlist> <hashfile>",
        args_explained={
            "--wordlist": "Dictionary to try, e.g. /usr/share/wordlists/rockyou.txt",
            "--rules": "Apply mangling rules (leet-speak, capitalization, appended digits) to the wordlist",
            "--format": "Force a specific hash format if auto-detection guesses wrong",
            "john --show <hashfile>": "Display cracked passwords found so far",
        },
        example="john --wordlist=/usr/share/wordlists/rockyou.txt --rules shadow.hashes",
        expected_output="Cracked plaintexts printed as found; run 'john --show' afterward for a clean summary.",
        common_errors=["Format auto-detection can pick the wrong hash type — specify --format explicitly if cracking stalls"],
        next_steps=["Try hashcat instead for GPU-accelerated cracking on larger hash sets"],
        tags=["password cracking", "hash", "offline", "wordlist", "shadow"],
        alternatives=["hashcat"],
    ),
    ToolInfo(
        name="hashcat",
        category="password",
        package="hashcat",
        summary="GPU-accelerated offline password-hash cracker.",
        description=(
            "Hashcat uses GPU compute to try candidate passwords against "
            "hashes far faster than CPU-only tools, supporting hundreds of "
            "hash types and multiple attack modes (dictionary, rule-based, "
            "mask/brute-force, combinator)."
        ),
        when_to_use="Use instead of John when you have GPU hardware and/or a large hash set, for significant speed gains.",
        risk=RiskLevel.PASSIVE,
        requires_target_auth=False,
        command_template="hashcat -m <hash-mode> -a 0 <hashfile> <wordlist>",
        args_explained={
            "-m": "Hash type/mode ID, e.g. 1000 for NTLM, 1800 for sha512crypt — see 'hashcat --help'",
            "-a": "Attack mode: 0=dictionary, 1=combinator, 3=mask/brute-force, 6/7=hybrid",
            "-r": "Apply a rules file to mutate wordlist entries",
            "--show": "Display already-cracked hashes from the potfile",
        },
        example="hashcat -m 1000 -a 0 ntlm_hashes.txt /usr/share/wordlists/rockyou.txt",
        expected_output="Progress stats and cracked hash:plaintext pairs, saved to hashcat.potfile.",
        common_errors=["Wrong -m mode makes it 'crack' nothing — verify the hash format first (hashid can help)"],
        next_steps=["Run 'hashcat --show <hashfile>' any time to review all cracked results so far"],
        tags=["password cracking", "gpu", "hash", "ntlm", "offline"],
        alternatives=["john"],
    ),
    ToolInfo(
        name="crunch",
        category="password",
        package="crunch",
        summary="Generates custom wordlists based on character sets and patterns.",
        description=(
            "crunch produces every possible combination of a given character "
            "set within a length range (or following a specific pattern), "
            "for use as input to hydra/john/hashcat when a generic wordlist "
            "like rockyou.txt isn't a good fit (e.g. a known PIN format)."
        ),
        when_to_use="Use when you know something about the password structure (length, charset, pattern) and want a targeted list instead of a generic one.",
        risk=RiskLevel.PASSIVE,
        requires_target_auth=False,
        command_template="crunch <min-len> <max-len> <charset> -o <outfile>",
        args_explained={
            "<min-len> <max-len>": "Minimum and maximum password length to generate",
            "<charset>": "Characters to use, e.g. 0123456789 for numeric PINs",
            "-t": "Pattern template, e.g. @@@@%%%% for 4 letters + 4 digits",
            "-o": "Output file to write the generated list to",
        },
        example="crunch 4 4 0123456789 -o pins.txt",
        expected_output="A wordlist file containing every combination matching the given parameters.",
        common_errors=["Large ranges/charsets can generate enormous files — estimate size first with 'crunch ... -c' dry notes"],
        next_steps=["Feed the generated list into hydra, john, or hashcat"],
        tags=["wordlist generation", "password", "charset", "pattern"],
        alternatives=[],
    ),
]
