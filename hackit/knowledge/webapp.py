from hackit.knowledge import RiskLevel, ToolInfo

TOOLS: list[ToolInfo] = [
    ToolInfo(
        name="burpsuite",
        category="webapp",
        package="burpsuite",
        summary="Interactive web proxy/testing platform — the core tool for manual web app assessment.",
        description=(
            "Burp Suite sits as a proxy between your browser and the target "
            "web app, letting you inspect, intercept, and modify every "
            "request/response. Its toolset (Repeater, Intruder, Scanner in "
            "the Pro edition, extensions) covers almost every manual web "
            "testing technique."
        ),
        when_to_use="Use for any hands-on web app assessment — this is the primary tool, not a quick automated check.",
        risk=RiskLevel.LOW,
        requires_target_auth=True,
        command_template="burpsuite",
        args_explained={
            "Proxy tab": "Intercept and view/edit live requests",
            "Repeater": "Resend and tweak a single request repeatedly",
            "Intruder": "Automate payload injection across a request (fuzzing, brute force)",
            "Target > Site map": "Passively builds a map of the app as you browse it",
        },
        example="burpsuite",
        expected_output="A GUI; captured traffic appears under Proxy > HTTP history as you browse the target.",
        common_errors=["Forgetting to install Burp's CA cert in the browser blocks HTTPS interception"],
        next_steps=["Configure your browser to proxy through 127.0.0.1:8080", "Walk the app manually first to build the site map, then test individual parameters"],
        tags=["web", "proxy", "intercept", "manual testing", "intruder", "repeater"],
        alternatives=["owasp zap"],
    ),
    ToolInfo(
        name="zaproxy",
        category="webapp",
        package="zaproxy",
        summary="Free, open-source web app scanner/proxy (OWASP ZAP) — a good Burp Community alternative.",
        description=(
            "OWASP ZAP is a full web app security tool: an intercepting "
            "proxy plus an automated scanner, spider, and fuzzer, fully "
            "open-source and scriptable, including a headless/CLI mode for "
            "CI-style scans."
        ),
        when_to_use="Use when you want automated active/passive scanning in addition to manual proxying, or need a scriptable/headless workflow.",
        risk=RiskLevel.MEDIUM,
        requires_target_auth=True,
        command_template="zap.sh -cmd -quickurl <url> -quickout <report.html>",
        args_explained={
            "-cmd": "Run headless (no GUI)",
            "-quickurl": "URL to run ZAP's Quick Scan against",
            "-quickout": "Where to save the HTML report",
            "-daemon -port <n>": "Run as a background daemon exposing its API on a port",
        },
        example="zap.sh -cmd -quickurl http://10.10.10.5 -quickout zap_report.html",
        expected_output="An HTML/JSON report listing passive and active findings (XSS, SQLi hints, headers, etc.).",
        common_errors=["Active scan can be slow and intrusive — confirm scope before running it against production"],
        next_steps=["Triage findings manually; ZAP's automated scanner has false positives like any scanner"],
        tags=["web", "scanner", "proxy", "open source", "automated", "spider"],
        alternatives=["burpsuite"],
    ),
    ToolInfo(
        name="sqlmap",
        category="webapp",
        package="sqlmap",
        summary="Automates detection and exploitation of SQL injection.",
        description=(
            "sqlmap takes a URL/request and systematically tests parameters "
            "for SQL injection across many database engines and injection "
            "techniques, and — if confirmed — can automate extracting "
            "database content through the vulnerable parameter."
        ),
        when_to_use="Use once you suspect (or want to systematically check for) SQL injection in a parameter.",
        risk=RiskLevel.HIGH,
        requires_target_auth=True,
        command_template="sqlmap -u '<url-with-param>' --batch",
        args_explained={
            "-u": "Target URL containing the parameter(s) to test",
            "--data": "POST body to test instead of/alongside URL params",
            "--cookie": "Session cookie, if the page requires auth",
            "--batch": "Use sqlmap's default answer for prompts (non-interactive)",
            "--dbs": "After confirming injection, enumerate available databases",
            "--risk / --level": "Control how aggressive/extensive the test payloads are (higher = noisier, more thorough)",
        },
        example="sqlmap -u 'http://10.10.10.5/item.php?id=1' --batch --dbs",
        expected_output="Confirmation of the injection point/technique, then (with --dbs etc.) enumerated database names.",
        common_errors=["WAFs can block/mangle requests — consider --tamper scripts, with caution and authorization"],
        next_steps=["Extraction flags (--tables, --dump) only after confirming you're authorized to pull data"],
        tags=["sql injection", "sqli", "database", "web", "automated exploitation"],
        alternatives=[],
    ),
    ToolInfo(
        name="wpscan",
        category="webapp",
        package="wpscan",
        summary="WordPress-specific vulnerability scanner.",
        description=(
            "WPScan fingerprints a WordPress install's core version, themes, "
            "and plugins, checks them against a vulnerability database, and "
            "can enumerate usernames or run authenticated/brute-force checks."
        ),
        when_to_use="Use as soon as you identify a target is running WordPress.",
        risk=RiskLevel.MEDIUM,
        requires_target_auth=True,
        command_template="wpscan --url <url> --enumerate vp,vt,u",
        args_explained={
            "--url": "Target WordPress site",
            "--enumerate": "What to enumerate: vp (vulnerable plugins), vt (vulnerable themes), u (users)",
            "--api-token": "Free WPScan/WPVulnDB API token for full vulnerability data",
            "--passwords": "Wordlist for a login brute-force attempt (only with explicit authorization)",
        },
        example="wpscan --url https://example.com --enumerate vp,vt,u --api-token <token>",
        expected_output="WordPress version, theme/plugin inventory with known CVEs flagged, discovered usernames.",
        common_errors=["Rate-limited/blocked by the free API token tier — register for a token"],
        next_steps=["Cross-check any flagged plugin CVEs with searchsploit for available exploit code"],
        tags=["wordpress", "cms", "plugins", "themes", "web"],
        alternatives=[],
    ),
]
