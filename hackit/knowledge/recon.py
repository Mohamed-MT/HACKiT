from hackit.knowledge import RiskLevel, ToolInfo

TOOLS: list[ToolInfo] = [
    ToolInfo(
        name="theharvester",
        category="recon",
        package="theharvester",
        summary="Gathers emails, subdomains, hosts, and employee names from public sources.",
        description=(
            "theHarvester queries public sources (search engines, certificate "
            "transparency logs, DNS, PGP key servers, etc.) to build an OSINT "
            "picture of an organization's external footprint — email addresses, "
            "subdomains, hostnames, and sometimes open ports — without ever "
            "touching the target's own infrastructure."
        ),
        when_to_use=(
            "Use this first, before any active scanning, when you need to map "
            "an organization's attack surface or build a target/employee list "
            "for later phases, and want to stay fully passive."
        ),
        risk=RiskLevel.PASSIVE,
        requires_target_auth=False,
        command_template="theHarvester -d <domain> -b <source> -l <limit>",
        args_explained={
            "-d": "Target domain to search for, e.g. example.com",
            "-b": "Data source to query: google, bing, duckduckgo, crtsh, hackertarget, all, etc.",
            "-l": "Limit on the number of results to retrieve per source",
            "-f": "Optional: save results to an HTML/XML/JSON file",
        },
        example="theHarvester -d example.com -b all -l 200",
        expected_output=(
            "A list of discovered email addresses, subdomains/hosts, and "
            "sometimes IPs, grouped by the source they came from."
        ),
        common_errors=[
            "API rate limits or missing API keys for some sources (edit api-keys.yaml)",
            "Some sources are deprecated/unavailable and will just return 0 results",
        ],
        next_steps=[
            "Feed discovered subdomains into amass or dnsrecon for DNS enumeration",
            "Cross-check emails for use in later authorized social-engineering or password-spray planning",
        ],
        tags=["osint", "email", "subdomain", "recon", "footprint", "passive", "domain", "organization"],
        alternatives=["amass", "recon-ng", "maltego"],
    ),
    ToolInfo(
        name="amass",
        category="recon",
        package="amass",
        summary="In-depth attack-surface mapping via DNS enumeration and OSINT.",
        description=(
            "OWASP Amass performs extensive subdomain enumeration by combining "
            "passive sources (certificate transparency, scraping, APIs) with "
            "active DNS techniques (brute force, permutations, zone transfer "
            "attempts) to build a graph of an organization's external assets."
        ),
        when_to_use=(
            "Use when theHarvester's subdomain list isn't thorough enough and "
            "you need a more complete picture of an org's DNS footprint. The "
            "'enum' passive mode keeps things non-intrusive; active modes do "
            "send DNS queries to the target's name servers."
        ),
        risk=RiskLevel.LOW,
        requires_target_auth=True,
        command_template="amass enum -passive -d <domain> -o <outfile>",
        args_explained={
            "enum": "Run the subdomain enumeration subcommand",
            "-passive": "Stay passive — only query third-party sources, no direct DNS to the target",
            "-active": "Enable active techniques (DNS brute force, zone-transfer attempts)",
            "-d": "Domain to enumerate",
            "-brute": "Enable brute-force subdomain guessing (active, noisier)",
            "-o": "Write discovered names to a file",
        },
        example="amass enum -passive -d example.com -o amass_results.txt",
        expected_output="A growing list of resolved/discovered subdomains, printed live as found.",
        common_errors=[
            "Very slow first run while it populates its local graph database",
            "Active brute-force mode can generate large volumes of DNS traffic — get authorization first",
        ],
        next_steps=[
            "Run nmap against the discovered subdomains/IPs to find live hosts and open ports",
            "Visually inspect the asset graph with amass viz",
        ],
        tags=["dns", "subdomain", "osint", "recon", "attack surface", "enumeration"],
        alternatives=["theharvester", "dnsrecon", "subfinder"],
    ),
    ToolInfo(
        name="recon-ng",
        category="recon",
        package="recon-ng",
        summary="Modular OSINT reconnaissance framework with a Metasploit-like workflow.",
        description=(
            "recon-ng is a full reconnaissance framework: it organizes OSINT "
            "work into workspaces and modules (domains, hosts, contacts, "
            "credentials, etc.) so results from one module automatically feed "
            "the next, similar to how Metasploit organizes exploit modules."
        ),
        when_to_use=(
            "Use when you want a structured, repeatable OSINT workflow across "
            "many data sources rather than running single-purpose tools "
            "one-by-one, especially for larger or recurring engagements."
        ),
        risk=RiskLevel.PASSIVE,
        requires_target_auth=False,
        command_template="recon-ng -w <workspace>",
        args_explained={
            "-w": "Create or open a named workspace to store results in",
            "marketplace install <module>": "Install a recon module from the marketplace (inside the shell)",
            "modules load <module>": "Load a module into the current context",
            "options set SOURCE <domain>": "Set the module's input, e.g. target domain",
            "run": "Execute the loaded module",
        },
        example="recon-ng -w acme_engagement",
        expected_output="An interactive shell; module output populates workspace tables (hosts, contacts, etc.).",
        common_errors=[
            "Many modules need free API keys configured with 'keys add <name> <key>'",
        ],
        next_steps=[
            "Use 'show hosts' / 'show contacts' to review aggregated findings",
            "Export a report with the reporting modules",
        ],
        tags=["osint", "framework", "recon", "modules", "workspace"],
        alternatives=["theharvester", "maltego"],
    ),
    ToolInfo(
        name="whois",
        category="recon",
        package="whois",
        summary="Looks up domain/IP registration records.",
        description=(
            "whois queries registrar/registry databases for ownership, "
            "registrar, name-server, and creation/expiry data about a domain "
            "or an IP's allocating organization."
        ),
        when_to_use="Use for a quick first look at who owns a domain or IP block before deeper recon.",
        risk=RiskLevel.PASSIVE,
        requires_target_auth=False,
        command_template="whois <domain-or-ip>",
        args_explained={"<domain-or-ip>": "The domain name or IP address to look up"},
        example="whois example.com",
        expected_output="Registrar, registrant org (often redacted by privacy services), name servers, key dates.",
        common_errors=["Privacy/proxy services hide most registrant details for domains"],
        next_steps=["Resolve name servers with dig/nslookup", "Move into amass/theHarvester for subdomains"],
        tags=["domain", "ip", "registration", "recon", "passive"],
        alternatives=[],
    ),
]
