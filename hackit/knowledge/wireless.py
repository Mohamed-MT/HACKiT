from hackit.knowledge import RiskLevel, ToolInfo

TOOLS: list[ToolInfo] = [
    ToolInfo(
        name="aircrack-ng",
        category="wireless",
        package="aircrack-ng",
        summary="The core Wi-Fi auditing suite — capture, deauth, and crack WPA/WPA2 handshakes or WEP keys.",
        description=(
            "aircrack-ng is a suite (airmon-ng, airodump-ng, aireplay-ng, "
            "aircrack-ng) covering the full workflow: put a wireless adapter "
            "into monitor mode, capture traffic/handshakes, optionally send "
            "deauth frames to force a handshake, then crack the captured key "
            "material against a wordlist."
        ),
        when_to_use=(
            "Use for authorized Wi-Fi security assessments of networks you "
            "own or have explicit written permission to test — this requires "
            "a wireless adapter that supports monitor mode and packet "
            "injection."
        ),
        risk=RiskLevel.HIGH,
        requires_target_auth=True,
        command_template="airmon-ng start <iface>",
        args_explained={
            "airmon-ng start <iface>": "Put the adapter into monitor mode (creates e.g. wlan0mon)",
            "airodump-ng <mon-iface>": "Discover nearby networks and connected clients",
            "airodump-ng -c <ch> --bssid <bssid> -w <cap> <mon-iface>": "Capture traffic for one specific network to a file",
            "aireplay-ng --deauth <n> -a <bssid> <mon-iface>": "Send deauth frames to force a client to reconnect/re-handshake",
            "aircrack-ng -w <wordlist> <capfile>.cap": "Attempt to crack the captured handshake",
        },
        example="airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon",
        expected_output="A .cap file containing packets, hopefully including a 4-way WPA handshake, for cracking.",
        common_errors=[
            "Adapter doesn't support monitor mode/injection — check with 'airmon-ng' driver compatibility list",
            "No handshake captured — wait for a natural client (re)connection, or use aireplay-ng deauth (own network only)",
        ],
        next_steps=["After monitor mode starts, run airodump-ng <mon-iface> as a separate command to discover nearby networks", "Verify the captured handshake is complete before a long crack attempt: aircrack-ng <cap> (it will say if valid)"],
        tags=["wifi", "wireless", "wpa", "wpa2", "handshake", "deauth", "monitor mode", "wep"],
        alternatives=["wifite"],
    ),
    ToolInfo(
        name="wifite",
        category="wireless",
        package="wifite",
        summary="Automates the aircrack-ng/reaver workflow against all nearby networks.",
        description=(
            "Wifite orchestrates monitor mode, scanning, handshake/PMKID "
            "capture, and cracking automatically across every in-range "
            "network, picking reasonable attack strategies per target so you "
            "don't have to drive aircrack-ng by hand for routine audits."
        ),
        when_to_use="Use for a faster, more automated sweep once you already have aircrack-ng's manual workflow down, on authorized targets only.",
        risk=RiskLevel.HIGH,
        requires_target_auth=True,
        command_template="wifite --wpa -i <mon-iface>",
        args_explained={
            "-i": "Wireless interface to use",
            "--wpa": "Restrict attacks to WPA/WPA2 targets",
            "--wps": "Restrict attacks to WPS-vulnerable targets",
            "-c <channel>": "Restrict scanning to one channel",
        },
        example="wifite --wpa -i wlan0",
        expected_output="An interactive target list; after selection, it automates capture and attempts to crack.",
        common_errors=["Same monitor-mode/injection hardware requirements as aircrack-ng"],
        next_steps=["Cracked keys and captured handshakes are saved under ./hs/ for later review"],
        tags=["wifi", "wireless", "automated", "wpa", "wps"],
        alternatives=["aircrack-ng"],
    ),
    ToolInfo(
        name="reaver",
        category="wireless",
        package="reaver",
        summary="Attacks WPS PINs to recover the WPA/WPA2 passphrase.",
        description=(
            "Reaver brute-forces a router's WPS PIN (which has a much "
            "smaller keyspace than WPA2 itself due to a design flaw) to "
            "recover the underlying WPA/WPA2 passphrase on routers that still "
            "have WPS enabled."
        ),
        when_to_use="Use when a target access point has WPS enabled (visible in a wash scan) and WPS is in scope.",
        risk=RiskLevel.HIGH,
        requires_target_auth=True,
        command_template="reaver -i <mon-iface> -b <bssid> -vv",
        args_explained={
            "-i": "Monitor-mode interface",
            "-b": "Target BSSID (find candidates first with 'wash -i <mon-iface>')",
            "-vv": "Verbose output to watch PIN attempts live",
        },
        example="reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -vv",
        expected_output="Progress through the WPS PIN space; on success, the recovered WPA PSK.",
        common_errors=["Can take many hours; some APs implement WPS lockout after repeated failures"],
        next_steps=["Use the recovered PSK to connect, or feed it into other authorized assessment steps"],
        tags=["wifi", "wps", "pin", "wireless"],
        alternatives=["bully"],
    ),
]
