from hackit.knowledge import RiskLevel, ToolInfo

TOOLS: list[ToolInfo] = [
    ToolInfo(
        name="autopsy",
        category="forensics",
        package="autopsy",
        summary="Graphical digital forensics platform built on The Sleuth Kit.",
        description=(
            "Autopsy provides a case-management GUI over disk/file-system "
            "forensics: timeline analysis, keyword search, file recovery, "
            "hash filtering, and artifact extraction (web history, EXIF, "
            "registry, etc.) from a disk image."
        ),
        when_to_use="Use as the primary tool for a structured disk-image investigation with a reportable case file.",
        risk=RiskLevel.PASSIVE,
        requires_target_auth=False,
        command_template="autopsy",
        args_explained={
            "New Case": "Start a case, then add a disk image or logical files as a data source",
            "Ingest Modules": "Choose which automated analyzers to run (hash lookup, keyword search, EXIF, etc.)",
        },
        example="autopsy",
        expected_output="A case workspace: file tree, extracted artifacts, and a timeline you can search and annotate.",
        common_errors=["Large images can take a long time to ingest fully — plan ingest module selection accordingly"],
        next_steps=["Follow the local URL shown by Autopsy after it starts", "Export a case report once analysis and annotation are complete"],
        tags=["disk forensics", "case management", "timeline", "sleuth kit", "image analysis"],
        alternatives=["sleuthkit (CLI)"],
    ),
    ToolInfo(
        name="volatility3",
        category="forensics",
        package="volatility3",
        summary="Memory (RAM) forensics framework — extracts processes, network state, and more from a memory dump.",
        description=(
            "Volatility parses a raw memory dump according to the OS's "
            "internal memory structures to reconstruct running processes, "
            "open network connections, loaded DLLs/kernel modules, registry "
            "hives in memory, and more — useful for incident response and "
            "malware analysis."
        ),
        when_to_use="Use when you have a memory image (e.g. from a live-response capture) and need to understand what was running.",
        risk=RiskLevel.PASSIVE,
        requires_target_auth=False,
        command_template="vol -f <memdump> <plugin>",
        args_explained={
            "-f": "Path to the memory dump file",
            "windows.pslist": "List running processes (Windows dumps)",
            "windows.netscan": "List network connections/sockets found in memory",
            "windows.malfind": "Flag memory regions with injection/malware-like characteristics",
            "linux.pslist / linux.bash": "Linux-specific equivalents (process list, bash history reconstruction)",
        },
        example="vol -f memory.raw windows.pslist",
        expected_output="A table of the requested artifact type (processes, connections, etc.) with relevant fields.",
        common_errors=["Wrong/no symbol profile for the OS build — Volatility 3 mostly auto-detects, but older dumps may need a manual symbol table"],
        next_steps=["Pivot from suspicious processes (malfind, pslist) into dumping and analyzing the binary itself"],
        tags=["memory forensics", "ram", "incident response", "malware analysis"],
        alternatives=[],
    ),
    ToolInfo(
        name="binwalk",
        category="forensics",
        package="binwalk",
        summary="Identifies and extracts embedded files/filesystems inside a binary blob (e.g. firmware).",
        description=(
            "Binwalk scans a file for signatures of known file types and "
            "filesystems embedded within it — common for firmware images "
            "that bundle a bootloader, kernel, and filesystem together — and "
            "can automatically carve them out."
        ),
        when_to_use="Use when analyzing firmware dumps or any file suspected of containing embedded/hidden data.",
        risk=RiskLevel.PASSIVE,
        requires_target_auth=False,
        command_template="binwalk -e <file>",
        args_explained={
            "(no flag)": "Just scan and report signatures found, without extracting",
            "-e": "Extract identified files/filesystems automatically",
            "-M": "Recursively scan extracted files too",
        },
        example="binwalk -e firmware.bin",
        expected_output="A list of offsets with identified file/filesystem types, extracted into a _<file>.extracted/ dir with -e.",
        common_errors=["False-positive signature matches are common — verify extracted content makes sense"],
        next_steps=["Explore the extracted filesystem for credentials, keys, or configuration of interest"],
        tags=["firmware", "extraction", "file carving", "embedded", "reverse engineering"],
        alternatives=["foremost"],
    ),
    ToolInfo(
        name="exiftool",
        category="forensics",
        package="libimage-exiftool-perl",
        summary="Reads and edits metadata embedded in files (EXIF, XMP, document properties).",
        description=(
            "exiftool extracts (and can modify) the metadata that image, "
            "document, and media files carry — camera/GPS data in photos, "
            "author/editing history in documents, and similar — useful for "
            "OSINT and forensic review alike."
        ),
        when_to_use="Use on any image/document of interest to check for embedded metadata (location, author, software, timestamps).",
        risk=RiskLevel.PASSIVE,
        requires_target_auth=False,
        command_template="exiftool <file>",
        args_explained={
            "<file>": "File to inspect",
            "-gps:all": "Show only GPS-related metadata",
            "-all=": "Strip all metadata from the file (used defensively, not offensively)",
        },
        example="exiftool photo.jpg",
        expected_output="A list of metadata fields and values (camera model, GPS coordinates, timestamps, software used, etc.).",
        common_errors=["Many platforms strip EXIF data on upload — metadata may simply be absent"],
        next_steps=["Cross-reference GPS/timestamp data with other OSINT findings"],
        tags=["metadata", "exif", "gps", "osint", "document properties"],
        alternatives=[],
    ),
]
