# HACKiT

**A command-line assistant that helps you choose and use Kali Linux security tools.**

HACKiT is designed for cybersecurity students and authorized security testers. Describe a task in plain English, and it recommends a relevant tool from its built-in knowledge base, explains the suggested command, and guides you through running it.

HACKiT does not execute commands automatically. You review and approve each command before it runs.

## What HACKiT does

- **Plain-English guidance:** Describe your goal instead of needing to know the tool name first.
- **Tool recommendations:** Get suggestions across reconnaissance, scanning, enumeration, vulnerability assessment, web testing, exploitation, password auditing, wireless security, and digital forensics.
- **Command explanations:** Review command examples, flag explanations, expected output, common errors, and suggested next steps.
- **Local tool detection:** Check which supported tools are installed and see the relevant Kali package name when one is missing.
- **Approval before execution:** HACKiT displays the command and asks for approval before running it. Higher-risk tools require an additional confirmation.
- **Optional graphical interface:** Use the PyQt6 desktop interface instead of the terminal.
- **Offline-first operation:** The built-in recommendations and knowledge base work without an API key or network connection. Optional AI-assisted explanations require an Anthropic API key.

HACKiT provides guidance and command construction; it does not install or bundle the Kali tools themselves.

## Requirements

- Linux is recommended; HACKiT is designed primarily for Kali Linux.
- Python 3.10 or newer.
- The Kali security tools you want to use must be installed separately.
- The optional graphical interface requires PyQt6.

## Installation

Clone the repository:

```bash
git clone https://github.com/Mohamed-MT/HACKiT.git
cd HACKiT
```

Run the installer:

```bash
./install.sh
```

The installer uses `pipx` when available. Otherwise, it falls back to pip with `--break-system-packages`. If you choose the GUI option and its system dependency is missing, the installer may ask for `sudo` to install it.

After installation, start HACKiT with:

```bash
hackit
```

### Optional GUI

Choose the GUI option when running `./install.sh`, or install the GUI extra manually in an isolated environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[gui]'
hackit gui
```

### Manual CLI installation

For a local development installation:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

## Using HACKiT

Start the interactive assistant:

```bash
hackit
```

Then describe what you want to do. For example:

```text
hackit> I want to find open ports on an authorized test machine
```

HACKiT will recommend a tool, explain why it fits, and show a command template. You can ask follow-up questions, inspect alternatives, or proceed through the command-building and approval steps.

Useful commands inside the session:

| Command | Purpose |
|---|---|
| `tools [category]` | List available tools, optionally by category |
| `show <tool>` | Display details for a specific tool |
| `categories` | List knowledge-base categories |
| `status` | Check which supported tools are installed |
| `run` | Build and request approval to run the suggested command |
| `alternatives` | Show other tools relevant to the last objective |
| `gui` | Open the graphical interface |
| `config` | Review or change HACKiT preferences |
| `help` | Show available commands |
| `exit` | Close the session |

You can also use one-shot commands:

```bash
hackit ask "enumerate SMB shares on an authorized Windows host"
hackit tools wireless
hackit status
hackit gui
```

Use `hackit --help` to see the available command-line options.

## Safety and responsible use

HACKiT is intended for learning and authorized security work only. **Only test systems you own or have explicit permission to assess.**

- HACKiT asks you to acknowledge authorization and scope before running commands that interact with network targets.
- Every command is shown for review and requires your approval before execution.
- Higher-risk actions, such as exploitation, brute forcing, and wireless injection, require an additional confirmation.
- HACKiT does not silently execute recommended commands.

These safeguards do not make an activity legal or authorized by themselves. You are responsible for obtaining permission and staying within the agreed scope.

## Optional AI explanations and privacy

HACKiT's built-in tool matching and explanations work locally. If you enable AI-assisted explanations and configure an Anthropic API key, HACKiT sends your objective text and the selected tool's knowledge-base information to Anthropic to generate a more conversational explanation.

Do not include passwords, API keys, private customer information, or other sensitive engagement details in an objective when using the optional AI feature. If your objective contains an IP address, hostname, or other identifying information, that text may be sent as part of the request. HACKiT does not send command output or scan results to Anthropic through this explanation feature.

You can leave the AI feature disabled and continue using HACKiT's local functionality. Configure the API key through `hackit config` or the `ANTHROPIC_API_KEY` environment variable. A key saved through the configuration command is stored locally in your HACKiT configuration directory; protect access to your user account and device.

## Development

Create and activate a virtual environment, then install the development dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
```

Run the tests and security checks:

```bash
python -m pytest -q
bandit -r hackit/
pip-audit
```

GitHub Actions runs these checks on pushes and pull requests.

## License

HACKiT is released under the MIT License. See [LICENSE](LICENSE).
