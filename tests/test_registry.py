from hackit.knowledge import CATEGORY_LABELS
from hackit.knowledge.registry import ALL_TOOLS, all_categories, get_tool, list_category, search


def test_all_tools_have_required_fields():
    assert len(ALL_TOOLS) > 0
    for tool in ALL_TOOLS:
        assert tool.name
        assert tool.category in CATEGORY_LABELS
        assert tool.package
        assert tool.summary
        assert tool.description
        assert tool.when_to_use
        assert tool.command_template
        # package names must be bare apt package tokens, not prose
        assert " " not in tool.package or tool.package.count(" ") == 0, (
            f"{tool.name}'s package field looks like prose, not an apt package: {tool.package!r}"
        )


def test_get_tool_case_insensitive():
    assert get_tool("NMAP") is not None
    assert get_tool("nmap") is get_tool("NMAP")
    assert get_tool("not-a-real-tool-xyz") is None


def test_list_category_matches_all_categories():
    for cat in all_categories():
        tools = list_category(cat)
        assert len(tools) > 0, f"category {cat} has no tools"
        assert all(t.category == cat for t in tools)


def test_search_finds_nmap_for_port_scan_query():
    results = search("scan for open ports on a network", limit=5)
    names = [t.name for t, _ in results]
    assert "nmap" in names


def test_search_stopword_does_not_falsely_match_forensics():
    # Regression test: "for" must not match inside "forensic" via naive
    # substring search.
    results = search("looking for a tool to scan ports", limit=10)
    names = [t.name for t, _ in results]
    assert "nmap" in names
    # autopsy/volatility3 should not outrank nmap just because "for" is
    # a substring of "forensic"
    top_name = results[0][0].name
    assert top_name in ("nmap", "masscan", "rustscan")


def test_search_empty_query_returns_nothing():
    assert search("", limit=5) == []
    assert search("a an the", limit=5) == []


def test_command_templates_are_single_commands_without_shell_comments():
    # The executor intentionally does not invoke a shell. Keep templates
    # limited to one command and put follow-up instructions in next_steps.
    for tool in ALL_TOOLS:
        assert "&&" not in tool.command_template, tool.name
        assert "||" not in tool.command_template, tool.name
        assert "|" not in tool.command_template, tool.name
        assert ";" not in tool.command_template, tool.name
        assert " #" not in tool.command_template, tool.name
