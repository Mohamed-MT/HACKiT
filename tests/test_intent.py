from hackit.intent import classify


def test_port_scan_objective_maps_to_nmap():
    result = classify("I want to scan a network for open ports")
    assert result.category == "scanning"
    assert result.candidates
    assert result.candidates[0].name == "nmap"
    assert result.confidence == "high"


def test_password_cracking_objective_maps_to_password_category():
    result = classify("help me crack some password hashes I dumped")
    assert result.category == "password"
    assert result.candidates[0].name in ("john", "hashcat")


def test_wordpress_vuln_objective_maps_to_wpscan():
    result = classify("check a wordpress site for vulnerabilities")
    assert result.candidates
    names = [t.name for t in result.candidates]
    assert "wpscan" in names


def test_wireless_objective_maps_to_wireless_category():
    result = classify("audit wifi network wpa2 handshake")
    assert result.category == "wireless"
    assert result.candidates[0].name in ("aircrack-ng", "wifite")


def test_sql_injection_objective_maps_to_sqlmap():
    result = classify("test this login form for sql injection")
    names = [t.name for t in result.candidates]
    assert "sqlmap" in names


def test_gibberish_query_returns_low_confidence_or_empty():
    result = classify("asdkj qpwoei zxcvb")
    assert result.confidence in ("low", "medium")


def test_classify_never_raises_on_empty_string():
    result = classify("")
    assert result.candidates == []
    assert result.confidence == "low"
