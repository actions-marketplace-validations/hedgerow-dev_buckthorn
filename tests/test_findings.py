from buckthorn.findings import Finding, Severity, verdict


def _finding(rule_id: str, severity: Severity) -> Finding:
    return Finding(rule_id, "msg", severity, "pkg/x.pth")


def test_no_findings_is_clean():
    assert verdict([]) == "clean"


def test_info_only_is_clean():
    assert verdict([_finding("BKT-PTH-001", Severity.INFO)]) == "clean"


def test_detection_above_info_is_flagged():
    assert verdict([_finding("BKT-PTH-001", Severity.HIGH)]) == "flagged"


def test_coverage_gap_is_not_verified_never_clean():
    assert verdict([_finding("BKT-SKIP-001", Severity.INFO)]) == "not_verified"


def test_flagged_wins_over_not_verified():
    findings = [_finding("BKT-SKIP-001", Severity.INFO), _finding("BKT-PTH-001", Severity.HIGH)]
    assert verdict(findings) == "flagged"
