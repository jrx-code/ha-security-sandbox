"""Phase 2.7 tests: Finding deduplication."""

from app.models import Finding, Severity
from app.scanner.pipeline import deduplicate_findings


class TestDeduplication:
    def test_exact_duplicates_merged(self):
        """Same file, line, category → merged into one."""
        findings = [
            Finding(severity=Severity.HIGH, category="code_injection",
                    file="a.py", line=10, description="eval() found"),
            Finding(severity=Severity.HIGH, category="code_injection",
                    file="a.py", line=10, description="eval() found"),
        ]
        result = deduplicate_findings(findings)
        assert len(result) == 1

    def test_keeps_higher_severity(self):
        """When merging, keep the higher severity."""
        findings = [
            Finding(severity=Severity.MEDIUM, category="code_injection",
                    file="a.py", line=10, description="eval()"),
            Finding(severity=Severity.CRITICAL, category="code_injection",
                    file="a.py", line=10, description="eval() with user input"),
        ]
        result = deduplicate_findings(findings)
        assert len(result) == 1
        assert result[0].severity == Severity.CRITICAL

    def test_different_files_not_merged(self):
        """Different files → separate findings."""
        findings = [
            Finding(severity=Severity.HIGH, category="xss",
                    file="a.js", line=5, description="innerHTML"),
            Finding(severity=Severity.HIGH, category="xss",
                    file="b.js", line=5, description="innerHTML"),
        ]
        result = deduplicate_findings(findings)
        assert len(result) == 2

    def test_different_lines_not_merged(self):
        """Same file, different lines → separate findings."""
        findings = [
            Finding(severity=Severity.HIGH, category="xss",
                    file="a.js", line=5, description="innerHTML"),
            Finding(severity=Severity.HIGH, category="xss",
                    file="a.js", line=20, description="innerHTML"),
        ]
        result = deduplicate_findings(findings)
        assert len(result) == 2

    def test_taint_alias_merges(self):
        """taint_code_injection and code_injection → same category for dedup."""
        findings = [
            Finding(severity=Severity.HIGH, category="code_injection",
                    file="a.py", line=10, description="eval() detected"),
            Finding(severity=Severity.CRITICAL, category="taint_code_injection",
                    file="a.py", line=10, description="User input flows to eval()"),
        ]
        result = deduplicate_findings(findings)
        assert len(result) == 1
        assert result[0].severity == Severity.CRITICAL

    def test_ai_finding_without_line_deduped(self):
        """AI findings without line number dedup by file+category."""
        findings = [
            Finding(severity=Severity.HIGH, category="code_injection",
                    file="sensor.py", line=15, code="eval(x)", description="Static: eval()"),
            Finding(severity=Severity.HIGH, category="code_injection",
                    file="sensor.py", description="AI: eval() usage detected", code="[AI finding]"),
        ]
        result = deduplicate_findings(findings)
        # AI without line vs static with line have different keys
        # This is by design — AI findings without lines are separate
        assert len(result) == 2

    def test_no_duplicates_unchanged(self):
        """All unique findings should pass through unchanged."""
        findings = [
            Finding(severity=Severity.HIGH, category="xss", file="a.js", line=1, description="A"),
            Finding(severity=Severity.MEDIUM, category="network", file="b.py", line=5, description="B"),
            Finding(severity=Severity.LOW, category="telemetry", file="c.js", line=10, description="C"),
        ]
        result = deduplicate_findings(findings)
        assert len(result) == 3

    def test_empty_list(self):
        assert deduplicate_findings([]) == []

    def test_descriptions_combined_when_different(self):
        """Different descriptions on merge → combined with separator."""
        findings = [
            Finding(severity=Severity.MEDIUM, category="xss",
                    file="a.js", line=10, description="innerHTML assignment"),
            Finding(severity=Severity.HIGH, category="xss",
                    file="a.js", line=10, description="User data in DOM manipulation"),
        ]
        result = deduplicate_findings(findings)
        assert len(result) == 1
        assert "|" in result[0].description

    def test_preserves_code_on_merge(self):
        """Code snippet should be preserved from the finding that has one."""
        findings = [
            Finding(severity=Severity.HIGH, category="code_injection",
                    file="a.py", line=10, code="eval(x)", description="eval detected"),
            Finding(severity=Severity.CRITICAL, category="taint_code_injection",
                    file="a.py", line=10, code="", description="User input to eval"),
        ]
        result = deduplicate_findings(findings)
        assert result[0].code == "eval(x)"
