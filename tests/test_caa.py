"""Tests for CAA parsing and grading."""

from dns_doctor.checks.caa import CaaRecord, grade_caa, issuers, parse_caa, run
from dns_doctor.grading import Grade


def test_parse_presentation_format():
    recs = parse_caa(['0 issue "letsencrypt.org"', '128 iodef "mailto:sec@e.com"'])
    assert recs[0] == CaaRecord(flags=0, tag="issue", value="letsencrypt.org")
    assert recs[1].tag == "iodef"
    assert recs[1].critical is True


def test_parse_skips_malformed_records():
    recs = parse_caa(['0 issue "letsencrypt.org"', "not a caa record", 'x issue "a"'])
    assert len(recs) == 1


def test_parse_tag_is_lowercased():
    assert parse_caa(['0 ISSUEWILD "digicert.com"'])[0].tag == "issuewild"


def test_issuers_ignores_deny_all():
    recs = parse_caa(['0 issue ";"', '0 issue "sectigo.com"'])
    assert issuers(recs) == ["sectigo.com"]


def test_issuers_strips_ca_parameters():
    recs = parse_caa(['0 issue "letsencrypt.org; validationmethods=dns-01"'])
    assert issuers(recs) == ["letsencrypt.org"]


def test_no_records_is_C():
    grade, summary, fixes = grade_caa([])
    assert grade == Grade.C
    assert fixes


def test_issue_plus_iodef_is_A():
    recs = parse_caa(['0 issue "letsencrypt.org"', '0 iodef "mailto:sec@e.com"'])
    grade, summary, fixes = grade_caa(recs)
    assert grade == Grade.A
    assert "letsencrypt.org" in summary


def test_issue_without_iodef_is_B():
    grade, summary, fixes = grade_caa(parse_caa(['0 issue "letsencrypt.org"']))
    assert grade == Grade.B
    assert any("iodef" in f for f in fixes)


def test_deny_all_issuance_is_D():
    grade, summary, fixes = grade_caa(parse_caa(['0 issue ";"', '0 issuewild ";"']))
    assert grade == Grade.D


def test_critical_flag_on_unknown_tag_is_F():
    grade, summary, fixes = grade_caa(parse_caa(['128 isue "letsencrypt.org"']))
    assert grade == Grade.F
    assert "isue" in summary


def test_unknown_tag_without_critical_flag_only_warns():
    recs = parse_caa(['0 issue "letsencrypt.org"', '0 iodef "mailto:s@e.com"', '0 isue "x"'])
    grade, summary, fixes = grade_caa(recs)
    assert grade == Grade.A
    assert any("isue" in f for f in fixes)


def test_wildcard_only_authorisation_still_counts():
    grade, summary, fixes = grade_caa(parse_caa(['0 issuewild "digicert.com"']))
    assert grade == Grade.B


class _StubResolver:
    def __init__(self, records):
        self._records = records

    def resolve(self, name, rdtype):
        if not self._records:
            raise LookupError("no answer")
        return self._records


def test_run_uses_injected_resolver():
    result = run("example.com", resolver=_StubResolver(
        ['0 issue "letsencrypt.org"', '0 iodef "mailto:sec@example.com"']
    ))
    assert result.name == "CAA"
    assert result.grade == Grade.A
    assert result.details["issuers"] == ["letsencrypt.org"]


def test_run_treats_lookup_failure_as_no_records():
    result = run("example.com", resolver=_StubResolver([]))
    assert result.grade == Grade.C
    assert result.details["records"] == []
