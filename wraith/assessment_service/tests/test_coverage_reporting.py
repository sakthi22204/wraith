"""Coverage reporting: an empty findings list must not read as a clean bill of health.

Before this, an investigation with zero findings and an investigation with zero
*evidence* both rendered as risk_score 2.0 with nothing else to tell them apart.
These tests pin the distinction.
"""
from app.services import AssessmentEngine


def _graph(nodes):
    return {"nodes": nodes, "links": []}


def _endpoint(url):
    return {"id": url, "labels": ["Endpoint"], "properties": {"url": url}}


def _finding(status, vuln_type="SQL Injection", severity="high"):
    return {
        "id": f"f-{vuln_type}-{status}",
        "labels": ["Finding"],
        "properties": {
            "status": status,
            "vuln_type": vuln_type,
            "severity": severity,
        },
    }


def _validation(outcome):
    return {
        "id": f"v-{outcome}",
        "labels": ["ValidationAttempt"],
        "properties": {"outcome": outcome},
    }


def test_coverage_counts_endpoints_bundles_and_api_routes():
    graph = _graph([
        _endpoint("http://t:3000/"),
        _endpoint("http://t:3000/main.js"),
        _endpoint("http://t:3000/vendor.js"),
        _endpoint("http://t:3000/rest/products/search?q="),
        _endpoint("http://t:3000/api/Users"),
    ])

    cov = AssessmentEngine.generate_report("inv", graph).coverage

    assert cov.endpoints_discovered == 5
    assert cov.javascript_bundles == 2
    assert cov.api_endpoints == 2


def test_bundle_url_is_not_mistaken_for_an_api_route():
    """A query string on a static asset must not count toward API coverage."""
    graph = _graph([_endpoint("http://t:3000/main.js?v=1")])

    cov = AssessmentEngine.generate_report("inv", graph).coverage

    assert cov.javascript_bundles == 1
    assert cov.api_endpoints == 0


def test_empty_graph_reports_no_coverage_not_clean_coverage():
    cov = AssessmentEngine.generate_report("inv", _graph([])).coverage

    assert cov.endpoints_discovered == 0
    assert cov.validations_run == 0
    assert cov.findings_confirmed == 0
    assert cov.gaps
    assert any("No endpoints" in g for g in cov.gaps)


def test_no_api_routes_found_is_reported_as_a_gap():
    """The Juice Shop failure mode: a shell and its assets, no backend."""
    graph = _graph([
        _endpoint("http://t:3000/"),
        _endpoint("http://t:3000/main.js"),
    ])

    cov = AssessmentEngine.generate_report("inv", graph).coverage

    assert cov.api_endpoints == 0
    assert any("No API routes" in g for g in cov.gaps)


def test_unparsed_bundle_is_reported_as_a_gap():
    graph = _graph([_endpoint("http://t:3000/")])

    cov = AssessmentEngine.generate_report("inv", graph).coverage

    assert cov.javascript_bundles == 0
    assert any("JavaScript bundle" in g for g in cov.gaps)


def test_confirmed_findings_are_counted_and_lift_the_score():
    graph = _graph([
        _endpoint("http://t:3000/rest/products/search?q="),
        # The graph stores AI_VALIDATED; "CONFIRMED" is the runner's word and
        # never reaches the graph, so a fixture using it tested a status no
        # stored finding has.
        _finding("AI_VALIDATED"),
        _validation("CONFIRMED"),
    ])

    report = AssessmentEngine.generate_report("inv", graph)

    assert report.coverage.findings_confirmed == 1
    assert report.coverage.validations_run == 1
    assert report.coverage.candidate_families == ["SQL Injection"]
    assert report.risk_score > 2.0


def test_a_proven_finding_counts_as_confirmed_in_graph_vocabulary():
    """The runner reports CONFIRMED; the graph stores AI_VALIDATED. Counting
    only the runner's word would report zero confirmed findings for an
    investigation that has one -- which is the bug this whole change exists
    to prevent."""
    graph = _graph([
        _endpoint("http://t:3000/main.js"),
        _endpoint("http://t:3000/rest/products/search?q="),
        _finding("AI_VALIDATED"),
    ])

    report = AssessmentEngine.generate_report("inv", graph)

    assert report.coverage.findings_confirmed == 1
    assert not report.coverage.gaps
    assert report.risk_score > 2.0


def test_human_confirmed_and_corroborated_also_count():
    for status in ("HUMAN_CONFIRMED", "CORROBORATED", "CONFIRMED"):
        graph = _graph([
            _endpoint("http://t:3000/rest/x"),
            _finding(status),
        ])
        assert AssessmentEngine.generate_report("inv", graph).coverage.findings_confirmed == 1


def test_a_false_positive_is_not_a_confirmed_finding():
    graph = _graph([
        _endpoint("http://t:3000/rest/x"),
        _finding("FALSE_POSITIVE"),
    ])

    report = AssessmentEngine.generate_report("inv", graph)

    assert report.coverage.findings_confirmed == 0


def test_inconclusive_validations_are_counted_but_never_confirmed():
    """A validation that could not conclude is not a result.

    INCONCLUSIVE used to be weighted as "high", which made a probe that proved
    nothing raise the risk of the target it proved nothing about. It is
    inventoried (so the gap stays visible) and carries no weight.

    It is also not a *finding* status: an inconclusive validation leaves the
    finding UNCONFIRMED. The old fixture stored INCONCLUSIVE as a finding
    status the graph never writes, which is how the counter came to always
    read zero."""
    graph = _graph([
        _endpoint("http://t:3000/rest/products/search?q="),
        _finding("UNCONFIRMED"),
        _validation("INCONCLUSIVE"),
    ])

    report = AssessmentEngine.generate_report("inv", graph)

    assert report.coverage.validations_run == 1
    assert report.coverage.validations_inconclusive == 1
    assert report.coverage.findings_confirmed == 0
    # Inventoried as a high-severity finding; scored as no finding at all.
    assert report.findings_summary["High"] == 1
    assert report.risk_score == 2.0


def test_an_unconfirmed_finding_is_not_counted_as_a_validation():
    """The bug this fixed: validations_run was len(findings). A finding with no
    validation attempt is a hypothesis, not a test."""
    graph = _graph([_finding("UNCONFIRMED", vuln_type="CVE-2021-1234")])

    cov = AssessmentEngine.generate_report("inv", graph).coverage

    assert cov.findings_recorded == 1
    assert cov.validations_run == 0
    assert cov.findings_confirmed == 0
    assert cov.candidate_families == ["CVE-2021-1234"]


def test_coverage_reports_no_invented_candidate_count():
    """Candidate hypotheses are not persisted to the graph. A counter for them
    would be a number this service made up, so the field does not exist and
    what is reported instead is the findings that were actually written."""
    from app.schemas import AssessmentCoverage

    assert "candidates_generated" not in AssessmentCoverage.model_fields
    assert "findings_recorded" in AssessmentCoverage.model_fields

    graph = _graph([
        _endpoint("http://t:3000/main.js"),
        _endpoint("http://t:3000/rest/products/search?q="),
        _finding("AI_VALIDATED"),
    ])
    cov = AssessmentEngine.generate_report("inv", graph).coverage

    assert cov.findings_recorded == 1


def test_coverage_distinguishes_untested_from_clean():
    """The whole point: no confirmed finding either way, but one report says
    nothing was tried and the other says the hypothesis was tested and refuted.

    Note these two reports score differently (2.0 vs 3.5) because the legacy
    arithmetic weights a REFUTED finding by its severity. That is precisely why
    coverage cannot be inferred from the score and has to be reported beside it.
    """
    untested = AssessmentEngine.generate_report(
        "inv", _graph([_endpoint("http://t:3000/")])
    )
    tested_and_clean = AssessmentEngine.generate_report(
        "inv",
        _graph([
            _endpoint("http://t:3000/main.js"),
            _endpoint("http://t:3000/rest/products/search?q="),
            _finding("REFUTED", vuln_type="SQL Injection"),
            _validation("REFUTED"),
        ]),
    )

    assert untested.coverage.findings_confirmed == 0
    assert tested_and_clean.coverage.findings_confirmed == 0

    # The real difference is the evidence behind the number.
    assert untested.coverage.validations_run == 0
    assert tested_and_clean.coverage.validations_run == 1
    assert untested.coverage.api_endpoints == 0
    assert tested_and_clean.coverage.api_endpoints == 1

    # Only the fully-tested case is free of coverage warnings.
    assert untested.coverage.gaps
    assert not tested_and_clean.coverage.gaps


class TestRiskCountsOnlyProvenFindings:
    """The distinction the arithmetic was blurring.

    Risk is meant to answer "how bad is this target", which is a question about
    demonstrated damage. Before this, it answered "how many Finding nodes
    exist" -- so an investigation that generated candidates and disproved them
    scored higher than one that found nothing at all."""

    def test_a_refuted_finding_does_not_raise_risk(self):
        graph = _graph([_finding("REFUTED")])

        report = AssessmentEngine.generate_report("inv", graph)

        # Still inventoried: the bug was proposed and checked.
        assert report.findings_summary["High"] == 1
        # But it is not risk: nobody was harmed by it.
        assert report.risk_score == 2.0

    def test_an_untested_finding_does_not_raise_risk(self):
        """The case that motivated the change. A candidate nobody probed is a
        guess; scoring it as a high bug reported a vulnerability that had never
        been shown to exist."""
        graph = _graph([_finding("UNCONFIRMED")])

        report = AssessmentEngine.generate_report("inv", graph)

        assert report.risk_score == 2.0

    def test_a_human_confirmed_finding_does_raise_risk(self):
        graph = _graph([_finding("HUMAN_CONFIRMED")])

        assert AssessmentEngine.generate_report("inv", graph).risk_score == 3.5

    def test_only_the_proven_ones_are_weighted(self):
        """A graph holding both a real bug and a disproven one must score the
        real bug exactly as if the other had never been written."""
        graph = _graph([
            _finding("REFUTED", vuln_type="Command Injection"),
            _finding("AI_VALIDATED", vuln_type="SQL Injection"),
        ])

        report = AssessmentEngine.generate_report("inv", graph)

        assert report.risk_score == 3.5
        # Two findings exist; one is proven.
        assert report.coverage.findings_confirmed == 1


class TestValidationsRunCountsAttemptsNotFindings:
    """`validations_run` used to be len(findings) and `validations_inconclusive`
    counted an INCONCLUSIVE *finding status* the graph never stores, so it read
    zero always. Both now come from the ValidationAttempt nodes the runner
    writes, so the report says how much was actually tried."""

    def test_findings_without_attempts_do_not_count_as_validations(self):
        graph = _graph([
            _endpoint("http://t:3000/rest/x"),
            _finding("UNCONFIRMED", vuln_type="SQL Injection"),
            _finding("UNCONFIRMED", vuln_type="XSS"),
        ])

        cov = AssessmentEngine.generate_report("inv", graph).coverage

        assert cov.findings_recorded == 2
        assert cov.validations_run == 0
        assert any("validation" in g.lower() for g in cov.gaps)

    def test_each_attempt_is_counted_once(self):
        graph = _graph([
            _finding("AI_VALIDATED", vuln_type="SQL Injection"),
            _validation("CONFIRMED"),
            _validation("REFUTED"),
            _validation("REFUTED"),
        ])

        cov = AssessmentEngine.generate_report("inv", graph).coverage

        assert cov.validations_run == 3
        assert cov.validations_inconclusive == 0

    def test_blocked_attempts_were_refused_and_do_not_count_as_executed(self):
        """A gate that refused the probe means nothing reached the target;
        counting it as executed would overstate what was tested."""
        graph = _graph([
            _finding("UNCONFIRMED"),
            _validation("BLOCKED_SCOPE"),
            _validation("BLOCKED_KILLSWITCH"),
            _validation("BLOCKED_RATE_LIMIT"),
            _validation("BLOCKED_ERROR"),
        ])

        cov = AssessmentEngine.generate_report("inv", graph).coverage

        assert cov.validations_run == 0
        assert cov.validations_inconclusive == 0

    def test_inconclusive_is_read_from_the_attempt_outcome(self):
        graph = _graph([
            _validation("CONFIRMED"),
            _validation("INCONCLUSIVE"),
            _validation("INCONCLUSIVE"),
        ])

        cov = AssessmentEngine.generate_report("inv", graph).coverage

        assert cov.validations_run == 3
        assert cov.validations_inconclusive == 2

    def test_outcome_case_does_not_change_the_count(self):
        graph = _graph([_validation("refuted"), _validation("Inconclusive")])

        cov = AssessmentEngine.generate_report("inv", graph).coverage

        assert cov.validations_run == 2
        assert cov.validations_inconclusive == 1
