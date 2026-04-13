from core.cve_enricher import enrich_references


def test_enrich_references_extracts_cve_ids():
    refs = enrich_references(
        description="Potential issue CVE-2023-12345 detected",
        evidence="banner mentions CVE-2021-44228",
        references=[],
    )

    assert "https://nvd.nist.gov/vuln/detail/CVE-2023-12345" in refs
    assert "https://nvd.nist.gov/vuln/detail/CVE-2021-44228" in refs
