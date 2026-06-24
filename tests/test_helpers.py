"""Shared non-fixture helpers for the top-level test suite."""


def extract_csv_data(result):
    """Extract csv_data findings from a check function result."""
    if isinstance(result, list):
        return result
    return result.get("csv_data", [])


def assert_finding_schema(finding):
    """Assert that a single finding dict has all required schema fields."""
    required_keys = {
        "Check_ID",
        "Finding",
        "Finding_Details",
        "Resolution",
        "Reference",
        "Severity",
        "Status",
        "Region",
    }
    assert required_keys.issubset(finding.keys()), (
        f"Missing keys: {required_keys - finding.keys()}"
    )
    assert finding["Severity"] in ("High", "Medium", "Low", "Informational")
    assert finding["Status"] in ("Failed", "Passed", "N/A")
    assert finding["Reference"].startswith("https://")
    assert isinstance(finding["Region"], str)
