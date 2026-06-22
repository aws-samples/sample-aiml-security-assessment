"""
Tests for the _paginate helper — Task 2.1
FinServ Shared-Inventory Refactor (FU-3)

Requirements: REQ-2.3, REQ-2.5, REQ-9.2

Coverage
--------
1. WAFv2  token=("NextMarker", "NextMarker")  — multi-page
2. S3     token=("ContinuationToken", "ContinuationToken")  — multi-page
3. Regression: Lambda Marker convention (no token= passed) — multi-page
4. Regression: bedrock nextToken convention (no token= passed) — multi-page
5. Single-page = exactly one call (both with and without token=)
6. Repeated-token loop guard (infinite-loop protection)
7. token= override bypasses the convention table (WAFv2 NextMarker ≠ Lambda Marker)
"""

from __future__ import annotations

from unittest.mock import MagicMock, call

from .support import finserv_app as app


# ===========================================================================
# Helpers
# ===========================================================================


def _make_client(pages: list[dict]) -> MagicMock:
    """Return a mock boto3 client whose ``list_items`` method yields ``pages``
    sequentially.  Each element in ``pages`` is the raw response dict."""
    client = MagicMock()
    client.list_items.side_effect = pages
    return client


# ===========================================================================
# 1. WAFv2 NextMarker / NextMarker  (explicit token override, multi-page)
# ===========================================================================


class TestWafv2NextMarkerOverride:
    """token=("NextMarker", "NextMarker") — both the output field and the
    request parameter are "NextMarker", which collides with Lambda's
    convention that maps "NextMarker" → "Marker".  The explicit override
    must bypass the table and use the correct input param.

    Validates: REQ-2.3 (correct per-operation convention), REQ-9.2-b
    """

    def test_multi_page_collects_all_items(self):
        pages = [
            {"WebACLs": [{"Id": "acl-1"}, {"Id": "acl-2"}], "NextMarker": "tok-1"},
            {"WebACLs": [{"Id": "acl-3"}]},
        ]
        client = _make_client(pages)

        result = app._paginate(
            client,
            "list_items",
            "WebACLs",
            token=("NextMarker", "NextMarker"),
            Scope="REGIONAL",
        )

        assert result == [{"Id": "acl-1"}, {"Id": "acl-2"}, {"Id": "acl-3"}]

    def test_multi_page_request_uses_NextMarker_not_Marker(self):
        """The second call must send NextMarker= (WAFv2), NOT Marker= (Lambda)."""
        pages = [
            {"WebACLs": [{"Id": "acl-1"}], "NextMarker": "tok-1"},
            {"WebACLs": [{"Id": "acl-2"}]},
        ]
        client = _make_client(pages)

        app._paginate(
            client,
            "list_items",
            "WebACLs",
            token=("NextMarker", "NextMarker"),
            Scope="REGIONAL",
        )

        calls = client.list_items.call_args_list
        assert len(calls) == 2
        # First call: no pagination token
        assert calls[0] == call(Scope="REGIONAL")
        # Second call: NextMarker= (not Marker=)
        assert calls[1] == call(Scope="REGIONAL", NextMarker="tok-1")
        assert "Marker" not in calls[1].kwargs

    def test_three_pages_correct_order(self):
        pages = [
            {"WebACLs": [{"Id": "a"}], "NextMarker": "t1"},
            {"WebACLs": [{"Id": "b"}], "NextMarker": "t2"},
            {"WebACLs": [{"Id": "c"}]},
        ]
        client = _make_client(pages)

        result = app._paginate(
            client, "list_items", "WebACLs", token=("NextMarker", "NextMarker")
        )

        assert result == [{"Id": "a"}, {"Id": "b"}, {"Id": "c"}]
        assert client.list_items.call_count == 3


# ===========================================================================
# 2. S3 ContinuationToken / ContinuationToken  (explicit token override, multi-page)
# ===========================================================================


class TestS3ContinuationTokenOverride:
    """token=("ContinuationToken", "ContinuationToken") — ContinuationToken is
    absent from the default convention table, so without the explicit override
    _paginate would stop after the first page.

    Validates: REQ-2.3, REQ-2.8, REQ-9.2-b
    """

    def test_multi_page_collects_all_buckets(self):
        pages = [
            {
                "Buckets": [{"Name": "bucket-1"}, {"Name": "bucket-2"}],
                "ContinuationToken": "ct-1",
            },
            {"Buckets": [{"Name": "bucket-3"}]},
        ]
        client = _make_client(pages)

        result = app._paginate(
            client,
            "list_items",
            "Buckets",
            token=("ContinuationToken", "ContinuationToken"),
            MaxBuckets=1000,
        )

        assert result == [
            {"Name": "bucket-1"},
            {"Name": "bucket-2"},
            {"Name": "bucket-3"},
        ]

    def test_second_call_sends_continuation_token(self):
        pages = [
            {"Buckets": [{"Name": "b1"}], "ContinuationToken": "ct-1"},
            {"Buckets": [{"Name": "b2"}]},
        ]
        client = _make_client(pages)

        app._paginate(
            client,
            "list_items",
            "Buckets",
            token=("ContinuationToken", "ContinuationToken"),
            MaxBuckets=1000,
        )

        calls = client.list_items.call_args_list
        assert calls[0] == call(MaxBuckets=1000)
        assert calls[1] == call(MaxBuckets=1000, ContinuationToken="ct-1")

    def test_three_pages_order_preserved(self):
        pages = [
            {"Buckets": [{"Name": "b1"}], "ContinuationToken": "ct-1"},
            {"Buckets": [{"Name": "b2"}], "ContinuationToken": "ct-2"},
            {"Buckets": [{"Name": "b3"}]},
        ]
        client = _make_client(pages)

        result = app._paginate(
            client,
            "list_items",
            "Buckets",
            token=("ContinuationToken", "ContinuationToken"),
        )

        assert [b["Name"] for b in result] == ["b1", "b2", "b3"]
        assert client.list_items.call_count == 3


# ===========================================================================
# 3. Regression: Lambda Marker convention unchanged (no token= passed)
# ===========================================================================


class TestLambdaMarkerRegression:
    """Existing callers that use the Lambda convention (output: NextMarker,
    input: Marker) must behave identically when no token= is passed.

    Validates: REQ-2.3 (no regression), REQ-9.2-b
    """

    def test_single_page_single_call(self):
        client = _make_client([{"Functions": [{"FunctionName": "f1"}]}])

        result = app._paginate(client, "list_items", "Functions")

        assert result == [{"FunctionName": "f1"}]
        assert client.list_items.call_count == 1

    def test_multi_page_uses_Marker_not_NextMarker(self):
        pages = [
            {"Functions": [{"FunctionName": "f1"}], "NextMarker": "m1"},
            {"Functions": [{"FunctionName": "f2"}]},
        ]
        client = _make_client(pages)

        result = app._paginate(client, "list_items", "Functions")

        assert result == [{"FunctionName": "f1"}, {"FunctionName": "f2"}]
        calls = client.list_items.call_args_list
        # Second call must use "Marker=" (Lambda convention), not "NextMarker="
        assert calls[1] == call(Marker="m1")
        assert "NextMarker" not in calls[1].kwargs

    def test_multi_page_collects_all(self):
        pages = [
            {"Functions": [{"FunctionName": "f1"}], "NextMarker": "m1"},
            {"Functions": [{"FunctionName": "f2"}], "NextMarker": "m2"},
            {"Functions": [{"FunctionName": "f3"}]},
        ]
        client = _make_client(pages)

        result = app._paginate(client, "list_items", "Functions")

        assert [f["FunctionName"] for f in result] == ["f1", "f2", "f3"]
        assert client.list_items.call_count == 3


# ===========================================================================
# 4. Regression: bedrock nextToken convention unchanged (no token= passed)
# ===========================================================================


class TestBedrockNextTokenRegression:
    """Existing callers that use the bedrock lower-camel nextToken convention
    must behave identically when no token= is passed.

    Validates: REQ-2.3 (no regression), REQ-9.2-b
    """

    def test_single_page_single_call(self):
        client = _make_client([{"guardrails": [{"id": "g1"}]}])

        result = app._paginate(client, "list_items", "guardrails")

        assert result == [{"id": "g1"}]
        assert client.list_items.call_count == 1

    def test_multi_page_collects_all(self):
        pages = [
            {"guardrails": [{"id": "g1"}], "nextToken": "nt1"},
            {"guardrails": [{"id": "g2"}], "nextToken": "nt2"},
            {"guardrails": [{"id": "g3"}]},
        ]
        client = _make_client(pages)

        result = app._paginate(client, "list_items", "guardrails")

        assert [g["id"] for g in result] == ["g1", "g2", "g3"]
        calls = client.list_items.call_args_list
        assert calls[1] == call(nextToken="nt1")
        assert calls[2] == call(nextToken="nt2")
        assert client.list_items.call_count == 3


# ===========================================================================
# 5. Single-page = exactly one call (both with and without token=)
# ===========================================================================


class TestSinglePageSingleCall:
    """A single-page response (no continuation token in output) must yield
    exactly one API call regardless of whether token= is supplied.

    Validates: REQ-2.5
    """

    def test_no_token_override_single_call(self):
        client = _make_client([{"Items": [{"id": "x"}]}])

        result = app._paginate(client, "list_items", "Items")

        assert result == [{"id": "x"}]
        assert client.list_items.call_count == 1

    def test_wafv2_token_override_single_call(self):
        client = _make_client([{"WebACLs": [{"Id": "a1"}]}])

        result = app._paginate(
            client,
            "list_items",
            "WebACLs",
            token=("NextMarker", "NextMarker"),
            Scope="REGIONAL",
        )

        assert result == [{"Id": "a1"}]
        assert client.list_items.call_count == 1

    def test_s3_token_override_single_call(self):
        client = _make_client([{"Buckets": [{"Name": "b1"}]}])

        result = app._paginate(
            client,
            "list_items",
            "Buckets",
            token=("ContinuationToken", "ContinuationToken"),
        )

        assert result == [{"Name": "b1"}]
        assert client.list_items.call_count == 1


# ===========================================================================
# 6. Repeated-token loop guard
# ===========================================================================


class TestRepeatedTokenLoopGuard:
    """If a mock (or a misbehaving API) returns the same token every call,
    _paginate must stop after collecting the first page and not loop forever.

    This guard must hold both with and without the token= override.

    Validates: REQ-9.2 (loop-guard regression)
    """

    def test_loop_guard_no_override(self):
        """Lambda convention: repeated NextMarker stops after two calls."""
        repeated_page = {"Functions": [{"FunctionName": "f1"}], "NextMarker": "same"}
        client = MagicMock()
        client.list_items.return_value = repeated_page

        result = app._paginate(client, "list_items", "Functions")

        # First call collects items; token "same" is seen; second call also
        # returns "same" which is in seen_tokens → stop.
        assert result == [{"FunctionName": "f1"}, {"FunctionName": "f1"}]
        assert client.list_items.call_count == 2

    def test_loop_guard_with_wafv2_override(self):
        """WAFv2 token= override: repeated NextMarker stops after two calls."""
        repeated_page = {"WebACLs": [{"Id": "a"}], "NextMarker": "same"}
        client = MagicMock()
        client.list_items.return_value = repeated_page

        result = app._paginate(
            client,
            "list_items",
            "WebACLs",
            token=("NextMarker", "NextMarker"),
        )

        assert result == [{"Id": "a"}, {"Id": "a"}]
        assert client.list_items.call_count == 2

    def test_loop_guard_with_s3_override(self):
        """S3 token= override: repeated ContinuationToken stops after two calls."""
        repeated_page = {"Buckets": [{"Name": "b"}], "ContinuationToken": "same"}
        client = MagicMock()
        client.list_items.return_value = repeated_page

        result = app._paginate(
            client,
            "list_items",
            "Buckets",
            token=("ContinuationToken", "ContinuationToken"),
        )

        assert result == [{"Name": "b"}, {"Name": "b"}]
        assert client.list_items.call_count == 2


# ===========================================================================
# 7. token= override disambiguates WAFv2 NextMarker from Lambda NextMarker
# ===========================================================================


class TestWafv2VsLambdaDisambiguation:
    """Prove that the explicit token= override is the only way to correctly
    paginate WAFv2: without it, the convention table maps NextMarker → Marker
    (Lambda convention), which would send the wrong input parameter.

    Validates: REQ-2.9 — the (output, input) pair must be supplied explicitly
    for WAFv2 because output-field name alone is insufficient to infer the
    correct input parameter.
    """

    def test_without_override_sends_Marker_for_NextMarker_output(self):
        """Without token=, the convention table maps NextMarker → Marker.
        This is the Lambda convention — correct for Lambda, wrong for WAFv2."""
        pages = [
            {"WebACLs": [{"Id": "a1"}], "NextMarker": "tok"},
            {"WebACLs": [{"Id": "a2"}]},
        ]
        client = _make_client(pages)

        # Intentionally NOT passing token= to demonstrate the convention-table behavior
        app._paginate(client, "list_items", "WebACLs")

        calls = client.list_items.call_args_list
        # The convention table sends Marker= (Lambda convention) — wrong for WAFv2
        assert calls[1] == call(Marker="tok")

    def test_with_override_sends_NextMarker_for_NextMarker_output(self):
        """With token=("NextMarker","NextMarker"), the second call sends NextMarker=."""
        pages = [
            {"WebACLs": [{"Id": "a1"}], "NextMarker": "tok"},
            {"WebACLs": [{"Id": "a2"}]},
        ]
        client = _make_client(pages)

        app._paginate(
            client,
            "list_items",
            "WebACLs",
            token=("NextMarker", "NextMarker"),
        )

        calls = client.list_items.call_args_list
        assert calls[1] == call(NextMarker="tok")
        assert "Marker" not in calls[1].kwargs
