"""
Unit tests for collect_resource_inventory() and the _safe_collect_* helpers.

Validates: Requirements REQ-1, REQ-2, REQ-3.4, REQ-4, REQ-7.5, REQ-9.2
"""

from unittest.mock import MagicMock, patch

import pytest

from .support import finserv_app as app


# ---------------------------------------------------------------------------
# Helpers to build mock boto3 clients
# ---------------------------------------------------------------------------


def _make_client(responses: dict) -> MagicMock:
    """Return a MagicMock boto3 client where each key in *responses* is a method
    name and the value is either a single dict (returned every call) or a list
    of dicts (returned in sequence, raising StopIteration when exhausted)."""
    client = MagicMock()
    for method_name, return_values in responses.items():
        if isinstance(return_values, list):
            method = getattr(client, method_name)
            method.side_effect = return_values
        else:
            method = getattr(client, method_name)
            method.return_value = return_values
    return client


def _single_page(key, items, extra=None):
    """Build a single-page response dict with no continuation token."""
    r = {key: items}
    if extra:
        r.update(extra)
    return r


# ---------------------------------------------------------------------------
# _safe_collect_lambda_functions
# ---------------------------------------------------------------------------


class TestSafeCollectLambdaFunctions:
    def test_single_page_returns_functions(self):
        fn = {"FunctionName": "my-fn", "Runtime": "python3.12"}
        client = _make_client({"list_functions": {"Functions": [fn]}})
        with patch("finserv_app.boto3.client", return_value=client):
            result = app._safe_collect_lambda_functions()
        assert result == [fn]

    def test_single_listing_call(self):
        client = _make_client({"list_functions": {"Functions": []}})
        with patch("finserv_app.boto3.client", return_value=client):
            app._safe_collect_lambda_functions()
        assert client.list_functions.call_count == 1

    def test_multi_page_merges_all_functions(self):
        """Multi-page result via NextMarker/Marker pagination is merged correctly."""
        fn1 = {"FunctionName": "fn-1"}
        fn2 = {"FunctionName": "fn-2"}
        client = _make_client(
            {
                "list_functions": [
                    {"Functions": [fn1], "NextMarker": "page2"},
                    {"Functions": [fn2]},
                ]
            }
        )
        with patch("finserv_app.boto3.client", return_value=client):
            result = app._safe_collect_lambda_functions()
        assert result == [fn1, fn2]
        assert client.list_functions.call_count == 2
        # Second call must use Marker= (Lambda convention)
        _, kwargs = client.list_functions.call_args
        assert "Marker" in kwargs

    def test_failure_returns_unavailable(self):
        err = PermissionError("AccessDenied")
        client = _make_client({})
        client.list_functions.side_effect = err
        with patch("finserv_app.boto3.client", return_value=client):
            result = app._safe_collect_lambda_functions()
        assert isinstance(result, app._Unavailable)
        assert result.error is err

    def test_client_constructed_without_region_or_endpoint(self):
        client = _make_client({"list_functions": {"Functions": []}})
        with patch("finserv_app.boto3.client", return_value=client) as mock_boto:
            app._safe_collect_lambda_functions()
        mock_boto.assert_called_once()
        _, kwargs = mock_boto.call_args
        assert "region_name" not in kwargs
        assert "endpoint_url" not in kwargs


# ---------------------------------------------------------------------------
# _safe_collect_guardrails
# ---------------------------------------------------------------------------


class TestSafeCollectGuardrails:
    def test_single_page_returns_guardrail_inventory(self):
        g1 = {"id": "g-abc", "name": "my-guardrail"}
        detail = {"guardrailId": "g-abc", "sensitiveInformationPolicy": {}}
        client = _make_client(
            {
                "list_guardrails": {"guardrails": [g1]},
                "get_guardrail": detail,
            }
        )
        with patch("finserv_app.boto3.client", return_value=client):
            result = app._safe_collect_guardrails()
        assert isinstance(result, app.GuardrailInventory)
        assert result.summaries == [g1]
        assert result.detail_by_id["g-abc"] is detail

    def test_single_listing_call(self):
        client = _make_client(
            {
                "list_guardrails": {"guardrails": []},
            }
        )
        with patch("finserv_app.boto3.client", return_value=client):
            app._safe_collect_guardrails()
        assert client.list_guardrails.call_count == 1

    def test_multi_page_merges_guardrails(self):
        g1 = {"id": "g1"}
        g2 = {"id": "g2"}
        client = _make_client(
            {
                "list_guardrails": [
                    {"guardrails": [g1], "nextToken": "tok2"},
                    {"guardrails": [g2]},
                ],
                "get_guardrail": {"guardrailId": "gx"},
            }
        )
        with patch("finserv_app.boto3.client", return_value=client):
            result = app._safe_collect_guardrails()
        assert len(result.summaries) == 2
        assert client.list_guardrails.call_count == 2

    def test_get_guardrail_called_with_draft(self):
        """get_guardrail must always be called with guardrailVersion='DRAFT'."""
        g1 = {"id": "g-001"}
        detail = {"guardrailId": "g-001"}
        client = _make_client(
            {
                "list_guardrails": {"guardrails": [g1]},
                "get_guardrail": detail,
            }
        )
        with patch("finserv_app.boto3.client", return_value=client):
            app._safe_collect_guardrails()
        client.get_guardrail.assert_called_once_with(
            guardrailIdentifier="g-001", guardrailVersion="DRAFT"
        )

    def test_whole_inventory_failure_returns_unavailable(self):
        err = PermissionError("AccessDenied on list_guardrails")
        client = _make_client({})
        client.list_guardrails.side_effect = err
        with patch("finserv_app.boto3.client", return_value=client):
            result = app._safe_collect_guardrails()
        assert isinstance(result, app._Unavailable)
        assert result.error is err

    def test_single_detail_failure_isolates_to_that_id(self):
        """A get_guardrail failure for one id stores _Unavailable only for that id."""
        g1 = {"id": "g-ok"}
        g2 = {"id": "g-bad"}
        ok_detail = {"guardrailId": "g-ok"}
        err = PermissionError("denied")

        def detail_side_effect(**kwargs):
            if kwargs["guardrailIdentifier"] == "g-bad":
                raise err
            return ok_detail

        client = _make_client({"list_guardrails": {"guardrails": [g1, g2]}})
        client.get_guardrail.side_effect = detail_side_effect
        with patch("finserv_app.boto3.client", return_value=client):
            result = app._safe_collect_guardrails()
        assert isinstance(result, app.GuardrailInventory)
        assert result.detail_by_id["g-ok"] is ok_detail
        assert isinstance(result.detail_by_id["g-bad"], app._Unavailable)
        assert result.detail_by_id["g-bad"].error is err

    def test_client_constructed_without_region_or_endpoint(self):
        client = _make_client({"list_guardrails": {"guardrails": []}})
        with patch("finserv_app.boto3.client", return_value=client) as mock_boto:
            app._safe_collect_guardrails()
        mock_boto.assert_called_once()
        _, kwargs = mock_boto.call_args
        assert "region_name" not in kwargs
        assert "endpoint_url" not in kwargs


# ---------------------------------------------------------------------------
# _safe_collect_knowledge_bases
# ---------------------------------------------------------------------------


class TestSafeCollectKnowledgeBases:
    def _setup_client(self, kb_list, ds_by_kb=None, ds_detail_by_pair=None):
        """Build a mock bedrock-agent client."""
        client = MagicMock()
        # list_knowledge_bases
        client.list_knowledge_bases.return_value = {"knowledgeBaseSummaries": kb_list}

        # list_data_sources
        def list_ds(**kwargs):
            kb_id = kwargs["knowledgeBaseId"]
            items = (ds_by_kb or {}).get(kb_id, [])
            return {"dataSourceSummaries": items}

        client.list_data_sources.side_effect = list_ds

        # get_data_source
        def get_ds(**kwargs):
            pair = (kwargs["knowledgeBaseId"], kwargs["dataSourceId"])
            if ds_detail_by_pair and pair in ds_detail_by_pair:
                v = ds_detail_by_pair[pair]
                if isinstance(v, Exception):
                    raise v
                return v
            return {"dataSource": {"knowledgeBaseId": kwargs["knowledgeBaseId"]}}

        client.get_data_source.side_effect = get_ds
        return client

    def test_single_kb_single_ds(self):
        kb1 = {"knowledgeBaseId": "kb-1"}
        ds1 = {"dataSourceId": "ds-1"}
        detail = {"dataSource": {"dataSourceId": "ds-1"}}
        client = self._setup_client([kb1], {"kb-1": [ds1]}, {("kb-1", "ds-1"): detail})
        with patch("finserv_app.boto3.client", return_value=client):
            result = app._safe_collect_knowledge_bases()
        assert isinstance(result, app.KbInventory)
        assert result.summaries == [kb1]
        assert result.data_sources_by_kb["kb-1"] == [ds1]
        assert result.data_source_detail[("kb-1", "ds-1")] is detail

    def test_single_listing_call(self):
        client = self._setup_client([])
        with patch("finserv_app.boto3.client", return_value=client):
            app._safe_collect_knowledge_bases()
        assert client.list_knowledge_bases.call_count == 1

    def test_multi_page_kbs(self):
        kb1 = {"knowledgeBaseId": "kb-1"}
        kb2 = {"knowledgeBaseId": "kb-2"}
        client = MagicMock()
        client.list_knowledge_bases.side_effect = [
            {"knowledgeBaseSummaries": [kb1], "nextToken": "tok2"},
            {"knowledgeBaseSummaries": [kb2]},
        ]
        client.list_data_sources.return_value = {"dataSourceSummaries": []}
        with patch("finserv_app.boto3.client", return_value=client):
            result = app._safe_collect_knowledge_bases()
        assert len(result.summaries) == 2
        assert client.list_knowledge_bases.call_count == 2

    def test_whole_inventory_failure_returns_unavailable(self):
        err = PermissionError("denied")
        client = MagicMock()
        client.list_knowledge_bases.side_effect = err
        with patch("finserv_app.boto3.client", return_value=client):
            result = app._safe_collect_knowledge_bases()
        assert isinstance(result, app._Unavailable)
        assert result.error is err

    def test_per_kb_data_source_failure_isolates(self):
        """list_data_sources failure for one KB stores _Unavailable for that KB only."""
        kb1 = {"knowledgeBaseId": "kb-ok"}
        kb2 = {"knowledgeBaseId": "kb-bad"}
        err = PermissionError("denied for kb-bad")

        client = MagicMock()
        client.list_knowledge_bases.return_value = {
            "knowledgeBaseSummaries": [kb1, kb2]
        }

        def list_ds(**kwargs):
            if kwargs["knowledgeBaseId"] == "kb-bad":
                raise err
            return {"dataSourceSummaries": []}

        client.list_data_sources.side_effect = list_ds
        with patch("finserv_app.boto3.client", return_value=client):
            result = app._safe_collect_knowledge_bases()
        assert isinstance(result, app.KbInventory)
        assert result.data_sources_by_kb["kb-ok"] == []
        assert isinstance(result.data_sources_by_kb["kb-bad"], app._Unavailable)
        assert result.data_sources_by_kb["kb-bad"].error is err

    def test_per_data_source_detail_failure_isolates(self):
        """get_data_source failure for one DS stores _Unavailable for that (kb, ds) only."""
        kb1 = {"knowledgeBaseId": "kb-1"}
        ds_ok = {"dataSourceId": "ds-ok"}
        ds_bad = {"dataSourceId": "ds-bad"}
        ok_detail = {"dataSource": {"dataSourceId": "ds-ok"}}
        err = PermissionError("denied")

        client = self._setup_client(
            [kb1],
            {"kb-1": [ds_ok, ds_bad]},
            {("kb-1", "ds-ok"): ok_detail, ("kb-1", "ds-bad"): err},
        )
        with patch("finserv_app.boto3.client", return_value=client):
            result = app._safe_collect_knowledge_bases()
        assert result.data_source_detail[("kb-1", "ds-ok")] is ok_detail
        assert isinstance(
            result.data_source_detail[("kb-1", "ds-bad")], app._Unavailable
        )

    def test_client_constructed_without_region_or_endpoint(self):
        client = self._setup_client([])
        with patch("finserv_app.boto3.client", return_value=client) as mock_boto:
            app._safe_collect_knowledge_bases()
        mock_boto.assert_called_once()
        _, kwargs = mock_boto.call_args
        assert "region_name" not in kwargs
        assert "endpoint_url" not in kwargs


# ---------------------------------------------------------------------------
# _safe_collect_buckets
# ---------------------------------------------------------------------------


class TestSafeCollectBuckets:
    def test_single_page_returns_buckets(self):
        b1 = {"Name": "my-bucket"}
        client = _make_client({"list_buckets": {"Buckets": [b1]}})
        with patch("finserv_app.boto3.client", return_value=client):
            result = app._safe_collect_buckets()
        assert result == [b1]

    def test_single_listing_call(self):
        client = _make_client({"list_buckets": {"Buckets": []}})
        with patch("finserv_app.boto3.client", return_value=client):
            app._safe_collect_buckets()
        assert client.list_buckets.call_count == 1

    def test_multi_page_with_continuation_token(self):
        """S3 ContinuationToken/ContinuationToken pagination is used (REQ-2.8)."""
        b1 = {"Name": "bucket-1"}
        b2 = {"Name": "bucket-2"}
        client = _make_client(
            {
                "list_buckets": [
                    {"Buckets": [b1], "ContinuationToken": "tok2"},
                    {"Buckets": [b2]},
                ]
            }
        )
        with patch("finserv_app.boto3.client", return_value=client):
            result = app._safe_collect_buckets()
        assert result == [b1, b2]
        assert client.list_buckets.call_count == 2
        # Second call must use ContinuationToken= as input (not NextToken etc.)
        _, kwargs = client.list_buckets.call_args
        assert "ContinuationToken" in kwargs

    def test_max_buckets_parameter_sent_on_first_call(self):
        """MaxBuckets must be included on the first call to engage pagination."""
        client = _make_client({"list_buckets": {"Buckets": []}})
        with patch("finserv_app.boto3.client", return_value=client):
            app._safe_collect_buckets()
        first_call_kwargs = client.list_buckets.call_args_list[0][1]
        assert first_call_kwargs.get("MaxBuckets") == 1000

    def test_failure_returns_unavailable(self):
        err = PermissionError("AccessDenied")
        client = MagicMock()
        client.list_buckets.side_effect = err
        with patch("finserv_app.boto3.client", return_value=client):
            result = app._safe_collect_buckets()
        assert isinstance(result, app._Unavailable)
        assert result.error is err

    def test_client_constructed_without_region_or_endpoint(self):
        client = _make_client({"list_buckets": {"Buckets": []}})
        with patch("finserv_app.boto3.client", return_value=client) as mock_boto:
            app._safe_collect_buckets()
        mock_boto.assert_called_once()
        _, kwargs = mock_boto.call_args
        assert "region_name" not in kwargs
        assert "endpoint_url" not in kwargs


# ---------------------------------------------------------------------------
# _safe_collect_web_acls
# ---------------------------------------------------------------------------


class TestSafeCollectWebAcls:
    def test_single_page_returns_web_acl_inventory(self):
        acl1 = {"Id": "acl-1", "Name": "my-acl", "ARN": "arn:aws:wafv2:::webacl/acl-1"}
        detail = {"WebACL": {"Id": "acl-1"}}
        client = _make_client(
            {
                "list_web_acls": {"WebACLs": [acl1]},
                "get_web_acl": detail,
            }
        )
        with patch("finserv_app.boto3.client", return_value=client):
            result = app._safe_collect_web_acls()
        assert isinstance(result, app.WebAclInventory)
        assert result.summaries == [acl1]
        # The collector extracts response["WebACL"] — not the full envelope —
        # so downstream checks can do detail.get("Rules") without extra indirection.
        assert result.detail_by_id["acl-1"] == detail["WebACL"]

    def test_single_listing_call(self):
        client = _make_client(
            {
                "list_web_acls": {"WebACLs": []},
            }
        )
        with patch("finserv_app.boto3.client", return_value=client):
            app._safe_collect_web_acls()
        assert client.list_web_acls.call_count == 1

    def test_list_web_acls_called_with_scope_regional(self):
        """Scope='REGIONAL' must be passed on every list_web_acls call (REQ-7.2)."""
        client = _make_client({"list_web_acls": {"WebACLs": []}})
        with patch("finserv_app.boto3.client", return_value=client):
            app._safe_collect_web_acls()
        client.list_web_acls.assert_called_once()
        _, kwargs = client.list_web_acls.call_args
        assert kwargs.get("Scope") == "REGIONAL"

    def test_multi_page_uses_next_marker_as_input(self):
        """WAFv2 pagination uses NextMarker as BOTH output and input (REQ-2.2)."""
        acl1 = {"Id": "acl-1", "Name": "acl-1"}
        acl2 = {"Id": "acl-2", "Name": "acl-2"}
        detail = {"WebACL": {}}
        client = _make_client(
            {
                "list_web_acls": [
                    {"WebACLs": [acl1], "NextMarker": "mark2"},
                    {"WebACLs": [acl2]},
                ],
                "get_web_acl": detail,
            }
        )
        with patch("finserv_app.boto3.client", return_value=client):
            result = app._safe_collect_web_acls()
        assert len(result.summaries) == 2
        assert client.list_web_acls.call_count == 2
        # Second call must use NextMarker= (NOT Marker= which is Lambda's convention)
        second_call_kwargs = client.list_web_acls.call_args_list[1][1]
        assert "NextMarker" in second_call_kwargs
        assert second_call_kwargs["NextMarker"] == "mark2"
        assert "Marker" not in second_call_kwargs

    def test_get_web_acl_called_with_scope_regional(self):
        """get_web_acl must always use Scope='REGIONAL' (REQ-7.2)."""
        acl1 = {"Id": "acl-1", "Name": "acl-name"}
        detail = {"WebACL": {"Id": "acl-1"}}
        client = _make_client(
            {
                "list_web_acls": {"WebACLs": [acl1]},
                "get_web_acl": detail,
            }
        )
        with patch("finserv_app.boto3.client", return_value=client):
            app._safe_collect_web_acls()
        client.get_web_acl.assert_called_once_with(
            Name="acl-name", Scope="REGIONAL", Id="acl-1"
        )

    def test_whole_inventory_failure_returns_unavailable(self):
        err = PermissionError("AccessDenied")
        client = MagicMock()
        client.list_web_acls.side_effect = err
        with patch("finserv_app.boto3.client", return_value=client):
            result = app._safe_collect_web_acls()
        assert isinstance(result, app._Unavailable)
        assert result.error is err

    def test_single_detail_failure_isolates_to_that_id(self):
        acl_ok = {"Id": "acl-ok", "Name": "ok-acl"}
        acl_bad = {"Id": "acl-bad", "Name": "bad-acl"}
        ok_detail = {"WebACL": {"Id": "acl-ok"}}
        err = PermissionError("denied")

        def get_web_acl(**kwargs):
            if kwargs["Id"] == "acl-bad":
                raise err
            return ok_detail

        client = _make_client(
            {
                "list_web_acls": {"WebACLs": [acl_ok, acl_bad]},
            }
        )
        client.get_web_acl.side_effect = get_web_acl
        with patch("finserv_app.boto3.client", return_value=client):
            result = app._safe_collect_web_acls()
        # Collector extracts ["WebACL"] — verify the stored dict matches the inner value
        assert result.detail_by_id["acl-ok"] == ok_detail["WebACL"]
        assert isinstance(result.detail_by_id["acl-bad"], app._Unavailable)
        assert result.detail_by_id["acl-bad"].error is err

    def test_client_constructed_without_region_or_endpoint(self):
        client = _make_client({"list_web_acls": {"WebACLs": []}})
        with patch("finserv_app.boto3.client", return_value=client) as mock_boto:
            app._safe_collect_web_acls()
        mock_boto.assert_called_once()
        _, kwargs = mock_boto.call_args
        assert "region_name" not in kwargs
        assert "endpoint_url" not in kwargs


# ---------------------------------------------------------------------------
# collect_resource_inventory — integration
# ---------------------------------------------------------------------------


class TestCollectResourceInventory:
    """Verify that collect_resource_inventory delegates to each _safe_collect_*
    and assembles a ResourceInventory."""

    def _patch_all_safe_fns(self):
        """Context-manager that patches all five _safe_collect_* functions."""
        import contextlib

        @contextlib.contextmanager
        def _ctx():
            lf = [{"FunctionName": "fn-1"}]
            gi = app.GuardrailInventory(summaries=[{"id": "g-1"}], detail_by_id={})
            ki = app.KbInventory(
                summaries=[], data_sources_by_kb={}, data_source_detail={}
            )
            bk = [{"Name": "bkt-1"}]
            wi = app.WebAclInventory(summaries=[{"Id": "acl-1"}], detail_by_id={})
            with (
                patch(
                    "finserv_app._safe_collect_lambda_functions", return_value=lf
                ) as p1,
                patch("finserv_app._safe_collect_guardrails", return_value=gi) as p2,
                patch(
                    "finserv_app._safe_collect_knowledge_bases", return_value=ki
                ) as p3,
                patch("finserv_app._safe_collect_buckets", return_value=bk) as p4,
                patch("finserv_app._safe_collect_web_acls", return_value=wi) as p5,
            ):
                yield p1, p2, p3, p4, p5

        return _ctx()

    def test_returns_resource_inventory(self):
        with self._patch_all_safe_fns():
            inv = app.collect_resource_inventory()
        assert isinstance(inv, app.ResourceInventory)

    def test_each_safe_fn_called_exactly_once(self):
        with self._patch_all_safe_fns() as (p1, p2, p3, p4, p5):
            app.collect_resource_inventory()
        for p in (p1, p2, p3, p4, p5):
            assert p.call_count == 1

    def test_inventory_fields_come_from_safe_fns(self):
        with self._patch_all_safe_fns():
            inv = app.collect_resource_inventory()
        # Spot-check a few field values match what the patched fns returned
        assert inv.lambda_functions == [{"FunctionName": "fn-1"}]
        assert inv.buckets == [{"Name": "bkt-1"}]

    def test_one_unavailable_does_not_prevent_others(self):
        """An _Unavailable on one field doesn't affect the rest."""
        err = PermissionError("denied")
        with (
            patch(
                "finserv_app._safe_collect_lambda_functions",
                return_value=app._Unavailable(err),
            ),
            patch(
                "finserv_app._safe_collect_guardrails",
                return_value=app.GuardrailInventory([], {}),
            ),
            patch(
                "finserv_app._safe_collect_knowledge_bases",
                return_value=app.KbInventory([], {}, {}),
            ),
            patch("finserv_app._safe_collect_buckets", return_value=[]),
            patch(
                "finserv_app._safe_collect_web_acls",
                return_value=app.WebAclInventory([], {}),
            ),
        ):
            inv = app.collect_resource_inventory()
        assert isinstance(inv.lambda_functions, app._Unavailable)
        assert isinstance(inv.guardrails, app.GuardrailInventory)
        assert inv.buckets == []

    def test_all_unavailable_still_returns_inventory(self):
        """Even when every field fails, we get a ResourceInventory (not an exception)."""
        err = RuntimeError("all down")
        unav = app._Unavailable(err)
        with (
            patch("finserv_app._safe_collect_lambda_functions", return_value=unav),
            patch("finserv_app._safe_collect_guardrails", return_value=unav),
            patch("finserv_app._safe_collect_knowledge_bases", return_value=unav),
            patch("finserv_app._safe_collect_buckets", return_value=unav),
            patch("finserv_app._safe_collect_web_acls", return_value=unav),
        ):
            inv = app.collect_resource_inventory()
        assert isinstance(inv, app.ResourceInventory)
        for field in (
            "lambda_functions",
            "guardrails",
            "knowledge_bases",
            "buckets",
            "web_acls",
        ):
            assert isinstance(getattr(inv, field), app._Unavailable)

    def test_unavailable_field_causes_could_not_assess_via_require(self):
        """A consuming check using require() on an unavailable field gets the stored
        error raised, which the outer try/except turns into _error_findings."""
        err = PermissionError("AccessDenied")
        inv = app.ResourceInventory(
            lambda_functions=app._Unavailable(err),
            guardrails=app.GuardrailInventory([], {}),
            knowledge_bases=app.KbInventory([], {}, {}),
            buckets=[],
            web_acls=app.WebAclInventory([], {}),
        )
        with pytest.raises(PermissionError) as exc_info:
            app.require(inv, "lambda_functions")
        assert exc_info.value is err


# ---------------------------------------------------------------------------
# Ordering / listing-order preservation
# ---------------------------------------------------------------------------


class TestOrderPreservation:
    def test_lambda_functions_order_preserved(self):
        fns = [{"FunctionName": f"fn-{i}"} for i in range(5)]
        client = _make_client({"list_functions": {"Functions": fns}})
        with patch("finserv_app.boto3.client", return_value=client):
            result = app._safe_collect_lambda_functions()
        assert result == fns

    def test_web_acls_multi_page_order_preserved(self):
        acls_p1 = [{"Id": f"acl-{i}", "Name": f"acl-{i}"} for i in range(3)]
        acls_p2 = [{"Id": f"acl-{i}", "Name": f"acl-{i}"} for i in range(3, 6)]
        client = _make_client(
            {
                "list_web_acls": [
                    {"WebACLs": acls_p1, "NextMarker": "pg2"},
                    {"WebACLs": acls_p2},
                ],
                "get_web_acl": {"WebACL": {}},
            }
        )
        with patch("finserv_app.boto3.client", return_value=client):
            result = app._safe_collect_web_acls()
        assert result.summaries == acls_p1 + acls_p2

    def test_buckets_multi_page_order_preserved(self):
        bkts_p1 = [{"Name": f"bkt-{i}"} for i in range(3)]
        bkts_p2 = [{"Name": f"bkt-{i}"} for i in range(3, 6)]
        client = _make_client(
            {
                "list_buckets": [
                    {"Buckets": bkts_p1, "ContinuationToken": "pg2"},
                    {"Buckets": bkts_p2},
                ]
            }
        )
        with patch("finserv_app.boto3.client", return_value=client):
            result = app._safe_collect_buckets()
        assert result == bkts_p1 + bkts_p2
