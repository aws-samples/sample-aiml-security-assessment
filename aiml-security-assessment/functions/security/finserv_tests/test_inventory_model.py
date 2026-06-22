"""
Unit tests for ResourceInventory data model and accessors.

Validates: Requirements REQ-4.1, REQ-4.2, REQ-9.2
"""

import pytest

from .support import finserv_app as app


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_minimal_inventory(**overrides):
    """Build a minimal ResourceInventory with all-available fields unless
    overridden."""
    defaults = dict(
        lambda_functions=[],
        guardrails=app.GuardrailInventory(summaries=[], detail_by_id={}),
        knowledge_bases=app.KbInventory(
            summaries=[], data_sources_by_kb={}, data_source_detail={}
        ),
        buckets=[],
        web_acls=app.WebAclInventory(summaries=[], detail_by_id={}),
    )
    defaults.update(overrides)
    return app.ResourceInventory(**defaults)


# ---------------------------------------------------------------------------
# Tests for `require`
# ---------------------------------------------------------------------------


class TestRequire:
    def test_raises_runtime_error_when_inventory_is_none(self):
        """require(None, ...) always raises RuntimeError (test-only default path)."""
        with pytest.raises(RuntimeError, match="resource inventory not provided"):
            app.require(None, "lambda_functions")

    def test_reraises_stored_error_when_field_is_unavailable(self):
        """require re-raises the exact exception stored in _Unavailable."""
        original_err = PermissionError("AccessDenied: list_functions denied")
        inv = _make_minimal_inventory(lambda_functions=app._Unavailable(original_err))
        with pytest.raises(PermissionError) as exc_info:
            app.require(inv, "lambda_functions")
        assert exc_info.value is original_err

    def test_reraises_stored_error_preserves_type(self):
        """The re-raised error has the same type as the stored one."""
        err = ValueError("boom")
        inv = _make_minimal_inventory(buckets=app._Unavailable(err))
        with pytest.raises(ValueError):
            app.require(inv, "buckets")

    def test_returns_value_when_field_is_available(self):
        """require returns the field's value when it is not an _Unavailable."""
        functions = [{"FunctionName": "my-fn"}]
        inv = _make_minimal_inventory(lambda_functions=functions)
        result = app.require(inv, "lambda_functions")
        assert result is functions

    def test_returns_nested_inventory_when_available(self):
        """require works for complex nested types like GuardrailInventory."""
        guardrail_inv = app.GuardrailInventory(
            summaries=[{"id": "g1"}], detail_by_id={"g1": {"policy": {}}}
        )
        inv = _make_minimal_inventory(guardrails=guardrail_inv)
        result = app.require(inv, "guardrails")
        assert result is guardrail_inv

    def test_raises_on_any_unavailable_field(self):
        """require raises for each inventory field name when it holds _Unavailable."""
        err = RuntimeError("some error")
        for field in (
            "lambda_functions",
            "guardrails",
            "knowledge_bases",
            "buckets",
            "web_acls",
        ):
            inv = _make_minimal_inventory(**{field: app._Unavailable(err)})
            with pytest.raises(RuntimeError):
                app.require(inv, field)


# ---------------------------------------------------------------------------
# Tests for `inv_available`
# ---------------------------------------------------------------------------


class TestInvAvailable:
    def test_returns_true_for_normal_value(self):
        """inv_available returns True for a plain list."""
        assert app.inv_available([]) is True

    def test_returns_true_for_non_empty_list(self):
        """inv_available returns True for a populated list."""
        assert app.inv_available([{"FunctionName": "fn"}]) is True

    def test_returns_true_for_nested_dataclass(self):
        """inv_available returns True for a GuardrailInventory."""
        gi = app.GuardrailInventory(summaries=[], detail_by_id={})
        assert app.inv_available(gi) is True

    def test_returns_false_for_unavailable(self):
        """inv_available returns False for an _Unavailable sentinel."""
        assert app.inv_available(app._Unavailable(Exception("x"))) is False

    def test_returns_false_regardless_of_stored_error(self):
        """inv_available is False for _Unavailable regardless of the error type."""
        for err in (ValueError("v"), RuntimeError("r"), Exception("e")):
            assert app.inv_available(app._Unavailable(err)) is False


# ---------------------------------------------------------------------------
# Tests for _Unavailable sentinel itself
# ---------------------------------------------------------------------------


class TestUnavailableSentinel:
    def test_stores_error(self):
        """_Unavailable stores the given exception on .error."""
        err = IOError("network error")
        sentinel = app._Unavailable(err)
        assert sentinel.error is err

    def test_is_not_list_or_dict(self):
        """_Unavailable is distinguishable from the normal inventory types."""
        sentinel = app._Unavailable(Exception())
        assert not isinstance(sentinel, (list, dict))
        assert not isinstance(sentinel, app.GuardrailInventory)
