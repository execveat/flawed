"""Tests for L1-H03: Exception semantics.

Tests the CFG builder's try/except region metadata collection and the
L2 exception_guards() detection logic.
"""

from __future__ import annotations

from pathlib import Path

import libcst as cst
from libcst.metadata import MetadataWrapper

from flawed._index._cfg import build_cfg
from flawed._index._types import TryExceptRegion


def _build(source: str):
    """Parse *source* as a function body, build the CFG.

    Returns (cfg, errors).  Source is wrapped in
    ``def _test_fn():\\n    <source>`` automatically.
    """
    indented = "\n".join(f"    {line}" for line in source.splitlines())
    full = f"def _test_fn():\n{indented}\n"
    mod = cst.parse_module(full)
    wrapper = MetadataWrapper(mod, unsafe_skip_copy=True)
    func = mod.body[0]
    assert isinstance(func, cst.FunctionDef)
    return build_cfg(func, "module._test_fn", Path("test.py"), wrapper)


# =====================================================================
# 1. TryExceptRegion metadata collection (L1)
# =====================================================================


class TestTryExceptRegionMetadata:
    """CFG builder collects structured try/except region metadata."""

    def test_basic_try_except_produces_region(self):
        cfg, errors = _build("try:\n    risky()\nexcept ValueError:\n    handle()\nreturn done")
        assert not errors
        regions = cfg.try_regions
        assert len(regions) == 1
        region = regions[0]
        assert isinstance(region, TryExceptRegion)
        assert len(region.try_body_block_ids) >= 1
        assert len(region.handlers) == 1
        assert region.handlers[0].exception_types == ("ValueError",)
        assert region.finally_block_id is None
        assert region.else_block_id is None

    def test_bare_except_has_empty_exception_types(self):
        cfg, errors = _build("try:\n    risky()\nexcept:\n    handle()\nreturn done")
        assert not errors
        regions = cfg.try_regions
        assert len(regions) == 1
        assert regions[0].handlers[0].exception_types == ()

    def test_multiple_exception_types_in_handler(self):
        cfg, errors = _build(
            "try:\n    risky()\nexcept (ValueError, TypeError):\n    handle()\nreturn done"
        )
        assert not errors
        regions = cfg.try_regions
        assert len(regions) == 1
        handler = regions[0].handlers[0]
        assert set(handler.exception_types) == {"ValueError", "TypeError"}

    def test_handler_name_captured(self):
        cfg, errors = _build(
            "try:\n    risky()\nexcept ValueError as e:\n    handle(e)\nreturn done"
        )
        assert not errors
        regions = cfg.try_regions
        assert regions[0].handlers[0].name == "e"

    def test_handler_name_none_without_as(self):
        cfg, errors = _build("try:\n    risky()\nexcept ValueError:\n    handle()\nreturn done")
        assert not errors
        regions = cfg.try_regions
        assert regions[0].handlers[0].name is None

    def test_multiple_handlers(self):
        cfg, errors = _build(
            "try:\n    risky()\n"
            "except ValueError:\n    handle_v()\n"
            "except TypeError:\n    handle_t()\n"
            "return done"
        )
        assert not errors
        regions = cfg.try_regions
        assert len(regions) == 1
        assert len(regions[0].handlers) == 2
        assert regions[0].handlers[0].exception_types == ("ValueError",)
        assert regions[0].handlers[1].exception_types == ("TypeError",)

    def test_try_finally_records_finally_block_id(self):
        cfg, errors = _build(
            "try:\n    risky()\nexcept ValueError:\n    handle()\n"
            "finally:\n    cleanup()\nreturn done"
        )
        assert not errors
        regions = cfg.try_regions
        assert len(regions) == 1
        assert regions[0].finally_block_id is not None

    def test_try_else_records_else_block_id(self):
        cfg, errors = _build(
            "try:\n    risky()\nexcept ValueError:\n    handle()\nelse:\n    good()\nreturn done"
        )
        assert not errors
        regions = cfg.try_regions
        assert len(regions) == 1
        assert regions[0].else_block_id is not None

    def test_nested_try_produces_multiple_regions(self):
        cfg, errors = _build(
            "try:\n"
            "    try:\n"
            "        inner_risky()\n"
            "    except TypeError:\n"
            "        inner_handle()\n"
            "except ValueError:\n"
            "    outer_handle()\n"
            "return done"
        )
        assert not errors
        regions = cfg.try_regions
        assert len(regions) == 2

    def test_region_location_points_to_try_keyword(self):
        cfg, errors = _build("try:\n    risky()\nexcept ValueError:\n    handle()\nreturn done")
        assert not errors
        region = cfg.try_regions[0]
        # The try keyword starts at column 4 (after function indentation)
        assert region.location.file == "test.py"
        assert region.location.line == 2  # line 2 in the wrapped source

    def test_handler_entry_block_id_valid(self):
        cfg, errors = _build("try:\n    risky()\nexcept ValueError:\n    handle()\nreturn done")
        assert not errors
        region = cfg.try_regions[0]
        handler = region.handlers[0]
        # Handler entry block should be among CFG blocks
        block_ids = {b.id for b in cfg.blocks}
        assert handler.entry_block_id in block_ids

    def test_try_body_block_ids_valid(self):
        cfg, errors = _build(
            "try:\n    a = 1\n    b = 2\nexcept ValueError:\n    handle()\nreturn done"
        )
        assert not errors
        region = cfg.try_regions[0]
        block_ids = {b.id for b in cfg.blocks}
        for bid in region.try_body_block_ids:
            assert bid in block_ids


# =====================================================================
# 2. Exception guards detection (L2)
# =====================================================================


class TestExceptionGuardsDetection:
    """L2 exception_guards() identifies security guard patterns."""

    def test_abort_in_handler_detected_as_guard(self):
        """try: verify() / except: abort(403) → detected as ABORT guard."""
        from flawed._semantic._cfgview import ControlFlowView
        from flawed._semantic._scope import ConcreteCodeScope

        cfg, errors = _build(
            "try:\n    verify_token(token)\nexcept InvalidTokenError:\n    abort(403)\nreturn done"
        )
        assert not errors

        # Build mock call sites that match the CFG positions
        call_sites = _make_call_sites_for_exception_guard(cfg)

        scope = ConcreteCodeScope(
            call_sites=call_sites,
            cfg=ControlFlowView(cfg, gaps=()),
        )

        guards = scope.exception_guards()
        assert len(guards) >= 1
        guard = guards[0]
        assert guard.denial_kind.value == "abort"
        assert guard.guarded_call.target_expression == "verify_token"

    def test_no_denial_no_guard(self):
        """try: risky() / except: log() → NOT a guard (no denial)."""
        from flawed._semantic._cfgview import ControlFlowView
        from flawed._semantic._scope import ConcreteCodeScope

        cfg, errors = _build("try:\n    risky()\nexcept ValueError:\n    log_error()\nreturn done")
        assert not errors

        call_sites = _make_call_sites_for_logging_handler(cfg)

        scope = ConcreteCodeScope(
            call_sites=call_sites,
            cfg=ControlFlowView(cfg, gaps=()),
        )

        guards = scope.exception_guards()
        assert len(guards) == 0

    def test_empty_scope_returns_empty(self):
        """No call sites → no guards."""
        from flawed._semantic._cfgview import ControlFlowView
        from flawed._semantic._scope import ConcreteCodeScope

        cfg, errors = _build("x = 1\nreturn x")
        assert not errors

        scope = ConcreteCodeScope(
            call_sites=(),
            cfg=ControlFlowView(cfg, gaps=()),
        )
        guards = scope.exception_guards()
        assert guards == ()

    def test_redirect_denial_detected(self):
        """try: check() / except: redirect('/login') → REDIRECT guard."""
        from flawed._semantic._cfgview import ControlFlowView
        from flawed._semantic._scope import ConcreteCodeScope

        cfg, errors = _build(
            "try:\n    check_session()\n"
            "except SessionExpired:\n    redirect('/login')\n"
            "return done"
        )
        assert not errors

        call_sites = _make_call_sites_for_redirect_handler(cfg)

        scope = ConcreteCodeScope(
            call_sites=call_sites,
            cfg=ControlFlowView(cfg, gaps=()),
        )

        guards = scope.exception_guards()
        assert len(guards) >= 1
        assert guards[0].denial_kind.value == "redirect"

    def test_response_write_in_handler_detected_as_return_error(self):
        """try: risky() / except: jsonify(...) → RETURN_ERROR guard."""
        from flawed._semantic._cfgview import ControlFlowView
        from flawed._semantic._scope import ConcreteCodeScope
        from flawed.effects import Response

        cfg, errors = _build(
            "try:\n"
            "    risky()\n"
            "except Exception as e:\n"
            '    jsonify({"error": str(e)})\n'
            "return done"
        )
        assert not errors

        call_sites = _make_call_sites_for_response_handler(cfg)
        effect = _make_response_effect_for_handler(cfg)
        scope = ConcreteCodeScope(
            call_sites=call_sites,
            effects=(effect,),
            cfg=ControlFlowView(cfg, gaps=()),
        )

        guards = scope.exception_guards()
        assert len(guards) == 1
        guard = guards[0]
        assert guard.denial_kind.value == "return_error"
        assert [call.target_expression for call in guard.try_body.calls()] == ["risky"]
        assert [call.target_expression for call in guard.except_body.calls()] == ["jsonify"]
        assert list(guard.try_body.effects(Response.write())) == []
        assert list(guard.except_body.effects(Response.write())) == [effect]

    def test_guard_has_location(self):
        """ExceptionGuard.location points to the try statement."""
        from flawed._semantic._cfgview import ControlFlowView
        from flawed._semantic._scope import ConcreteCodeScope

        cfg, errors = _build(
            "try:\n    verify_token(token)\nexcept InvalidTokenError:\n    abort(403)\nreturn done"
        )
        assert not errors

        call_sites = _make_call_sites_for_exception_guard(cfg)
        scope = ConcreteCodeScope(
            call_sites=call_sites,
            cfg=ControlFlowView(cfg, gaps=()),
        )

        guards = scope.exception_guards()
        assert len(guards) >= 1
        assert guards[0].location.file == "test.py"
        assert guards[0].location.line >= 1

    def test_guard_has_provenance(self):
        """ExceptionGuard carries L2 provenance."""
        from flawed._semantic._cfgview import ControlFlowView
        from flawed._semantic._scope import ConcreteCodeScope

        cfg, errors = _build(
            "try:\n    verify_token(token)\nexcept InvalidTokenError:\n    abort(403)\nreturn done"
        )
        assert not errors

        call_sites = _make_call_sites_for_exception_guard(cfg)
        scope = ConcreteCodeScope(
            call_sites=call_sites,
            cfg=ControlFlowView(cfg, gaps=()),
        )

        guards = scope.exception_guards()
        assert len(guards) >= 1
        assert guards[0].provenance.source_layer == "L2"
        assert guards[0].provenance.interpreter == "exception_guard_detection"


# =====================================================================
# Test helpers — build mock CallSite objects at correct locations
# =====================================================================


def _make_call_sites_for_exception_guard(cfg):
    """Build CallSite mocks for 'try: verify_token() / except: abort()'."""
    from unittest.mock import MagicMock

    from flawed.core import Location

    # Find the try body block and handler block from the CFG
    region = cfg.try_regions[0]
    try_block = next(b for b in cfg.blocks if b.id in region.try_body_block_ids)
    handler_block = next(b for b in cfg.blocks if b.id == region.handlers[0].entry_block_id)

    # Create mock call sites at the right locations
    mock_fn = MagicMock()
    mock_fn.fqn = "module._test_fn"

    # Try body call - use a location within the try body block's statements
    try_stmt = try_block.statements[0] if try_block.statements else None
    if try_stmt:
        try_call = MagicMock()
        try_call.target_expression = "verify_token"
        try_call.location = Location(
            file=try_stmt.file,
            line=try_stmt.line,
            column=try_stmt.column,
            end_line=try_stmt.end_line,
            end_column=try_stmt.end_column,
        )
        try_call.function = mock_fn
    else:
        return ()

    # Handler call - use a location within the handler block's statements
    handler_stmt = handler_block.statements[0] if handler_block.statements else None
    if handler_stmt:
        handler_call = MagicMock()
        handler_call.target_expression = "abort"
        handler_call.location = Location(
            file=handler_stmt.file,
            line=handler_stmt.line,
            column=handler_stmt.column,
            end_line=handler_stmt.end_line,
            end_column=handler_stmt.end_column,
        )
        handler_call.function = mock_fn
    else:
        return (try_call,)

    return (try_call, handler_call)


def _make_call_sites_for_logging_handler(cfg):
    """Build CallSite mocks for 'try: risky() / except: log_error()'."""
    from unittest.mock import MagicMock

    from flawed.core import Location

    region = cfg.try_regions[0]
    try_block = next(b for b in cfg.blocks if b.id in region.try_body_block_ids)
    handler_block = next(b for b in cfg.blocks if b.id == region.handlers[0].entry_block_id)

    mock_fn = MagicMock()
    mock_fn.fqn = "module._test_fn"

    try_stmt = try_block.statements[0]
    try_call = MagicMock()
    try_call.target_expression = "risky"
    try_call.location = Location(
        file=try_stmt.file,
        line=try_stmt.line,
        column=try_stmt.column,
        end_line=try_stmt.end_line,
        end_column=try_stmt.end_column,
    )
    try_call.function = mock_fn

    handler_stmt = handler_block.statements[0]
    handler_call = MagicMock()
    handler_call.target_expression = "log_error"  # Not a denial action
    handler_call.location = Location(
        file=handler_stmt.file,
        line=handler_stmt.line,
        column=handler_stmt.column,
        end_line=handler_stmt.end_line,
        end_column=handler_stmt.end_column,
    )
    handler_call.function = mock_fn

    return (try_call, handler_call)


def _make_call_sites_for_redirect_handler(cfg):
    """Build CallSite mocks for 'try: check_session() / except: redirect()'."""
    from unittest.mock import MagicMock

    from flawed.core import Location

    region = cfg.try_regions[0]
    try_block = next(b for b in cfg.blocks if b.id in region.try_body_block_ids)
    handler_block = next(b for b in cfg.blocks if b.id == region.handlers[0].entry_block_id)

    mock_fn = MagicMock()
    mock_fn.fqn = "module._test_fn"

    try_stmt = try_block.statements[0]
    try_call = MagicMock()
    try_call.target_expression = "check_session"
    try_call.location = Location(
        file=try_stmt.file,
        line=try_stmt.line,
        column=try_stmt.column,
        end_line=try_stmt.end_line,
        end_column=try_stmt.end_column,
    )
    try_call.function = mock_fn

    handler_stmt = handler_block.statements[0]
    handler_call = MagicMock()
    handler_call.target_expression = "redirect"
    handler_call.location = Location(
        file=handler_stmt.file,
        line=handler_stmt.line,
        column=handler_stmt.column,
        end_line=handler_stmt.end_line,
        end_column=handler_stmt.end_column,
    )
    handler_call.function = mock_fn

    return (try_call, handler_call)


def _make_call_sites_for_response_handler(cfg):
    """Build CallSite mocks for 'try: risky() / except: jsonify(str(e))'."""
    from unittest.mock import MagicMock

    from flawed.core import Location

    region = cfg.try_regions[0]
    try_block = next(b for b in cfg.blocks if b.id in region.try_body_block_ids)
    handler_block = next(b for b in cfg.blocks if b.id == region.handlers[0].entry_block_id)

    mock_fn = MagicMock()
    mock_fn.fqn = "module._test_fn"

    try_stmt = try_block.statements[0]
    try_call = MagicMock()
    try_call.target_expression = "risky"
    try_call.location = Location(
        file=try_stmt.file,
        line=try_stmt.line,
        column=try_stmt.column,
        end_line=try_stmt.end_line,
        end_column=try_stmt.end_column,
    )
    try_call.function = mock_fn

    handler_stmt = handler_block.statements[0]
    handler_call = MagicMock()
    handler_call.target_expression = "jsonify"
    handler_call.location = Location(
        file=handler_stmt.file,
        line=handler_stmt.line,
        column=handler_stmt.column,
        end_line=handler_stmt.end_line,
        end_column=handler_stmt.end_column,
    )
    handler_call.function = mock_fn

    return (try_call, handler_call)


def _make_response_effect_for_handler(cfg):
    """Build a RESPONSE_WRITE effect at the exception handler statement."""
    from unittest.mock import MagicMock

    from flawed.core import Location, Provenance
    from flawed.effects import Effect, EffectCategory

    region = cfg.try_regions[0]
    handler_block = next(b for b in cfg.blocks if b.id == region.handlers[0].entry_block_id)
    handler_stmt = handler_block.statements[0]
    return Effect(
        category=EffectCategory.RESPONSE_WRITE,
        function=MagicMock(),
        location=Location(
            file=handler_stmt.file,
            line=handler_stmt.line,
            column=handler_stmt.column,
            end_line=handler_stmt.end_line,
            end_column=handler_stmt.end_column,
        ),
        expression='jsonify({"error": str(e)})',
        provenance=Provenance(source_layer="L2", interpreter="test", confidence=1.0),
    )
