"""Synthetic Flask app generator for memory stress testing.

Generates valid Python Flask apps at configurable scale dimensions.
The output exercises the full flawed pipeline: Semgrep extraction,
LibCST structural analysis, CFG construction, call-graph merge,
value-flow extraction, provider matching, semantic conversion,
scope attachment, and L3 rules.

Scale dimensions:
- file_count: total Python files (25, 50, 100, 150)
- functions_per_file: non-route helper functions per file
- routes_per_file: Flask route handlers per blueprint module
- call_edge_density: cross-file helper calls per route body
- blueprint_count: number of Blueprint packages
- helper_fan_out: how many routes call each shared helper
- providers: which provider patterns to emit (flask, pyjwt, sqlalchemy)
"""

from __future__ import annotations

import random
import textwrap
from dataclasses import dataclass
from pathlib import Path  # noqa: TC003 — runtime use


@dataclass(frozen=True)
class StressConfig:
    """Dimensions for synthetic app generation."""

    file_count: int = 25
    functions_per_file: int = 8
    routes_per_file: int = 4
    call_edge_density: int = 3
    blueprint_count: int = 4
    helper_fan_out: int = 5
    providers: tuple[str, ...] = ("flask", "sqlalchemy")
    seed: int = 42

    @property
    def label(self) -> str:
        """Short human-readable label for this configuration."""
        return f"f{self.file_count}_fn{self.functions_per_file}_r{self.routes_per_file}"


# -- Preset configurations for scaling experiments ---------------------------

PRESETS: dict[str, StressConfig] = {
    "small": StressConfig(
        file_count=25,
        functions_per_file=6,
        routes_per_file=3,
        call_edge_density=2,
        blueprint_count=3,
        helper_fan_out=4,
    ),
    "medium": StressConfig(
        file_count=50,
        functions_per_file=8,
        routes_per_file=4,
        call_edge_density=3,
        blueprint_count=5,
        helper_fan_out=6,
    ),
    "large": StressConfig(
        file_count=100,
        functions_per_file=10,
        routes_per_file=5,
        call_edge_density=4,
        blueprint_count=8,
        helper_fan_out=8,
    ),
    "xlarge": StressConfig(
        file_count=150,
        functions_per_file=12,
        routes_per_file=6,
        call_edge_density=5,
        blueprint_count=10,
        helper_fan_out=10,
        providers=("flask", "sqlalchemy", "pyjwt"),
    ),
}


@dataclass(frozen=True)
class GeneratedApp:
    """Metadata about a generated synthetic app."""

    app_dir: Path
    file_count: int
    function_count: int
    route_count: int
    line_count: int


def generate_stress_app(config: StressConfig, output_dir: Path) -> GeneratedApp:
    """Generate a synthetic Flask app and return metadata about it.

    Creates a realistic Flask app structure with blueprints, helpers,
    cross-file calls, and provider-specific patterns.  All generated
    code is syntactically valid Python.
    """
    rng = random.Random(config.seed)
    app_dir = output_dir / f"stress_{config.label}"
    app_dir.mkdir(parents=True, exist_ok=True)

    helper_names = _generate_helpers(config, app_dir)
    _generate_blueprints(config, app_dir, helper_names, rng)
    _generate_app_py(config, app_dir)
    _generate_init(app_dir)

    stats = describe_generated_app(config, app_dir)
    return GeneratedApp(
        app_dir=app_dir,
        file_count=int(stats["python_files"]),  # type: ignore[call-overload]
        function_count=int(stats["estimated_functions"]),  # type: ignore[call-overload]
        route_count=int(stats["estimated_routes"]),  # type: ignore[call-overload]
        line_count=int(stats["total_lines"]),  # type: ignore[call-overload]
    )


# ---------------------------------------------------------------------------
# Helpers module generation
# ---------------------------------------------------------------------------

_INPUT_PATTERNS = [
    'request.args.get("{key}")',
    'request.form.get("{key}")',
    'request.form["{key}"]',
    'request.headers.get("{key}")',
    'request.cookies.get("{key}")',
    "request.get_json()",
    "request.json",
    "request.data",
]

_EFFECT_PATTERNS_FLASK = [
    'session["{key}"] = value',
    "g.{key} = value",
    'flash("operation completed")',
]

_EFFECT_PATTERNS_SQLA = [
    'db.execute(text("SELECT * FROM {table} WHERE id=:id"), {{"id": pk}})',
    'db.execute(text("INSERT INTO {table} (name) VALUES (:n)"), {{"n": name}})',
    "db.commit()",
]

_SINK_PATTERNS_SQLA = [
    "db.execute(text(user_input))",
]

_SINK_PATTERNS_FLASK = [
    "render_template_string(user_input)",
    "redirect(user_input)",
]


def _generate_helpers(
    config: StressConfig,
    app_dir: Path,
) -> list[str]:
    """Generate shared helper modules and return a list of helper FQNs."""
    helpers_dir = app_dir / "helpers"
    helpers_dir.mkdir(exist_ok=True)
    (helpers_dir / "__init__.py").write_text("", encoding="utf-8")

    all_helper_names: list[str] = []

    # common.py: generic helpers that read inputs and return values
    common_helpers = _generate_common_helpers(config)
    all_helper_names.extend(f"helpers.common.{n}" for n in common_helpers)
    _write_helper_module(helpers_dir / "common.py", common_helpers, "common")

    # db.py: SQLAlchemy-flavored helpers (if sqlalchemy in providers)
    if "sqlalchemy" in config.providers:
        db_helpers = _generate_db_helpers(config)
        all_helper_names.extend(f"helpers.db.{n}" for n in db_helpers)
        _write_db_module(helpers_dir / "db.py", db_helpers)

    # auth.py: JWT/auth helpers (if pyjwt in providers)
    if "pyjwt" in config.providers:
        auth_helpers = _generate_auth_helpers(config)
        all_helper_names.extend(f"helpers.auth.{n}" for n in auth_helpers)
        _write_auth_module(helpers_dir / "auth.py", auth_helpers)

    return all_helper_names


def _generate_common_helpers(config: StressConfig) -> list[str]:
    """Return a list of common helper function names."""
    count = max(config.helper_fan_out * 2, 10)
    return [f"process_data_{i}" for i in range(count)]


def _generate_db_helpers(config: StressConfig) -> list[str]:
    count = max(config.helper_fan_out, 5)
    return [f"db_operation_{i}" for i in range(count)]


def _generate_auth_helpers(config: StressConfig) -> list[str]:
    count = max(config.helper_fan_out, 4)
    return [f"verify_token_{i}" for i in range(count)]


def _write_helper_module(path: Path, names: list[str], module_label: str) -> None:
    """Write a common helper module with functions that read inputs."""
    lines = [
        f'"""Shared {module_label} helpers for stress testing."""',
        "",
        "from flask import g, jsonify, request, session",
        "",
    ]
    for i, name in enumerate(names):
        key = f"param_{module_label}_{i}"
        lines.extend(
            [
                "",
                f"def {name}(value=None):",
                f'    """Helper {name}: reads input, processes, returns."""',
                f'    data = request.args.get("{key}", "")',
                f'    session["{key}_processed"] = True',
                "    intermediate = data.strip().lower() if data else str(value)",
                f"    g.last_{module_label}_{i} = intermediate",
                "    return intermediate",
            ]
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_db_module(path: Path, names: list[str]) -> None:
    """Write a SQLAlchemy-flavored helper module."""
    lines = [
        '"""Database helpers for stress testing."""',
        "",
        "from flask import g, request",
        "from sqlalchemy import text",
        "from sqlalchemy.orm import Session as SaSession",
        "",
    ]
    tables = ["users", "orders", "items", "logs", "sessions", "events"]
    for i, name in enumerate(names):
        table = tables[i % len(tables)]
        select_q = f"SELECT * FROM {table} WHERE id=:id"
        update_q = f"UPDATE {table} SET status=:s WHERE id=:id"
        lines.extend(
            [
                "",
                f"def {name}(pk=None):",
                f'    """DB helper: query and mutate {table} table."""',
                "    db = g.db_session  # type: SaSession",
                f'    user_input = request.form.get("query_{i}", "")',
                f'    result = db.execute(text("{select_q}"), {{"id": pk}})',
                f'    db.execute(text("{update_q}"),',
                '               {"s": user_input, "id": pk})',
                "    db.commit()",
                "    return list(result)",
            ]
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_auth_module(path: Path, names: list[str]) -> None:
    """Write a JWT/auth helper module."""
    lines = [
        '"""Auth/JWT helpers for stress testing."""',
        "",
        "import jwt",
        "",
        "from flask import request",
        "",
        'SECRET_KEY = "stress-test-secret"',
        "",
    ]
    for i, name in enumerate(names):
        lines.extend(
            [
                "",
                f"def {name}(token=None):",
                f'    """Auth helper: decode and verify token variant {i}."""',
                "    if token is None:",
                '        token = request.headers.get("Authorization", "")',
                '        if token.startswith("Bearer "):',
                "            token = token[7:]",
                "    try:",
                '        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])',
                '        return payload.get("sub")',
                "    except jwt.InvalidTokenError:",
                "        return None",
            ]
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Blueprint module generation
# ---------------------------------------------------------------------------


def _generate_blueprints(
    config: StressConfig,
    app_dir: Path,
    helper_names: list[str],
    rng: random.Random,
) -> None:
    """Generate blueprint packages with route modules."""
    # Distribute files across blueprints
    route_files = config.file_count - _non_route_file_count(config)
    files_per_bp = max(1, route_files // config.blueprint_count)

    file_idx = 0
    for bp_idx in range(config.blueprint_count):
        bp_name = f"bp_{bp_idx:03d}"
        bp_dir = app_dir / bp_name
        bp_dir.mkdir(exist_ok=True)

        # __init__.py with Blueprint definition
        _write_blueprint_init(bp_dir, bp_name, bp_idx)

        # Route files for this blueprint
        n_files = files_per_bp
        if bp_idx == config.blueprint_count - 1:
            n_files = max(1, route_files - file_idx)
        for _f_idx in range(n_files):
            if file_idx >= route_files:
                break
            _write_route_file(
                config,
                bp_dir,
                bp_name=bp_name,
                file_idx=file_idx,
                helper_names=helper_names,
                rng=rng,
            )
            file_idx += 1


def _non_route_file_count(config: StressConfig) -> int:
    """Count non-route files (app.py, __init__.py, helpers/*)."""
    count = 3  # app.py, __init__.py, helpers/__init__.py, helpers/common.py
    if "sqlalchemy" in config.providers:
        count += 1
    if "pyjwt" in config.providers:
        count += 1
    # Each blueprint has an __init__.py
    count += config.blueprint_count
    return count


def _write_blueprint_init(bp_dir: Path, bp_name: str, _bp_idx: int) -> None:
    """Write a blueprint package __init__.py."""
    content = textwrap.dedent(f"""\
        \"\"\"Blueprint {bp_name}: auto-generated for stress testing.\"\"\"

        from flask import Blueprint

        bp = Blueprint("{bp_name}", __name__, url_prefix="/{bp_name}")
    """)
    (bp_dir / "__init__.py").write_text(content, encoding="utf-8")


def _write_route_file(
    config: StressConfig,
    bp_dir: Path,
    *,
    bp_name: str,
    file_idx: int,
    helper_names: list[str],
    rng: random.Random,
) -> None:
    """Write a route file with routes and helper functions."""
    filename = f"routes_{file_idx:03d}.py"
    lines: list[str] = []

    # Imports
    lines.append(f'"""Routes file {file_idx} for blueprint {bp_name}."""')
    lines.append("")
    lines.append(
        "from flask import g, jsonify, redirect, render_template_string, request, session"
    )
    lines.append("")
    lines.append("from . import bp")
    lines.append("")

    # Provider-specific imports
    if "sqlalchemy" in config.providers:
        lines.append("from sqlalchemy import text")
        lines.append("from sqlalchemy.orm import Session as SaSession")
        lines.append("")

    # Helper imports — pick a subset for this file's routes to call
    available_helpers = _pick_helpers_for_file(config, helper_names, file_idx)
    import_groups = _group_helper_imports(available_helpers)
    for module_path, func_names in sorted(import_groups.items()):
        names_str = ", ".join(sorted(func_names))
        lines.append(f"from {module_path} import {names_str}")
    if import_groups:
        lines.append("")

    # Local helper functions (non-route, creates intra-file call edges)
    local_fn_names: list[str] = []
    for fn_idx in range(config.functions_per_file):
        fn_name = f"_helper_f{file_idx}_{fn_idx}"
        local_fn_names.append(fn_name)
        lines.extend(_generate_local_helper(fn_name, fn_idx, file_idx))
        lines.append("")

    # Route handlers
    for r_idx in range(config.routes_per_file):
        route_name = f"route_f{file_idx}_r{r_idx}"
        path = f"/{bp_name}/f{file_idx}/r{r_idx}"
        lines.extend(
            _generate_route(
                config,
                route_name=route_name,
                path=path,
                r_idx=r_idx,
                file_idx=file_idx,
                local_fn_names=local_fn_names,
                available_helpers=[h.rsplit(".", 1)[-1] for h in available_helpers],
                rng=rng,
            )
        )
        lines.append("")

    (bp_dir / filename).write_text("\n".join(lines) + "\n", encoding="utf-8")


def _pick_helpers_for_file(
    config: StressConfig,
    helper_names: list[str],
    file_idx: int,
) -> list[str]:
    """Pick a subset of helpers for this file to import and call.

    Uses a rotating window so each helper is called from approximately
    ``helper_fan_out`` different files, creating the cross-file
    reachable-scope pressure that real apps exhibit.
    """
    if not helper_names:
        return []
    needed = config.call_edge_density * config.routes_per_file
    needed = min(needed, len(helper_names))

    # Rotating window ensures fan-out distribution
    start = (file_idx * config.call_edge_density) % len(helper_names)
    selected: list[str] = []
    for i in range(needed):
        idx = (start + i) % len(helper_names)
        selected.append(helper_names[idx])
    return selected


def _group_helper_imports(helpers: list[str]) -> dict[str, list[str]]:
    """Group helper FQNs by their module path for import statements."""
    groups: dict[str, list[str]] = {}
    for fqn in helpers:
        parts = fqn.rsplit(".", 1)
        if len(parts) == 2:
            module, name = parts
            groups.setdefault(module, []).append(name)
    return groups


def _generate_local_helper(
    fn_name: str,
    fn_idx: int,
    file_idx: int,
) -> list[str]:
    """Generate a local (intra-file) helper function."""
    lines = [
        f"def {fn_name}(data=None):",
        f'    """Local helper {fn_idx} in file {file_idx}."""',
        f'    value = request.args.get("local_{fn_idx}", "")',
        "    result = value.strip().lower() if value else str(data)",
    ]
    # Some helpers do state writes
    if fn_idx % 3 == 0:
        lines.append(f'    session["local_{file_idx}_{fn_idx}"] = result')
    # Some helpers do g writes
    if fn_idx % 4 == 0:
        lines.append(f"    g.local_{file_idx}_{fn_idx} = result")
    lines.append("    return result")
    return lines


def _generate_route(
    config: StressConfig,
    *,
    route_name: str,
    path: str,
    r_idx: int,
    file_idx: int,
    local_fn_names: list[str],
    available_helpers: list[str],
    rng: random.Random,
) -> list[str]:
    """Generate a route handler with inputs, helper calls, effects, and sinks."""
    methods = rng.choice(
        [
            '["GET"]',
            '["POST"]',
            '["GET", "POST"]',
            '["GET", "POST", "PUT"]',
        ]
    )

    lines = [
        f'@bp.route("{path}", methods={methods})',
        f"def {route_name}():",
        f'    """Auto-generated route {route_name}."""',
    ]

    # Input reads (1-3 per route)
    input_count = rng.randint(1, 3)
    input_patterns = rng.sample(_INPUT_PATTERNS, min(input_count, len(_INPUT_PATTERNS)))
    for i, pat in enumerate(input_patterns):
        key = f"param_{file_idx}_{r_idx}_{i}"
        expr = pat.format(key=key, table="items")
        lines.append(f"    input_{i} = {expr}")

    # Cross-file helper calls (call_edge_density per route)
    helpers_to_call = available_helpers[: config.call_edge_density]
    for i, helper_name in enumerate(helpers_to_call):
        lines.append(f"    result_{i} = {helper_name}(input_0)")

    # Local helper calls (1-2 per route for intra-file edges)
    local_count = min(2, len(local_fn_names))
    local_picks = rng.sample(local_fn_names, local_count) if local_fn_names else []
    for i, local_name in enumerate(local_picks):
        lines.append(f"    local_result_{i} = {local_name}(input_0)")

    # Effects — flask session/g writes
    if r_idx % 2 == 0:
        key = f"route_{file_idx}_{r_idx}"
        effect = rng.choice(_EFFECT_PATTERNS_FLASK).format(key=key)
        lines.append(f"    {effect}")

    # SQLAlchemy effects (if provider is active)
    if "sqlalchemy" in config.providers and r_idx % 3 == 0:
        table = rng.choice(["users", "orders", "items", "logs"])
        lines.append("    db = g.db_session  # type: SaSession")
        effect = rng.choice(_EFFECT_PATTERNS_SQLA).format(table=table)
        lines.append(f"    {effect}")

    # Taint sinks — some routes have vulnerable patterns
    if r_idx % 5 == 0 and "sqlalchemy" in config.providers:
        lines.append("    user_input = input_0")
        sink = rng.choice(_SINK_PATTERNS_SQLA)
        lines.append("    db = g.db_session  # type: SaSession")
        lines.append(f"    {sink}")
    elif r_idx % 7 == 0:
        lines.append("    user_input = input_0")
        sink = rng.choice(_SINK_PATTERNS_FLASK)
        lines.append(f"    return {sink}")
        return lines  # early return — redirect/render is the response

    # Normal response
    lines.append("    return jsonify({")
    lines.append(f'        "route": "{route_name}",')
    if helpers_to_call:
        lines.append('        "processed": result_0,')
    lines.append("    })")

    return lines


# ---------------------------------------------------------------------------
# App module and package init
# ---------------------------------------------------------------------------


def _generate_app_py(config: StressConfig, app_dir: Path) -> None:
    """Generate the main app.py with Flask app and blueprint registration."""
    lines = [
        '"""Auto-generated Flask app for memory stress testing."""',
        "",
        "from flask import Flask",
        "",
        "app = Flask(__name__)",
        "",
    ]

    # Import and register each blueprint
    for bp_idx in range(config.blueprint_count):
        bp_name = f"bp_{bp_idx:03d}"
        lines.append(f"from {bp_name} import bp as {bp_name}_bp")

    lines.append("")

    for bp_idx in range(config.blueprint_count):
        bp_name = f"bp_{bp_idx:03d}"
        lines.append(f"app.register_blueprint({bp_name}_bp)")

    lines.append("")

    # Lifecycle hooks
    lines.extend(
        [
            "",
            "@app.before_request",
            "def before_request():",
            '    """Before-request lifecycle hook."""',
            "    pass",
            "",
            "",
            "@app.after_request",
            "def after_request(response):",
            '    """After-request lifecycle hook."""',
            "    return response",
            "",
            "",
            "@app.errorhandler(404)",
            "def not_found(e):",
            '    """Error handler lifecycle hook."""',
            '    return {"error": "not found"}, 404',
        ]
    )

    (app_dir / "app.py").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _generate_init(app_dir: Path) -> None:
    """Write a top-level __init__.py."""
    (app_dir / "__init__.py").write_text("", encoding="utf-8")


# ---------------------------------------------------------------------------
# Summary / stats
# ---------------------------------------------------------------------------


def describe_generated_app(config: StressConfig, app_dir: Path) -> dict[str, object]:
    """Count generated files and estimate pipeline workload."""
    py_files = list(app_dir.rglob("*.py"))
    total_lines = sum(f.read_text(encoding="utf-8").count("\n") for f in py_files)

    route_files = config.file_count - _non_route_file_count(config)
    est_routes = route_files * config.routes_per_file
    est_functions = route_files * config.functions_per_file + est_routes
    est_call_edges = est_routes * (config.call_edge_density + 2)

    return {
        "config_label": config.label,
        "python_files": len(py_files),
        "total_lines": total_lines,
        "estimated_routes": est_routes,
        "estimated_functions": est_functions,
        "estimated_cross_file_call_edges": est_call_edges,
        "blueprint_count": config.blueprint_count,
        "providers": list(config.providers),
        "app_dir": str(app_dir),
    }
