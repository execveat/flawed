"""Python standard-library provider.

Built-in calls are resolved by Layer 1 with ``builtins.*`` FQNs, but they do
not appear as import facts.  The provider engine treats ``library_fqn`` of
``"builtins"`` as always active so these descriptors apply to every analyzed
repository.  Non-builtin stdlib descriptors in this provider still require an
exact resolved call FQN such as ``os.system`` or ``subprocess.run``.
"""

from __future__ import annotations

from flawed._semantic.providers._base import Provider, ProviderMeta, TaintSinkPattern, arg, kwarg


class PythonStdlibProvider(Provider):
    meta = ProviderMeta(
        id="python-stdlib",
        name="Python standard library",
        version="0.1.0",
        library="Python",
        library_fqn="builtins",
    )

    sinks = (
        # -- Filesystem path sinks --
        TaintSinkPattern(
            fqn="builtins.open",
            arg=0,
            keyword="file",
            sink_kind="PATH_TRAVERSAL",
            when=~(arg(0).is_literal_string() | kwarg("file").is_literal_string()),
            description="Filesystem path may be user-controlled",
        ),
        TaintSinkPattern(
            fqn="os.path.join",
            arg=1,
            sink_kind="PATH_TRAVERSAL",
            when=~arg(1).is_literal_string(),
            description="Path component may be user-controlled",
        ),
        # -- Shell command sinks --
        TaintSinkPattern(
            fqn="os.system",
            arg=0,
            sink_kind="COMMAND_INJECTION",
            when=~arg(0).is_literal_string(),
            description="Shell command may be user-controlled",
        ),
        TaintSinkPattern(
            fqn="os.popen",
            arg=0,
            sink_kind="COMMAND_INJECTION",
            when=~arg(0).is_literal_string(),
            description="Shell command via popen may be user-controlled",
        ),
        TaintSinkPattern(
            fqn="subprocess.run",
            arg=0,
            keyword="args",
            sink_kind="COMMAND_INJECTION",
            when=~(arg(0).is_literal_string() | kwarg("args").is_literal_string()),
            description="Subprocess command may be user-controlled",
        ),
        TaintSinkPattern(
            fqn="subprocess.Popen",
            arg=0,
            keyword="args",
            sink_kind="COMMAND_INJECTION",
            when=~(arg(0).is_literal_string() | kwarg("args").is_literal_string()),
            description="Subprocess via Popen may be user-controlled",
        ),
        TaintSinkPattern(
            fqn="subprocess.call",
            arg=0,
            keyword="args",
            sink_kind="COMMAND_INJECTION",
            when=~(arg(0).is_literal_string() | kwarg("args").is_literal_string()),
            description="Subprocess via call may be user-controlled",
        ),
        TaintSinkPattern(
            fqn="subprocess.check_output",
            arg=0,
            keyword="args",
            sink_kind="COMMAND_INJECTION",
            when=~(arg(0).is_literal_string() | kwarg("args").is_literal_string()),
            description="Subprocess via check_output may be user-controlled",
        ),
        TaintSinkPattern(
            fqn="subprocess.check_call",
            arg=0,
            keyword="args",
            sink_kind="COMMAND_INJECTION",
            when=~(arg(0).is_literal_string() | kwarg("args").is_literal_string()),
            description="Subprocess via check_call may be user-controlled",
        ),
        # -- Code injection sinks --
        TaintSinkPattern(
            fqn="builtins.eval",
            arg=0,
            sink_kind="CODE_INJECTION",
            when=~arg(0).is_literal_string(),
            description="Python expression may be user-controlled",
        ),
        TaintSinkPattern(
            fqn="builtins.exec",
            arg=0,
            sink_kind="CODE_INJECTION",
            when=~arg(0).is_literal_string(),
            description="Python code body may be user-controlled",
        ),
        TaintSinkPattern(
            fqn="builtins.compile",
            arg=0,
            sink_kind="CODE_INJECTION",
            when=~arg(0).is_literal_string(),
            description="Python code compilation may be user-controlled",
        ),
        # -- Deserialization sinks --
        TaintSinkPattern(
            fqn="pickle.loads",
            arg=0,
            sink_kind="DESERIALIZATION",
            description="Pickle deserialization of potentially user-controlled data",
        ),
        TaintSinkPattern(
            fqn="pickle.load",
            arg=0,
            sink_kind="DESERIALIZATION",
            description="Pickle deserialization from potentially user-controlled stream",
        ),
        TaintSinkPattern(
            fqn="yaml.load",
            arg=0,
            sink_kind="DESERIALIZATION",
            description="YAML load may deserialize untrusted data",
        ),
        TaintSinkPattern(
            fqn="yaml.unsafe_load",
            arg=0,
            sink_kind="DESERIALIZATION",
            description="Explicit unsafe YAML loading",
        ),
    )
