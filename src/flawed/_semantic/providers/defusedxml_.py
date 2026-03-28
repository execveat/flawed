"""defusedxml provider -- XXE-safe XML parsing guards.

``defusedxml`` provides drop-in replacements for Python's stdlib XML
parsers that block XML entity expansion attacks (XXE / billion laughs).
Each submodule mirrors a stdlib module but with safe defaults:

- ``defusedxml.ElementTree`` replaces ``xml.etree.ElementTree``
- ``defusedxml.minidom`` replaces ``xml.dom.minidom``
- ``defusedxml.sax`` replaces ``xml.sax``
- ``defusedxml.pulldom`` replaces ``xml.dom.pulldom``
- ``defusedxml.expatreader`` replaces ``xml.sax.expatreader``
- ``defusedxml.lxml`` wraps ``lxml.etree`` with XXE protection

Using these functions is a security check: it proves the developer
chose the safe parsing path over the vulnerable stdlib default.
"""

from __future__ import annotations

from flawed._semantic.providers._base import (
    CheckKind,
    FlowPropagatorPattern,
    Provider,
    ProviderMeta,
    SecurityCheckPattern,
)


class DefusedXMLProvider(Provider):
    meta = ProviderMeta(
        id="defusedxml",
        name="defusedxml",
        version="0.1.0",
        library="defusedxml",
        library_fqn="defusedxml",
    )

    # =================================================================
    # Security checks: XXE-safe parsing functions
    # =================================================================

    checks = (
        # -- defusedxml.ElementTree (replaces xml.etree.ElementTree) ----
        SecurityCheckPattern(
            fqn="defusedxml.ElementTree.parse",
            kind=CheckKind.CALL,
            category="XXE_PROTECTION",
            description="Safe ElementTree parse (blocks entity expansion)",
        ),
        SecurityCheckPattern(
            fqn="defusedxml.ElementTree.fromstring",
            kind=CheckKind.CALL,
            category="XXE_PROTECTION",
            description="Safe ElementTree fromstring (blocks entity expansion)",
        ),
        SecurityCheckPattern(
            fqn="defusedxml.ElementTree.iterparse",
            kind=CheckKind.CALL,
            category="XXE_PROTECTION",
            description="Safe ElementTree iterparse (blocks entity expansion)",
        ),
        # -- defusedxml.minidom (replaces xml.dom.minidom) ---------------
        SecurityCheckPattern(
            fqn="defusedxml.minidom.parse",
            kind=CheckKind.CALL,
            category="XXE_PROTECTION",
            description="Safe minidom parse (blocks entity expansion)",
        ),
        SecurityCheckPattern(
            fqn="defusedxml.minidom.parseString",
            kind=CheckKind.CALL,
            category="XXE_PROTECTION",
            description="Safe minidom parseString (blocks entity expansion)",
        ),
        # -- defusedxml.sax (replaces xml.sax) ---------------------------
        SecurityCheckPattern(
            fqn="defusedxml.sax.parse",
            kind=CheckKind.CALL,
            category="XXE_PROTECTION",
            description="Safe SAX parse (blocks entity expansion)",
        ),
        SecurityCheckPattern(
            fqn="defusedxml.sax.parseString",
            kind=CheckKind.CALL,
            category="XXE_PROTECTION",
            description="Safe SAX parseString (blocks entity expansion)",
        ),
        SecurityCheckPattern(
            fqn="defusedxml.sax.make_parser",
            kind=CheckKind.CALL,
            category="XXE_PROTECTION",
            description="Safe SAX parser factory (blocks entity expansion)",
        ),
        # -- defusedxml.pulldom (replaces xml.dom.pulldom) ---------------
        SecurityCheckPattern(
            fqn="defusedxml.pulldom.parse",
            kind=CheckKind.CALL,
            category="XXE_PROTECTION",
            description="Safe pulldom parse (blocks entity expansion)",
        ),
        SecurityCheckPattern(
            fqn="defusedxml.pulldom.parseString",
            kind=CheckKind.CALL,
            category="XXE_PROTECTION",
            description="Safe pulldom parseString (blocks entity expansion)",
        ),
        # -- defusedxml.expatreader (replaces xml.sax.expatreader) -------
        SecurityCheckPattern(
            fqn="defusedxml.expatreader.create_parser",
            kind=CheckKind.CALL,
            category="XXE_PROTECTION",
            description="Safe expat parser factory (blocks entity expansion)",
        ),
        # -- defusedxml.lxml (wraps lxml.etree with XXE protection) ------
        SecurityCheckPattern(
            fqn="defusedxml.lxml.parse",
            kind=CheckKind.CALL,
            category="XXE_PROTECTION",
            description="Safe lxml parse (blocks entity expansion)",
        ),
        SecurityCheckPattern(
            fqn="defusedxml.lxml.fromstring",
            kind=CheckKind.CALL,
            category="XXE_PROTECTION",
            description="Safe lxml fromstring (blocks entity expansion)",
        ),
    )

    # =================================================================
    # Flow propagation: XML input flows through parse to tree
    # =================================================================

    propagators = (
        # ElementTree parse/fromstring: XML source → parsed tree
        FlowPropagatorPattern(
            fqn="defusedxml.ElementTree.parse",
            input_arg=0,
            output="return",
            description="XML source flows through safe parse to ElementTree",
        ),
        FlowPropagatorPattern(
            fqn="defusedxml.ElementTree.fromstring",
            input_arg=0,
            output="return",
            description="XML string flows through safe parse to Element",
        ),
        FlowPropagatorPattern(
            fqn="defusedxml.ElementTree.iterparse",
            input_arg=0,
            output="return",
            description="XML source flows through safe iterparse to events",
        ),
        # minidom parse/parseString: XML source → Document
        FlowPropagatorPattern(
            fqn="defusedxml.minidom.parse",
            input_arg=0,
            output="return",
            description="XML source flows through safe parse to Document",
        ),
        FlowPropagatorPattern(
            fqn="defusedxml.minidom.parseString",
            input_arg=0,
            output="return",
            description="XML string flows through safe parse to Document",
        ),
        # lxml parse/fromstring: XML source → lxml Element
        FlowPropagatorPattern(
            fqn="defusedxml.lxml.parse",
            input_arg=0,
            output="return",
            description="XML source flows through safe lxml parse to tree",
        ),
        FlowPropagatorPattern(
            fqn="defusedxml.lxml.fromstring",
            input_arg=0,
            output="return",
            description="XML string flows through safe lxml parse to Element",
        ),
    )
