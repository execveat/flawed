"""Import patterns: absolute, relative, aliased, star."""

import os  # noqa: F401 - intentional: tests import resolution for stdlib
import os.path as osp  # noqa: F401 - intentional: tests aliased stdlib import
from collections import OrderedDict as OD  # noqa: F401 - intentional: tests aliased from-import
from pathlib import Path  # noqa: F401 - intentional: tests from-import resolution

from . import helpers
from .helpers import process_data
from .helpers import transform as t


def run():
    helpers.setup()
    result = process_data("input")
    return t(result)
