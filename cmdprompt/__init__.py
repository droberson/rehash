"""
This should import every file named cmd_*.py in this directory.

Each file will be a command for the rehash> prompt.
"""

import os
import glob

from .commands import *

MODULES = glob.glob(os.path.dirname(__file__) + "/cmd_*.py")
MODULES = ["." + os.path.basename(f)[:-3] for f in MODULES if os.path.isfile(f)]

# l-o-l. Couldn't figure out a better way to do this.
for module in MODULES:
    exec("from " + module + " import *")
