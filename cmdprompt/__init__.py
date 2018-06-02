import os
import glob

from .commands import *

modules = glob.glob(os.path.dirname(__file__) + "/cmd_*.py")
modules = ["." + os.path.basename(f)[:-3] for f in modules if os.path.isfile(f)]

# l-o-l. Couldn't figure out a better way to do this.
for module in modules:
    exec("from " + module + " import *")
