# Command line interface for qaczar

import os
from docopt import docopt

from .utils import set_dir, load_local_pyproject, purge_work_files
from .builder import Canvas

usage = """ QACZAR command line interface.

Usage:
  qaczar <canvas> [options]
  qaczar (-h | --help)

Options:
  -h --help     Show this screen.
  --version     Show version.
  --purge       Remove old workloads.
  --root <dir>  Specify root directory.
  --server      Start in server mode.

"""

def main():
    """Main entry point for qaczar."""
    pyproject = load_local_pyproject()
    args = docopt(usage, version=pyproject["version"])
    if root_dir := args["--root"]:
        os.environ["QACZAR_ROOT_DIR"] = root_dir
    else:
        assert "QACZAR_ROOT_DIR" in os.environ, "QACZAR_ROOT_DIR not set"
    with set_dir("/"):
        if args["--purge"]:
            purge_work_files()
        canvas = Canvas(args["<canvas>"])
        canvas.build_prototypes()
        

__all__ = ["main"]
