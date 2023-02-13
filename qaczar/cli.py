# Command line interface for qaczar

import os
from pathlib import Path
from docopt import docopt

from .utils import load_local_pyproject, purge_work_files
from .builder import Canvas
from .logger import init_logger

usage = """QACZAR command line interface.

Usage:
  qaczar <canvas> [options]
  qaczar (-h | --help)

Options:
  -h --help         Show this screen.
  --version         Show version.
  --purge           Remove old work files.
  --root <dir>      Set root directory [default: root].
  --server          Start in server mode.
  --debug           Enable debug mode.
  --log <level>     Set log level [default: INFO].
  -- <args>...      Pass arguments to the canvas.

"""

def main():
    """Main entry point for qaczar."""

    pyproject = load_local_pyproject()
    version = pyproject["project"]["version"]
    args = docopt(usage, version=f"QACZAR {version}")
    init_logger(args["--log"])

    root_dir = args["--root"] or "."
    if not os.path.isabs(root_dir):
        root_dir = os.path.join(os.getcwd(), root_dir)
    os.environ["QACZAR_ROOT_DIR"] = root_dir
    
    if args["--purge"]: purge_work_files()
    if args["--debug"]: os.environ["QACZAR_DEBUG"] = "1"
    if args["--server"]: raise NotImplementedError("Server not implemented.")

    canvas_filename = Path(args["<canvas>"])
    if str(canvas_filename).startswith("Prototypes"):
        print("Prototype already built.")
        return
    canvas = Canvas(str(canvas_filename))
    try:
        results = canvas.build_prototype()
        for result in results:
            print(str(result))
    except Exception as e:
        if args["--debug"]: raise
        print(e)
        return
        

__all__ = ["main"]
