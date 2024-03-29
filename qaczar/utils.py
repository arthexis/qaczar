import os
import sys
import contextlib
from typing import Generator
from glob import glob
from pathlib import Path

import logging
logger = logging.getLogger(__name__)


def parse_argfiles(mode: str, *exts) -> set:
    """Parse command line arguments for files with given extensions.	
    Args:    
        mode: "in" or "out".	
        exts: File extensions to parse.
    Returns:
        Set of files with given extensions.
    """
    assert mode in ("in", "out")
    prefixed_args = [arg for arg in sys.argv[1:] if arg.startswith(f"--{mode}:")]
    args_suffixes = [arg.split(":", 1)[1] for arg in prefixed_args]
    ext_args_map = {arg.split(".")[-1]: arg for arg in args_suffixes}
    results = {ext_args_map[ext] for ext in exts if ext in ext_args_map}
    return results


def parse_argfile(mode: str, *exts) -> str | None:
    """Parse command line arguments for a single file with given extensions.	
    Args:
        mode: "in" or "out".	
        exts: File extensions to parse.
    Returns:
        File with given extensions.
    Raises:
        ValueError: If multiple files are found.
    """
    results = parse_argfiles(mode, *exts)
    if len(results) > 1:
        raise ValueError(f"Multiple {mode}put files specified: {results}")
    if results:
        return results.pop()
    return None


def parse_flags(*flags) -> bool:
    """Parse command line arguments for flags.
    Args:
        flags: Flags to parse.
    Returns:
        True if any of the flags are found, False otherwise.
    """
    for flag in flags:
        if f"--{flag}" in sys.argv[1:]:
            return True
    return False


def list_local_files(pattern: str = "*.*", _verbose=True) -> list[str]:
    """List all canvas files in the current directory.
    Args:
        pattern: Glob pattern to match.
        _verbose: Print the list of canvas files.
    Returns:
        List of files matching the pattern.
    """
    import glob
    results = []
    if _verbose: print(f"Found canvas files in {os.getcwd()}:")
    for canvas in glob.glob(pattern):
        results.append(canvas)
        if _verbose: print(f"  {canvas}")
    return results


def get_local_python(venv_name: str = ".venv") -> str:
    """Get the path to the local Python executable.
    Args:
        venv_name: Name of the virtual environment directory.
    Returns:
        Path to the local Python executable.
    """
    cwd = os.getcwd()
    if sys.platform == "win32":
        return os.path.join(cwd, venv_name, "Scripts", "python.exe")
    return os.path.join(cwd, venv_name, "bin", "python")


def load_local_pyproject() -> dict:
    """Load the pyproject.toml file.
    Returns:
        Dictionary of the pyproject.toml file.
    """
    import tomllib
    module_dir = os.path.dirname(os.path.abspath(__file__))
    project_dir = os.path.dirname(module_dir)
    with open(os.path.join(project_dir, "pyproject.toml"), "rb") as f:
        return tomllib.load(f)
    

@contextlib.contextmanager
def curr_work_dir(*dirnames) -> Generator[str, None, None]:
    """Change the current working directory temporarily.
    Args:
        path: Path to change to.
    """
    root_dir = os.environ.get("QACZAR_ROOT_DIR", ".").strip()
    temp_path = os.path.join(root_dir, *dirnames)
    old_cwd = os.getcwd()
    try:
        os.chdir(temp_path)
        yield temp_path
    finally:
        os.chdir(old_cwd)


def strip_quotes(value: str) -> str:
    """Strip all kinds of quotes from a string.
    Args:
        value: String to strip quotes from.
    Returns:
        String with quotes stripped.
    """
    return value.strip().strip('"').strip("'").strip("`")


def purge_work_files():
    """Remove old workloads."""
    with curr_work_dir("Prototypes"):
        # logger.debug(f"Purging files from {os.getcwd()}")
        for canvas_file in glob("*.canvas"):
            os.unlink(canvas_file)


def fix_path(path: str) -> str:
    """ Use pathlib to fix path for current platform, and return the fixed string.
    Args:
        path: Path to fix or convert.
    Returns:
        Fixed path.
    """
    fixed_path = str(Path(path).resolve())
    root_dir = str(Path(os.environ.get("QACZAR_ROOT_DIR", ".")).resolve())
    if fixed_path.startswith(root_dir):
        fixed_path = fixed_path[len(root_dir) + 1 :]
    return fixed_path or path

__all__ = [
    "parse_argfiles",
    "parse_argfile",
    "parse_flags",
    "list_local_files",
    "get_local_python",
    "load_local_pyproject",
    "curr_work_dir",	
    "strip_quotes",
    "purge_work_files",
]


