# Description: A builder for QACzar canvas-based prototypes.

import io
import os
import sys
import ast
import json
import shutil
import logging
import requests
import subprocess
import contextlib
from enum import Enum
from typing import Optional, Any, Generator
from dataclasses import dataclass

import sigils  # type: ignore
from .utils import get_local_python, curr_work_dir, strip_quotes

logger = logging.getLogger(__name__)


class Status(str, Enum):
    """Sets the color of a node in a canvas diagram or prototype."""
    NEW = "7"       # Gray
    READY = "5"     # Blue
    ACTIVE = "3"    # Yellow
    WARNING = "2"   # Orange
    FAILURE = "1"   # Red
    SUCCESS = "4"   # Green
    HIDDEN = "6"    # Purple


@dataclass
class Node:
    """A node in a canvas diagram or prototype."""	
    id: str
    x: int
    y: int
    width: int
    height: int
    type: str
    file: str = ""
    text: str = ""
    color: str = ""
    url: str = ""
        
    def is_text(self) -> bool:
        return self.type == "text"
    
    def is_blank(self) -> bool:
        # Files are blank if they have 0 bytes
        with curr_work_dir():
            return (self.is_text() and not self.text) \
                or (self.is_file() and os.path.getsize(self.file) == 0)
    
    def is_remote(self) -> bool:
        return (self.type == "link" and bool(self.url)) or self.is_file("url") \
            or (bool(self.text) and self.text.startswith("http"))

    def get_ext(self) -> str:
        return self.file.split(".")[-1] if self.is_file() else ""

    def is_file(self, *exts: str) -> bool:
        _exts = [ext.lstrip(".") for ext in exts]
        return self.type == "file" and (not exts or self.get_ext() in _exts)
    
    def read_text_file(self) -> str:
        with curr_work_dir():
            with open(self.file, "r", encoding="utf-8") as f:
                return f.read()
        
    def write_text_file(self, text: str):
        with curr_work_dir():
            with open(self.file, "w", encoding="utf-8") as f:
                f.write(text)

    def is_markdown(self) -> bool:
        return self.is_text()  or self.is_file("md")

    def read_text_or_file(self) -> str:
        return self.text if self.is_text() else self.read_text_file()
    
    def write_text_or_file(self, text: str) -> None:
        if self.is_text():
            self.text = text
        else:
            self.write_text_file(text)
    
    def is_script(self) -> bool:
        return self.is_file("py")
        
    def is_canvas(self) -> bool:
        return self.is_file("canvas")
    
    def is_non_script_file(self) -> bool:
        return self.is_file() and not self.is_script()
    
    def is_cached(self) -> bool:
        return self.is_file() and os.path.exists(self.file) 

    def __str__(self) -> str:
        if self.is_text(): return self.text
        elif self.is_file(): return self.file
        elif self.is_remote(): return self.url
        else: return self.type

    def __repr__(self) -> str:
        return f"{self.id}: {self.type} {self}"
    
    def set_status(self, status: Status) -> None:
        self.color = status.value

    def get_status(self) -> Status:
        return Status(self.color if self.color else "7")
    
    def build_temp_filename(self) -> str:
        if self.file:
            return os.path.join(os.getcwd(), 
                    f"Temp-{self.file.split('/')[-1].split('.')[0]}.md")
        return os.path.join(os.getcwd(), f"Temp-Node.md")


@dataclass
class Edge:
    """An edge in a canvas diagram or prototype.
    An edge connects two nodes in a canvas in a directed fashion.
    """
    id: str
    fromNode: str
    toNode: str
    fromSide: str
    toSide: str
    label: str = ""


class Canvas:
    """A canvas diagram used to construct software prototypes."""

    def __init__(self, filename: str, context: Optional[dict[str, Any]] = None) -> None:
        """Load a canvas diagram from a file in the root directory.
        Canvas files are used as blueprints to construct software prototypes.
        Args:
            filename: The path to the canvas file
        Raises:
            ValueError: If the canvas file is in the workloads directory
        """	
        self.source_filename = filename
        if os.path.dirname(filename) == "Prototypes":
            raise ValueError("Canvas file must not be in the works directory")
        self.work_filename = os.path.basename(filename)
        # Print to stdout for Obsidian to capture the filename
        print(self.work_filename)
        with curr_work_dir():
            self.source_mtime = os.path.getmtime(filename) 
            with open(filename, "r") as f:
                canvas_data = json.load(f)
        self.nodes = [Node(**node) for node in canvas_data["nodes"]]
        self.edges = [Edge(**edge) for edge in canvas_data["edges"]]
        self.node_map = {node.id: node for node in self.nodes}
        self.context: dict[str, Any] = context or {
            "CANVAS": self, "OUTPUTS": [], 
            "IMG": lambda x, y: markdown_image(x, y),
            "LINK": lambda x, y: markdown_link(x, y),
        }
        
    
    def save_work_file(self) -> None:
        """Save a copy of the canvas diagram to its working file.
        This avoids overwriting the original canvas file.
        Args:
            filename: The path to the canvas file
        """
        diagram = {
            "nodes": [node.__dict__ for node in self.nodes],
            "edges": [edge.__dict__ for edge in self.edges],
        }
        with curr_work_dir("Prototypes"):
            with open(self.work_filename, "w") as f:
                json.dump(diagram, f, indent=4)
    
    def find_target_nodes(self) -> list[Node]:
        """Find nodes with no outgoing edges and at least one incoming edge.
        These nodes are executed to produce the canvas output.
        Returns:
            A list of target nodes
        """
        # Target nodes have no outgoing edges and at least one incoming edge
        outgoing_ids = [edge.fromNode for edge in self.edges]
        target_nodes = [node for node in self.nodes if node.id not in outgoing_ids]
        target_nodes = [node for node in target_nodes if node.id in 
                        [edge.toNode for edge in self.edges]]
        # Sort them by position in the diagram, top to bottom, left to right
        # This is so that the diagram is traversed in the same order every time
        target_nodes.sort(key=lambda node: (node.y, node.x))
        return target_nodes
    
    def find_upstream_nodes(self, node: Node) -> list[Node]:
        """Find nodes with an incoming edge to the given node.
        These nodes are executed before the given node to generate its input.
        Args:
            node: The node to find upstream nodes for
        Returns:
            A list of upstream nodes
        """
        upstream_nodes = []
        for edge in self.edges:
            if edge.toNode == node.id:
                upstream_nodes.append(self.node_map[edge.fromNode])
        upstream_nodes.sort(key=lambda node: (node.y, node.x))
        upstream_nodes = [n for n in upstream_nodes if n != node]
        return upstream_nodes
    
    def find_downstream_nodes(self, node: Node) -> list[Node]:
        """Find nodes with an outgoing edge from the given node.
        These nodes are used to populate the TARGET context before executing the node.
        Args:
            node: The node to find downstream nodes for
        Returns:
            A list of downstream nodes
        """
        downstream_nodes = []
        for edge in self.edges:
            if edge.fromNode == node.id:
                downstream_nodes.append(self.node_map[edge.toNode])
        downstream_nodes.sort(key=lambda node: (node.y, node.x))
        downstream_nodes = [n for n in downstream_nodes if n.id != node.id]
        return downstream_nodes
    
    def find_isolated_nodes(self) -> list[Node]:
        """Find nodes with no incoming or outgoing edges.
        These nodes are executed first to gather context, but give no output.
        Returns:
            A list of isolated nodes
        """
        isolated_nodes = []
        for node in self.nodes:
            if node.id not in [edge.fromNode for edge in self.edges] and \
               node.id not in [edge.toNode for edge in self.edges]:
                isolated_nodes.append(node)
        isolated_nodes.sort(key=lambda node: (node.y, node.x))
        return isolated_nodes
    
    def check_product(self, filename: str) -> bool:
        """Check if the given file has been modified since the canvas was loaded.
        If not, it may mean the file wasn't generated as expected.
        Args:
            filename: The path to the file
        Returns:
            True if the source file has been modified since the canvas was loaded.
        """
        # TODO: Include other validation checks here
        try:
            with curr_work_dir():
                assert os.path.exists(filename), f"File not found: {filename}"
                return self.source_mtime < os.path.getmtime(filename)
        except FileNotFoundError:
            return False
        
    def build_prototype(self, context: Optional[dict] = None) -> list[Node]:
        """Execute all target nodes in the canvas diagram to generate prototypes.
        Args:
            context (dict, optional): Context to pass to the processors. Defaults to None.
        Returns:
            list[Node]: List of built node results (generated prototypes)
        """	
        if context is None:
            context = {"CWD": os.getcwd(), "BASE_PYTHON": sys.executable}
        self.context.update(context)
        logger.info(f"Building {self.source_filename} -> {self.work_filename}") 
        self.save_work_file()
        # Isolated nodes are executed first, then the target nodes
        # No output is generated from isolated nodes, but they can set context
        isolated_nodes = self.find_isolated_nodes()
        target_nodes = self.find_target_nodes()
        self.process_node_list(isolated_nodes)
        target_outputs = self.process_node_list(target_nodes)
        self.save_work_file()
        return target_outputs

    def process_node_list(self, nodes: list[Node]) -> list[Node]:
        """Execute a list of nodes and return the results.	
        Args:
            nodes (list[Node]): List of nodes to execute
        Returns:
            list[Node]: List of results (one for each node usually)
        """
        self.context["NODES"] = nodes
        results = []
        for node in nodes:
            result = self.process_node(node)
            if result is not None:
                results.extend(result)
        return results
    
    def resolve_sigils(self, text: str) -> str:
        """Resolve sigils in the given text using the current context.
        Args:
            text (str): Text to resolve sigils in
        Returns:
            str: Text with sigils resolved
        """
        with sigils.local_context(**self.context):
            return sigils.resolve(text, recursion_limit=0)
    
    def save_node_changes(self, node: Node, status: Status, 
                text: Optional[str] = None, file: Optional[str] = None, 
                _type: Optional[str] = None) -> Node:
        """Save the changes made to a node during execution.
        Args:
            node (Node): Node to save
            status (Status): New status of the node
            text (str, optional): New text of the node. Defaults to None.
            file (str, optional): New file of the node. Defaults to None.
            _type (str, optional): New type of the node. Defaults to None.
        """
        node.set_status(status)
        if text is not None: node.text = text
        if file is not None: node.file = file
        if _type is not None: node.type = _type
        self.save_work_file()
        return node
    
    def find_edge(self, from_node: Node, to_node: Node) -> Optional[Edge]:
        """Find an edge between two nodes.
        Args:
            from_node (Node): Node to start from
            to_node (Node): Node to end at
        Returns:
            Optional[Edge]: The edge between the nodes, or None if no edge exists
        """
        for edge in self.edges:
            if edge.fromNode == from_node.id and edge.toNode == to_node.id:
                return edge
        return None
    
    def process_node(self, node: Node) -> list[Node]:
        """Execute a single node of any node and return the results.
        Args:
            node (Node): Node to execute
        Returns:
            list[Node]: List of results (a single node for most cases)
        """
        if not node.is_canvas():
            if node.get_status() == Status.SUCCESS:
                return [node]
            if node.get_status() == Status.FAILURE:
                return []
        self.context["NODE"] = node
        self.save_node_changes(node, Status.READY)
        upstream_nodes = self.find_upstream_nodes(node)
        input_results = self.process_node_list(upstream_nodes)

        unused_inputs = []
        for input_node in input_results[:]:
            edge = self.find_edge(input_node, node)
            if edge is not None and edge.label:
                edge.label = self.resolve_sigils(edge.label)
                self.context[edge.label.upper().strip()] = input_node
                self.save_work_file()
            else:
                unused_inputs.append(input_node)
        input_results = unused_inputs
        self.context["INPUT"] = input_results[0] if input_results else None
        self.context["INPUTS"] = input_results
        
        if venv_context := self.context.get("VENV"):
            self.context["PYTHON"] = get_local_python(venv_context)
        else:
            self.context["PYTHON"] = sys.executable
        downstream_nodes = self.find_downstream_nodes(node)
        downstream_files = [n.file for n in downstream_nodes if n.is_file()]
        self.context["TARGETS"] = downstream_files
        self.context["TARGET"] = downstream_files[0] if downstream_files else None

        results, status_ok = [], False
        self.save_node_changes(node, Status.ACTIVE)
        with curr_work_dir():   
            # Execution rules are based on node conditions.
            # Type is not used exclusively, for example a file node can be
            # executed as python, markdown, or just copied.

            if node.is_blank():
                # logger.debug(f"Copy output (blank) {self.context['OUTPUTS']}")
                if node.type == "text" or node.is_file("md"):
                    for output_node in self.context["INPUTS"]:
                        # Checking for temp files should be done here
                        with curr_work_dir("Prototypes", "Products"):
                            temp_filename = output_node.build_temp_filename()
                            if os.path.exists(temp_filename):
                                # Read the contents of the temp file
                                with open(temp_filename, "r") as f:
                                    output_node_text = f.read()
                                node.text = "\n".join([node.text, output_node_text]) + "\n"
                                continue
                        if output_node.type == 'text':
                            node.text = "\n".join([node.text, output_node.text]) + "\n"
                        elif output_node.is_file("md", "txt", "log"):
                            node.text = "\n".join([node.text, output_node.read_text_or_file()]) + "\n"
                        elif output_node.is_file():
                            node.text = "\n".join([node.text, f"![{output_node.file}]({output_node.file})"]) + "\n"
                        elif output_node.file:
                            node.text = "\n".join([node.text, f"### {output_node.file}"]) + "\n"

                    if node.text and node.file:
                        # Check if a tempfile was generated and read that instead
                        # Maybe this should be higher up?
                        node_text = node.text
                        
                        if node_text:
                            with curr_work_dir():
                                with open(node.file, "w") as f: f.write(node_text)
                    if node.type == 'text':
                        # Make the header work as a link to the original file
                        link_text = f"[{node.file}]({node.file})"
                        node.text = f"### {link_text}  \n{node.text}"
                    self.save_node_changes(node, Status.SUCCESS)
                    results.append(node)

                elif node.is_file():
                    # If its any other kind of file, loop over the outputs and find the first file
                    # that matches the node file name. If found, copy it to the node file.
                    for output_node in self.context["OUTPUTS"]:
                        if output_node.file == node.file:
                            shutil.copyfile(output_node.file, node.file)
                            self.save_node_changes(node, Status.SUCCESS)
                            results.append(node)
                            break

            elif node.is_markdown():
                # Markdown nodes are executed and the node is updated with the output
                # logger.debug(f"Resolve sigils (markdown) {node.file or '<text>'}")
                node_text = node.read_text_or_file()
                if 'TARGET' in node_text and not self.context.get("TARGET"):
                    with curr_work_dir("Prototypes", "Products"):
                        temp_filename = node.build_temp_filename()
                        self.context["TARGET"] = temp_filename
                        if os.path.exists(temp_filename):
                            os.remove(temp_filename)
                        logger.debug(f"Use temporary TARGET: {temp_filename}")
                # logger.debug(f"Execute (markdown) {node.id}")
                status_ok, markdown_output = self.exec_markdown(node_text)
                if node.file and not markdown_output.startswith("#"):
                    node_filename = node.file.split("/")[-1].split(".")[0]
                    link_text = f"[{node_filename}]({node_filename})"
                    markdown_output = f"## {link_text}\n{markdown_output}"
                node = self.save_node_changes(
                        node, Status.SUCCESS if status_ok else Status.FAILURE,
                        text=markdown_output, _type="text", file=None)
                if status_ok:
                    results.append(node)

            elif node.is_canvas():
                # Canvas nodes are executed and the node is updated with the output
                logger.info(f"Execute (sub-canvas) {node.file}")
                canvas = Canvas(node.file, self.context)
                try:
                    output_nodes = canvas.build_prototype()
                except AbortExecution as e:
                    logger.error(f"Error executing sub-canvas {node.file}: {e}")
                    raise AbortExecution(self, node, e.message) from e
                if output_nodes:
                    node = self.save_node_changes(node, Status.SUCCESS)
                    results.extend(output_nodes)
                else:
                    raise AbortExecution(self, node, "No output from sub-canvas")
                
            elif node.is_script():
                # Script nodes are executed 
                script_filename = node.file
                if not os.path.exists(script_filename):
                    raise AbortExecution(self, node, "Script file not found")
                # logger.debug(f"Execute (script) {node.id}")
                self.save_node_changes(node, Status.ACTIVE)
                return_code, script_out = self.exec_python_script(script_filename)
                if return_code != 0:
                    raise AbortExecution(self, node, script_out)
                self.save_node_changes(node, Status.SUCCESS)

            elif node.is_file():
                # Check the file exists
                with curr_work_dir():
                    if not os.path.exists(node.file):
                        raise AbortExecution(self, node, "File not found")
                self.save_node_changes(node, Status.SUCCESS)
                results.append(node)

            elif node.is_remote():
                # Do nothing for remote nodes for now
                self.save_node_changes(node, Status.SUCCESS)
                results.append(node)
                
            else:
                raise AbortExecution(self, node, "Unhandled node type")

        self.context["OUTPUTS"].extend(results)
        if len(results) > 0:
            self.context["OUTPUT"] = results[0]
        return results  

    def exec_markdown(self, text: str) -> tuple[bool, str]:
        """Process a markdown file and return the results.	
        Args:
            text (str): Markdown text to process
        Returns:
            tuple[bool, str]: Tuple of status and output text
        """
        # TODO: Fix error duplicating output of python scripts
        new_text, ignore_until = "", None
        # logger.info(f"Executing markdown:\n{text}")
        lines = text.splitlines()
        for i, line in enumerate(lines):
            if ignore_until is not None:
                if line.startswith(ignore_until): 
                    ignore_until = None
                continue
            line = self.resolve_sigils(line)
            new_text += line + "\n"
            if line.startswith("#"):
                # Interpret as a section header
                self.context["SECTION"] = line.strip("#").strip()
            elif "=" in line:
                # Interpret as a context assignment
                var, value = line.split("=")
                if var.startswith("-") or var.startswith("+") or var.startswith("*"):
                    var = var[1:]
                self.context[var.strip().upper()] = strip_quotes(value.strip())
            elif line.startswith("```"):
                last_line = i + 1
                try:
                    while not lines[last_line].startswith("```"):
                        last_line += 1
                except IndexError:
                    last_line = len(lines)
                code_block = "\n".join(lines[i+1:last_line])
                if "python" in line:
                    status_ok, output, code_block = self.exec_python_block(code_block)
                    # logger.info(f"Python block output: {output}")
                    output = self.mark_output_block(output.strip())
                    if not status_ok:
                        return False, new_text + f"{code_block.strip()}\n```" + output 
                    new_text = new_text + f"{code_block.strip()}\n```" + output 
                elif "shell" in line:
                    for command_line in code_block.splitlines():
                        command_line = self.resolve_sigils(command_line)
                        return_code, output = self.exec_command_line(command_line)
                        output = self.mark_output_block(output.strip())
                        if return_code != 0:
                            return False,  new_text + f"{code_block.strip()}\n```" + output 
                        new_text = new_text +f"{code_block.strip()}\n```" + output 
                # TODO: If there already is quoted section after the code block, 
                #       don't add another, instead check they are the same
                ignore_until = "```" 
            elif line.startswith("`") and line.endswith("`"):
                # Interpret as a command line
                command_line = line.strip("`")
                return_code, output = self.exec_command_line(command_line)
                new_text += self.mark_output_block(output)
                if return_code != 0:
                    return False, new_text.strip()
        return True, new_text.strip()

    def mark_output_block(self, text: str) -> str:
        """Prepare the output of a code block for markdown.
        This includes parsing the output for sigils and adding to context.
        Args:
            text (str): Text to mark
        Returns:
            str: Text with sigil
        """
        resolved = self.resolve_sigils(text.strip())
        for line in resolved.splitlines():
            if "=" in line:
                var, value = line.split("=", 1)
                if var.startswith("-") or var.startswith("+") or var.startswith("*"):
                    var = var[1:]
                self.context[var.strip().upper()] = strip_quotes(value.strip())
        return markdown_quote(resolved)

    def exec_python_block(self, code: str) -> tuple[bool, str, str]:
        """Execute a Python code block and return the results.
        Args:
            code (str): Python code to execute
        Returns:
            tuple[bool, str]: Status and output
        """
        stdout = io.StringIO()
        stderr = io.StringIO()
        error = None
        tree = ast.parse(code)
        replacements = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Str):
                resolved = self.resolve_sigils(node.s)
                if resolved != node.s:
                    replacements[node.s] = resolved
                    node.s = resolved
        compiled = compile(tree, "<string>", "exec")
        # Apply the replacements to the original code
        for original, replacement in replacements.items():
            code = code.replace(original, replacement)
        try:
            # logger.debug(f"Executing Python code:\n{code}")
            with contextlib.redirect_stdout(stdout):
                with contextlib.redirect_stderr(stderr):
                    with curr_work_dir():
                        exec(compiled, self.context)
        except Exception as e:
            error = e
        stdout_value = stdout.getvalue().strip()
        stderr_value = stderr.getvalue().strip()
        if error is not None or stderr_value:
            logger.warning(f"Python block failed:\n{code}\n{stdout_value}\n{stderr_value}\n{error}")
            return False, f"{stdout_value}{stderr_value}{error or ''}", code
        return True, stdout_value, code

    def exec_python_script(self, script_path: str) -> tuple[int, str]:
        """Execute a script and return the results.	
        Args:
            script_path (str): Path to the script to execute
        Returns:
            tuple[bool, str]: Status and output
        """
        # TODO: Add support for running modules
        python = self.context.get("PYTHON", "python")
        with curr_work_dir():
            return self.exec_command_line(f"{python} {script_path}")
        
    def exec_command_line(self, command_line: str) -> tuple[int, str]:
        """Execute a command line and return the results.
        Args:
            command_line (str): Command line to execute
        Returns:
            tuple[bool, str]: Status and output
        """
        proc = subprocess.run(command_line, shell=True, capture_output=True)
        stdout = proc.stdout.decode('utf-8').strip()
        if proc.returncode != 0:
            stderr = proc.stderr.decode('utf-8').strip()
            stdout = "\n".join([stderr, stdout])
        return proc.returncode, stdout


class AbortExecution(Exception):
    node: Node
    message: str
    canvas: Canvas

    def __init__(self, canvas: Canvas, node: Node, message="Aborting execution"):
        node.set_status(Status.FAILURE)
        self.node = node
        self.canvas = canvas
        self.message = f"[{node.id}] {message}" 
        canvas.save_node_changes(node, Status.FAILURE)
        super().__init__(self.message)


def markdown_quote(text: str) -> str:
    return "\n" + "\n".join(["> " + ln for ln in text.splitlines()]) + "\n"

def markdown_image(image_path: str, caption: str = "") -> str:
    if not caption:
        return f"![{image_path}]({image_path})"
    return f"![{caption}]({image_path})"

def markdown_link(link: str, caption: str = "") -> str:
    if not caption:
        return f"[{link}]({link})"
    return f"[{caption}]({link})"


__all__ = ["Canvas", "AbortExecution"]
