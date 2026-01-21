"""Documentation extractors for Python and SQL."""

from __future__ import annotations

import importlib.util
import inspect
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

import pglast
from pglast.enums import FunctionParameterMode

from .models import ExtractionResult, FunctionDoc


@dataclass
class ParsedDocstring:
    """Simple parsed docstring."""

    brief: str = ""
    params: dict[str, str] = field(default_factory=dict)
    returns: str | None = None
    raises: dict[str, str] = field(default_factory=dict)
    examples: list[str] = field(default_factory=list)


def _dedent_block(text: str) -> str:
    """Dedent a block of text, preserving relative indentation."""
    lines = text.split("\n")
    # Find minimum indentation of non-empty lines
    min_indent = float("inf")
    for line in lines:
        if line.strip():
            indent = len(line) - len(line.lstrip())
            min_indent = min(min_indent, indent)
    if min_indent == float("inf"):
        min_indent = 0
    # Dedent all lines
    dedented = "\n".join(
        line[int(min_indent) :] if len(line) >= min_indent else line for line in lines
    )
    return dedented.strip()


def _extract_params_from_args(args_text: str) -> dict[str, str]:
    """Extract parameters from Args section using indentation-aware parsing.

    Stops at any line with less indentation than the first parameter,
    which indicates a new section (Returns:, Example:, etc.).
    """
    params: dict[str, str] = {}
    current_param: str | None = None
    current_desc_lines: list[str] = []
    base_indent: int | None = None  # Indentation of parameter names

    for line in args_text.split("\n"):
        if not line.strip():
            continue  # Skip blank lines within args

        indent = len(line) - len(line.lstrip())
        stripped = line.lstrip()

        # First non-blank line establishes base indentation
        if base_indent is None:
            base_indent = indent

        # Line at less indentation = new section, stop processing
        if indent < base_indent:
            break

        # Check if this is a parameter line (word: description)
        param_match = re.match(r"^(\w+):\s*(.*)$", stripped)

        if indent == base_indent and param_match:
            # Save previous param
            if current_param:
                params[current_param] = " ".join(current_desc_lines).strip()

            current_param = param_match.group(1)
            desc_start = param_match.group(2).strip()
            current_desc_lines = [desc_start] if desc_start else []
        elif current_param and indent > base_indent:
            # Continuation line (more indented)
            current_desc_lines.append(stripped)
        # Lines at base_indent without param pattern are ignored

    # Save last param
    if current_param:
        params[current_param] = " ".join(current_desc_lines).strip()

    return params


def _parse_docstring(docstring: str | None) -> ParsedDocstring:
    """Parse a Google-style docstring."""
    if not docstring:
        return ParsedDocstring()

    lines = docstring.strip().split("\n")
    result = ParsedDocstring()

    # First non-empty line is brief
    brief_lines = []
    i = 0
    while i < len(lines) and not re.match(
        r"^\s*(Args|Returns|Example|Raises):", lines[i]
    ):
        if lines[i].strip():
            brief_lines.append(lines[i].strip())
        elif brief_lines:
            break
        i += 1
    result.brief = " ".join(brief_lines)

    # Find sections
    text = "\n".join(lines)

    # Args section - capture everything after, helper handles boundaries via indentation
    args_match = re.search(r"Args:\s*\n(.*)", text, re.DOTALL)
    if args_match:
        result.params = _extract_params_from_args(args_match.group(1))

    # Returns section - capture until next section header or end
    returns_match = re.search(
        r"Returns:\s*\n(.*?)(?=\n\s*(?:Args|Examples?|Raises):\s*\n|\Z)",
        text,
        re.DOTALL,
    )
    if returns_match:
        result.returns = _dedent_block(returns_match.group(1))

    # Example section (can be Example: or Examples:)
    example_match = re.search(r"Examples?:\s*\n((?:\s+.*\n?)*)", text)
    if example_match:
        dedented = _dedent_block(example_match.group(1))
        if dedented:
            result.examples.append(dedented)

    return result


def _relative_path(path: Path, root: Path) -> str:
    """Convert absolute path to relative from project root."""
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _load_module(path: Path):
    """Dynamically load a Python module from path.

    For packages with absolute imports (e.g., `from postkit.base import ...`),
    we need to add the package root to sys.path so Python can resolve them.
    """
    # Find package root (parent of postkit/) and add to sys.path
    src_dir = None
    for parent in path.parents:
        if (parent / "postkit" / "__init__.py").exists():
            src_dir = parent
            break

    added_to_path = False
    if src_dir and str(src_dir) not in sys.path:
        sys.path.insert(0, str(src_dir))
        added_to_path = True

    spec = importlib.util.spec_from_file_location("_doc_module", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load module from {path}")
    module = importlib.util.module_from_spec(spec)

    old_module = sys.modules.get("_doc_module")
    try:
        sys.modules["_doc_module"] = module
        spec.loader.exec_module(module)
        return module
    except Exception as e:
        raise ImportError(f"Failed to load {path}: {e.__class__.__name__}: {e}") from e
    finally:
        if old_module is None:
            sys.modules.pop("_doc_module", None)
        else:
            sys.modules["_doc_module"] = old_module
        if added_to_path:
            sys.path.remove(str(src_dir))


def _is_public_method(obj) -> bool:
    """Check if object is a public method (not starting with _)."""
    return inspect.isfunction(obj) and not obj.__name__.startswith("_")


def _format_annotation(ann) -> str:
    """Format an annotation, stripping quotes from string annotations."""
    if ann is inspect.Parameter.empty or ann is inspect.Signature.empty:
        return ""
    if isinstance(ann, str):
        return ann
    if hasattr(ann, "__name__"):
        return ann.__name__
    return str(ann).replace("typing.", "")


def _format_signature(name: str, sig: inspect.Signature) -> str:
    """Format a signature without spurious quotes around type annotations."""
    params = []
    need_star = False

    for p in sig.parameters.values():
        if p.name == "self":
            continue

        if p.kind == inspect.Parameter.KEYWORD_ONLY and not need_star:
            params.append("*")
            need_star = True

        part = p.name
        if p.annotation is not inspect.Parameter.empty:
            part += f": {_format_annotation(p.annotation)}"
        if p.default is not inspect.Parameter.empty:
            default_repr = repr(p.default)
            if default_repr.startswith("<"):
                default_repr = "..."
            part += f" = {default_repr}"

        if p.kind == inspect.Parameter.VAR_POSITIONAL:
            part = f"*{part}"
            need_star = True
        elif p.kind == inspect.Parameter.VAR_KEYWORD:
            part = f"**{part}"

        params.append(part)

    ret = ""
    if sig.return_annotation is not inspect.Signature.empty:
        ret = f" -> {_format_annotation(sig.return_annotation)}"

    return f"{name}({', '.join(params)}){ret}"


def extract_python_docs(client_path: Path, root: Path) -> ExtractionResult:
    """Extract documentation from a Python client file using inspect."""
    module = _load_module(client_path)
    module_name = client_path.parent.name

    docs: list[FunctionDoc] = []
    all_public: list[str] = []

    for _, cls in inspect.getmembers(module, inspect.isclass):
        # Only process classes defined in this module (not imported base classes)
        if cls.__module__ != "_doc_module":
            continue

        for name, method in inspect.getmembers(cls, _is_public_method):
            all_public.append(name)

            sig = inspect.signature(method)
            signature = _format_signature(name, sig)

            try:
                _, lineno = inspect.getsourcelines(method)
            except OSError:
                lineno = 0

            docstring = _parse_docstring(method.__doc__)

            return_type = None
            if sig.return_annotation is not inspect.Signature.empty:
                return_type = _format_annotation(sig.return_annotation)

            docs.append(
                FunctionDoc(
                    name=name,
                    module=module_name,
                    language="python",
                    signature=signature,
                    brief=docstring.brief,
                    params=docstring.params,
                    returns=docstring.returns,
                    return_type=return_type,
                    examples=docstring.examples,
                    source_file=_relative_path(Path(inspect.getfile(method)), root),
                    line_number=lineno,
                )
            )

    docs.sort(key=lambda d: d.name)
    all_public.sort()

    return ExtractionResult(functions=docs, all_public_functions=all_public)


def _type_name_to_str(tn) -> str:
    """Convert pglast TypeName to string."""
    if tn is None:
        return "void"
    names = [n.sval for n in tn.names]
    # Skip common schema prefixes for cleaner output
    if names and names[0] in ("pg_catalog", "public"):
        names = names[1:]
    base = ".".join(names)
    # Handle arrays
    if tn.arrayBounds:
        base += "[]"
    if tn.setof:
        return f"setof {base}"
    return base


def extract_sql_docs(sql_dir: Path, root: Path) -> ExtractionResult:
    """Extract documentation from SQL files using pglast parser."""
    docs: list[FunctionDoc] = []
    all_public: list[str] = []

    for sql_file in sorted(sql_dir.glob("*.sql")):
        content = sql_file.read_text()

        # Extract @group from file header
        group_match = re.search(r"--\s*@group\s+(.+)", content)
        file_group = group_match.group(1).strip() if group_match else None

        # Extract @function doc blocks
        doc_blocks = _extract_doc_blocks(content)
        used_doc_blocks: set[str] = set()

        # Parse SQL with pglast
        try:
            stmts = pglast.parse_sql(content)
        except pglast.Error as e:
            print(f"  ⚠ Failed to parse {sql_file.name}: {e}", file=sys.stderr)
            continue

        for stmt in stmts:
            if not hasattr(stmt, "stmt") or not isinstance(
                stmt.stmt, pglast.ast.CreateFunctionStmt
            ):
                continue

            func = stmt.stmt
            func_name = ".".join(n.sval for n in func.funcname)

            # Skip internal functions
            if "._" in func_name:
                continue

            all_public.append(func_name)

            # Extract parameters (skip TABLE output columns)
            params = []
            table_cols = []
            for p in func.parameters or []:
                if p.name:
                    param_type = _type_name_to_str(p.argType)
                    if p.mode == FunctionParameterMode.FUNC_PARAM_TABLE:
                        table_cols.append(f"{p.name}: {param_type}")
                    else:
                        params.append(f"{p.name}: {param_type}")

            # Extract return type
            if table_cols:
                return_type = f"table({', '.join(table_cols)})"
            else:
                return_type = _type_name_to_str(func.returnType)

            # Get line number
            line_num = content[: stmt.stmt_location].count("\n") + 1

            # Get doc block
            doc_block = doc_blocks.get(func_name)
            if doc_block:
                used_doc_blocks.add(func_name)
                brief = _extract_tag(doc_block, "brief")
                param_docs = _extract_params(doc_block)
                returns_desc = _extract_tag(doc_block, "returns")
                examples = _extract_examples(doc_block)
            else:
                brief = ""
                param_docs = {}
                returns_desc = None
                examples = []

            signature = f"{func_name}({', '.join(params)}) -> {return_type}"

            docs.append(
                FunctionDoc(
                    name=func_name,
                    module=func_name.split(".")[0],
                    language="sql",
                    group=file_group,
                    signature=signature,
                    brief=brief,
                    params=param_docs,
                    returns=returns_desc,
                    return_type=return_type,
                    examples=examples,
                    source_file=_relative_path(sql_file, root),
                    line_number=line_num,
                )
            )

        # Warn about orphaned doc blocks (skip internal functions)
        for name in set(doc_blocks.keys()) - used_doc_blocks:
            if "._" not in name:
                print(
                    f"  ⚠ @function {name} has no matching CREATE FUNCTION in {sql_file.name}",
                    file=sys.stderr,
                )

    docs.sort(key=lambda d: d.name)
    all_public.sort()

    return ExtractionResult(functions=docs, all_public_functions=all_public)


def _extract_doc_blocks(content: str) -> dict[str, str]:
    """Extract @function doc blocks from SQL content."""
    pattern = re.compile(r"--\s*@function\s+(\S+)\s*\n((?:--[^\n]*\n)*)", re.MULTILINE)
    return {m.group(1).strip(): m.group(2) for m in pattern.finditer(content)}


def _extract_tag(block: str, tag: str) -> str:
    """Extract content of an @-tag from a doc block."""
    pattern = rf"--\s*@{re.escape(tag)}\s+(.+?)(?=--\s*@|\Z)"
    match = re.search(pattern, block, re.DOTALL)
    if not match:
        return ""

    lines = match.group(1).strip().split("\n")
    cleaned = [lines[0].strip()]
    for line in lines[1:]:
        line = re.sub(r"^--\s*", "", line)
        if line.strip():
            cleaned.append(line.strip())

    return " ".join(cleaned)


def _extract_params(block: str) -> dict[str, str]:
    """Extract @param tags from a doc block."""
    params: dict[str, str] = {}
    for match in re.finditer(
        r"--\s*@param\s+(\w+)\s+(.+?)(?=--\s*@|\Z)", block, re.DOTALL
    ):
        name = match.group(1)
        desc = re.sub(r"\n--\s*", " ", match.group(2).strip())
        params[name] = desc.strip()
    return params


def _extract_examples(block: str) -> list[str]:
    """Extract @example tags from a doc block."""
    examples = []
    for match in re.finditer(r"--\s*@example\s+(.+?)(?=--\s*@|\Z)", block, re.DOTALL):
        example = re.sub(r"\n--\s*", "\n", match.group(1).strip())
        examples.append(example.strip())
    return examples
