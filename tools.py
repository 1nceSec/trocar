import asyncio
import json
import os
import re
from pathlib import Path
from config import TEMP_DIR, BASE_DIR

BLOCKED_PATTERNS = [
    re.compile(r"\brm\s+-rf\s+/", re.IGNORECASE),
    re.compile(r"\bmkfs\b", re.IGNORECASE),
    re.compile(r"\bdd\s+if=", re.IGNORECASE),
    re.compile(r"\b(shutdown|reboot|halt|poweroff)\b", re.IGNORECASE),
    re.compile(r"\bformat\s+[a-z]:", re.IGNORECASE),
    re.compile(r">\s*/etc/", re.IGNORECASE),
    re.compile(r"\bnc\s+-[elp]", re.IGNORECASE),
    re.compile(r"\bbash\s+-i\s+>&", re.IGNORECASE),
]

TOOL_DEFINITIONS = [
    {
        "name": "execute_command",
        "description": "Execute a shell command. Use for curl requests, running Python scripts, file operations. All HTTP requests MUST go through Burp proxy.",
        "input_schema": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "The shell command to execute. For HTTP requests use: curl.exe -sk -x http://127.0.0.1:8080 ..."
                },
                "timeout": {
                    "type": "integer",
                    "description": "Timeout in seconds (default 30, max 120)",
                    "default": 30
                }
            },
            "required": ["command"]
        }
    },
    {
        "name": "read_file",
        "description": "Read a file's contents. Use for reading JS files, responses, configs.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "File path to read (relative to session dir, or absolute within allowed paths)"
                },
                "max_lines": {
                    "type": "integer",
                    "description": "Max lines to return (default 200)",
                    "default": 200
                }
            },
            "required": ["path"]
        }
    },
    {
        "name": "write_file",
        "description": "Write content to a file in the session temp directory.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "File path (relative to session dir)"
                },
                "content": {
                    "type": "string",
                    "description": "Content to write"
                }
            },
            "required": ["path", "content"]
        }
    },
    {
        "name": "list_directory",
        "description": "List files in a directory.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Directory path to list"
                }
            },
            "required": ["path"]
        }
    },
    {
        "name": "blackboard_write",
        "description": "Write an entry to the shared blackboard. Partitions: attack_surfaces, verified_findings, pending_hypotheses, exploits, failure_records.",
        "input_schema": {
            "type": "object",
            "properties": {
                "partition": {
                    "type": "string",
                    "enum": ["attack_surfaces", "verified_findings", "pending_hypotheses", "exploits", "failure_records"],
                    "description": "Which blackboard partition to write to"
                },
                "key": {
                    "type": "string",
                    "description": "Unique key for this entry (e.g. endpoint path, vuln name)"
                },
                "value": {
                    "type": "string",
                    "description": "Details about this entry"
                },
                "status": {
                    "type": "string",
                    "enum": ["active", "done", "failed"],
                    "description": "Entry status (default: active)",
                    "default": "active"
                }
            },
            "required": ["partition", "key"]
        }
    },
    {
        "name": "blackboard_read",
        "description": "Read entries from the shared blackboard. Returns all entries or filtered by partition/status.",
        "input_schema": {
            "type": "object",
            "properties": {
                "partition": {
                    "type": "string",
                    "description": "Filter by partition (optional)"
                },
                "status": {
                    "type": "string",
                    "description": "Filter by status (optional)"
                }
            },
            "required": []
        }
    },
]


def _check_command_safety(command: str) -> str | None:
    for pattern in BLOCKED_PATTERNS:
        if pattern.search(command):
            return f"Blocked dangerous pattern: {pattern.pattern}"
    return None


async def execute_command(command: str, timeout: int = 30, cwd: str | None = None) -> dict:
    block_reason = _check_command_safety(command)
    if block_reason:
        return {"success": False, "error": block_reason}

    timeout = min(max(timeout, 5), 120)

    try:
        if os.name == "nt":
            proc = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
            )
        else:
            proc = await asyncio.create_subprocess_exec(
                "/bin/bash", "-c", command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
            )

        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)

        stdout_str = stdout.decode("utf-8", errors="replace")[:50000]
        stderr_str = stderr.decode("utf-8", errors="replace")[:10000]

        return {
            "success": proc.returncode == 0,
            "exit_code": proc.returncode,
            "stdout": stdout_str,
            "stderr": stderr_str,
        }
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:
            pass
        return {"success": False, "error": f"Command timed out after {timeout}s"}
    except Exception as e:
        return {"success": False, "error": str(e)}


async def read_file(path: str, max_lines: int = 200) -> dict:
    try:
        p = Path(path)
        if not p.exists():
            return {"success": False, "error": f"File not found: {path}"}
        if not p.is_file():
            return {"success": False, "error": f"Not a file: {path}"}
        if p.stat().st_size > 10 * 1024 * 1024:
            return {"success": False, "error": "File too large (>10MB)"}

        content = p.read_text(encoding="utf-8", errors="replace")
        lines = content.split("\n")
        truncated = len(lines) > max_lines
        if truncated:
            lines = lines[:max_lines]

        return {
            "success": True,
            "content": "\n".join(lines),
            "total_lines": len(content.split("\n")),
            "truncated": truncated,
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


async def write_file(path: str, content: str, sandbox_root: str | None = None) -> dict:
    try:
        p = Path(path)
        if sandbox_root:
            if not p.is_absolute():
                p = Path(sandbox_root) / p
            resolved = p.resolve()
            sandbox_resolved = Path(sandbox_root).resolve()
            if not str(resolved).startswith(str(sandbox_resolved)):
                return {"success": False, "error": f"Path escapes sandbox: {path}"}
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return {"success": True, "path": str(p), "size": len(content)}
    except Exception as e:
        return {"success": False, "error": str(e)}


async def list_directory(path: str) -> dict:
    try:
        p = Path(path)
        if not p.exists():
            return {"success": False, "error": f"Directory not found: {path}"}
        if not p.is_dir():
            return {"success": False, "error": f"Not a directory: {path}"}

        items = []
        for item in sorted(p.iterdir()):
            try:
                stat = item.stat()
                items.append({
                    "name": item.name,
                    "type": "dir" if item.is_dir() else "file",
                    "size": stat.st_size if item.is_file() else 0,
                })
            except OSError:
                continue

        return {"success": True, "items": items[:500]}
    except Exception as e:
        return {"success": False, "error": str(e)}


async def dispatch_tool(name: str, input_data: dict, session_cwd: str | None = None, session_id: int = 0) -> str:
    if name == "execute_command":
        result = await execute_command(
            input_data["command"],
            input_data.get("timeout", 30),
            cwd=session_cwd,
        )
    elif name == "read_file":
        file_path = input_data["path"]
        if not Path(file_path).is_absolute():
            file_path = str(BASE_DIR / file_path)
        result = await read_file(file_path, input_data.get("max_lines", 200))
    elif name == "write_file":
        result = await write_file(input_data["path"], input_data["content"], sandbox_root=session_cwd)
    elif name == "list_directory":
        dir_path = input_data["path"]
        if not Path(dir_path).is_absolute():
            dir_path = str(BASE_DIR / dir_path)
        result = await list_directory(dir_path)
    elif name == "blackboard_write":
        import db
        rid = await db.bb_write(
            session_id,
            input_data["partition"],
            input_data["key"],
            input_data.get("value", ""),
            input_data.get("status", "active"),
        )
        result = {"success": True, "id": rid, "partition": input_data["partition"], "key": input_data["key"]}
    elif name == "blackboard_read":
        import db
        entries = await db.bb_read(
            session_id,
            input_data.get("partition", ""),
            input_data.get("status", ""),
        )
        result = {"success": True, "count": len(entries), "entries": entries[:50]}
    else:
        result = {"success": False, "error": f"Unknown tool: {name}"}

    return json.dumps(result, ensure_ascii=False, default=str)
