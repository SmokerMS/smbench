#!/usr/bin/env python3
"""SMBench Impacket worker process.

Reads JSON-line requests from stdin, executes SMB operations via Impacket,
and writes JSON-line responses to stdout.

Protocol:
  - One JSON object per line on stdin  (WorkerRequest)
  - One JSON object per line on stdout (WorkerResponse)
  - stderr is used for debug logging only

Requirements:
  pip install impacket
"""

import base64
import json
import os
import sys
import uuid
from typing import Any, Dict, Optional

try:
    from impacket.smbconnection import SMBConnection  # type: ignore
except ImportError:
    SMBConnection = None  # Allow import for protocol testing without impacket


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

connections: Dict[str, Any] = {}  # connection_id -> SMBConnection
handles: Dict[str, Any] = {}      # handle_id -> (connection_id, tree_id, file_id)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def respond(obj: dict) -> None:
    """Write a JSON response line to stdout."""
    line = json.dumps(obj, separators=(",", ":"))
    sys.stdout.write(line + "\n")
    sys.stdout.flush()


def error_response(request_id: str, message: str) -> None:
    respond({"type": "Error", "request_id": request_id, "error": message})


def log(msg: str) -> None:
    """Debug log to stderr."""
    print(f"[worker] {msg}", file=sys.stderr, flush=True)


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------

def handle_connect(msg: dict) -> None:
    request_id = msg["request_id"]
    server = msg["server"]
    share = msg["share"]
    username = msg["username"]
    password = msg["password"]

    if SMBConnection is None:
        error_response(request_id, "impacket not installed")
        return

    try:
        conn = SMBConnection(server, server, sess_port=445)
        conn.login(username, password)
        conn.connectTree(share)
        connection_id = str(uuid.uuid4())
        connections[connection_id] = conn
        respond({
            "type": "Connected",
            "request_id": request_id,
            "connection_id": connection_id,
            "success": True,
            "error": None,
        })
    except Exception as e:
        respond({
            "type": "Connected",
            "request_id": request_id,
            "connection_id": "",
            "success": False,
            "error": str(e),
        })


def handle_open(msg: dict) -> None:
    request_id = msg["request_id"]
    connection_id = msg["connection_id"]
    path = msg["path"]
    mode = msg.get("mode", "ReadWrite")

    conn = connections.get(connection_id)
    if conn is None:
        error_response(request_id, f"Unknown connection_id: {connection_id}")
        return

    try:
        # Map mode to desired access
        if mode == "Read":
            desired_access = 0x80000000  # GENERIC_READ
        elif mode == "Write":
            desired_access = 0x40000000  # GENERIC_WRITE
        else:
            desired_access = 0x80000000 | 0x40000000  # GENERIC_READ | GENERIC_WRITE

        # Open or create file
        tree_id = conn.connectTree(conn.getRemoteHost().split("\\")[-1] if "\\" in conn.getRemoteHost() else "")
        file_id = conn.openFile(tree_id, path, desiredAccess=desired_access)
        handle_id = str(uuid.uuid4())
        handles[handle_id] = (connection_id, tree_id, file_id)

        respond({
            "type": "Opened",
            "request_id": request_id,
            "handle_id": handle_id,
            "success": True,
            "error": None,
        })
    except Exception as e:
        respond({
            "type": "Opened",
            "request_id": request_id,
            "handle_id": "",
            "success": False,
            "error": str(e),
        })


def handle_read(msg: dict) -> None:
    request_id = msg["request_id"]
    handle_id = msg["handle_id"]
    offset = msg["offset"]
    length = msg["length"]

    entry = handles.get(handle_id)
    if entry is None:
        error_response(request_id, f"Unknown handle_id: {handle_id}")
        return

    connection_id, tree_id, file_id = entry
    conn = connections.get(connection_id)
    if conn is None:
        error_response(request_id, f"Connection lost: {connection_id}")
        return

    try:
        data = conn.readFile(tree_id, file_id, offset, length)
        respond({
            "type": "ReadResult",
            "request_id": request_id,
            "data_base64": base64.b64encode(data).decode("ascii"),
            "success": True,
            "error": None,
        })
    except Exception as e:
        respond({
            "type": "ReadResult",
            "request_id": request_id,
            "data_base64": "",
            "success": False,
            "error": str(e),
        })


def handle_write(msg: dict) -> None:
    request_id = msg["request_id"]
    handle_id = msg["handle_id"]
    offset = msg["offset"]
    data_base64 = msg.get("data_base64", "")

    entry = handles.get(handle_id)
    if entry is None:
        error_response(request_id, f"Unknown handle_id: {handle_id}")
        return

    connection_id, tree_id, file_id = entry
    conn = connections.get(connection_id)
    if conn is None:
        error_response(request_id, f"Connection lost: {connection_id}")
        return

    try:
        data = base64.b64decode(data_base64)
        conn.writeFile(tree_id, file_id, data, offset)
        respond({
            "type": "WriteResult",
            "request_id": request_id,
            "bytes_written": len(data),
            "success": True,
            "error": None,
        })
    except Exception as e:
        respond({
            "type": "WriteResult",
            "request_id": request_id,
            "bytes_written": 0,
            "success": False,
            "error": str(e),
        })


def handle_close(msg: dict) -> None:
    request_id = msg["request_id"]
    handle_id = msg["handle_id"]

    entry = handles.pop(handle_id, None)
    if entry is None:
        # Already closed or unknown - treat as success
        respond({
            "type": "Closed",
            "request_id": request_id,
            "success": True,
            "error": None,
        })
        return

    connection_id, tree_id, file_id = entry
    conn = connections.get(connection_id)
    if conn is None:
        respond({
            "type": "Closed",
            "request_id": request_id,
            "success": True,
            "error": None,
        })
        return

    try:
        conn.closeFile(tree_id, file_id)
        respond({
            "type": "Closed",
            "request_id": request_id,
            "success": True,
            "error": None,
        })
    except Exception as e:
        respond({
            "type": "Closed",
            "request_id": request_id,
            "success": False,
            "error": str(e),
        })


def handle_rename(msg: dict) -> None:
    request_id = msg["request_id"]
    connection_id = msg["connection_id"]
    source_path = msg["source_path"]
    dest_path = msg["dest_path"]

    conn = connections.get(connection_id)
    if conn is None:
        error_response(request_id, f"Unknown connection_id: {connection_id}")
        return

    try:
        conn.rename(source_path, dest_path)
        respond({
            "type": "Renamed",
            "request_id": request_id,
            "success": True,
            "error": None,
        })
    except Exception as e:
        respond({
            "type": "Renamed",
            "request_id": request_id,
            "success": False,
            "error": str(e),
        })


def handle_delete(msg: dict) -> None:
    request_id = msg["request_id"]
    connection_id = msg["connection_id"]
    path = msg["path"]

    conn = connections.get(connection_id)
    if conn is None:
        error_response(request_id, f"Unknown connection_id: {connection_id}")
        return

    try:
        conn.deleteFile("", path)
        respond({
            "type": "Deleted",
            "request_id": request_id,
            "success": True,
            "error": None,
        })
    except Exception as e:
        respond({
            "type": "Deleted",
            "request_id": request_id,
            "success": False,
            "error": str(e),
        })


def handle_mkdir(msg: dict) -> None:
    request_id = msg["request_id"]
    connection_id = msg["connection_id"]
    path = msg["path"]

    conn = connections.get(connection_id)
    if conn is None:
        error_response(request_id, f"Unknown connection_id: {connection_id}")
        return

    try:
        conn.createDirectory("", path)
        respond({
            "type": "MkdirResult",
            "request_id": request_id,
            "success": True,
            "error": None,
        })
    except Exception as e:
        respond({
            "type": "MkdirResult",
            "request_id": request_id,
            "success": False,
            "error": str(e),
        })


def handle_rmdir(msg: dict) -> None:
    request_id = msg["request_id"]
    connection_id = msg["connection_id"]
    path = msg["path"]

    conn = connections.get(connection_id)
    if conn is None:
        error_response(request_id, f"Unknown connection_id: {connection_id}")
        return

    try:
        conn.deleteDirectory("", path)
        respond({
            "type": "RmdirResult",
            "request_id": request_id,
            "success": True,
            "error": None,
        })
    except Exception as e:
        respond({
            "type": "RmdirResult",
            "request_id": request_id,
            "success": False,
            "error": str(e),
        })


def handle_shutdown() -> None:
    """Clean up all connections and exit."""
    for handle_id, (connection_id, tree_id, file_id) in list(handles.items()):
        conn = connections.get(connection_id)
        if conn:
            try:
                conn.closeFile(tree_id, file_id)
            except Exception:
                pass
    handles.clear()

    for conn in connections.values():
        try:
            conn.logoff()
            conn.close()
        except Exception:
            pass
    connections.clear()


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

HANDLERS = {
    "Connect": handle_connect,
    "Open": handle_open,
    "Read": handle_read,
    "Write": handle_write,
    "Close": handle_close,
    "Rename": handle_rename,
    "Delete": handle_delete,
    "Mkdir": handle_mkdir,
    "Rmdir": handle_rmdir,
}


def main() -> None:
    log("Worker started")
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        try:
            msg = json.loads(line)
        except json.JSONDecodeError as e:
            log(f"Invalid JSON: {e}")
            continue

        msg_type = msg.get("type", "")

        if msg_type == "Shutdown":
            handle_shutdown()
            log("Shutdown received, exiting")
            break

        handler = HANDLERS.get(msg_type)
        if handler:
            try:
                handler(msg)
            except Exception as e:
                request_id = msg.get("request_id", "unknown")
                error_response(request_id, f"Unhandled error: {e}")
        else:
            request_id = msg.get("request_id", "unknown")
            error_response(request_id, f"Unknown message type: {msg_type}")


if __name__ == "__main__":
    main()
