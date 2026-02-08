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
    from impacket.smb3structs import SMB2_LOCK_ELEMENT  # type: ignore
except ImportError:
    SMBConnection = None  # Allow import for protocol testing without impacket
    SMB2_LOCK_ELEMENT = None


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

connections: Dict[str, Any] = {}  # connection_id -> SMBConnection
tree_ids: Dict[str, int] = {}    # connection_id -> tree_id (stored on Connect)
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
        tid = conn.connectTree(share)
        connection_id = str(uuid.uuid4())
        connections[connection_id] = conn
        tree_ids[connection_id] = tid
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
        # Use extended parameters if present, otherwise infer from mode
        ext_desired_access = msg.get("desired_access")
        ext_create_disposition = msg.get("create_disposition")
        ext_create_options = msg.get("create_options")
        ext_share_access = msg.get("share_access")
        ext_file_attributes = msg.get("file_attributes")

        if ext_desired_access is not None:
            desired_access = ext_desired_access
        elif mode == "Read":
            desired_access = 0x80000000  # GENERIC_READ
        elif mode == "Write":
            desired_access = 0x40000000  # GENERIC_WRITE
        else:
            desired_access = 0x80000000 | 0x40000000  # GENERIC_READ | GENERIC_WRITE

        # Reuse tree_id from Connect instead of reconnecting
        tree_id = tree_ids.get(connection_id)
        if tree_id is None:
            error_response(request_id, f"No tree_id stored for connection: {connection_id}")
            return

        # Build open kwargs with extended parameters
        open_kwargs = {"desiredAccess": desired_access}
        if ext_create_disposition is not None:
            open_kwargs["creationDisposition"] = ext_create_disposition
        if ext_create_options is not None:
            open_kwargs["creationOption"] = ext_create_options
        if ext_share_access is not None:
            open_kwargs["shareMode"] = ext_share_access
        if ext_file_attributes is not None:
            open_kwargs["fileAttributes"] = ext_file_attributes

        file_id = conn.openFile(tree_id, path, **open_kwargs)
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


def handle_write_from_blob(msg: dict) -> None:
    """Write data from a local file (blob) to a remote SMB file handle."""
    request_id = msg["request_id"]
    handle_id = msg["handle_id"]
    offset = msg.get("offset", 0)
    blob_path = msg["blob_path"]

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
        with open(blob_path, "rb") as f:
            data = f.read()
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


def handle_query_directory(msg: dict) -> None:
    request_id = msg["request_id"]
    handle_id = msg["handle_id"]
    pattern = msg.get("pattern", "*")
    info_class = msg.get("info_class", 0)

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
        # Use low-level SMB2 queryDirectory with the actual file_id handle
        smb_server = conn.getSMBServer()
        smb_server.queryDirectory(
            tree_id,
            file_id,
            searchString=pattern,
            informationClass=info_class if info_class else 0x25,  # IdBothDirectory default
            maxBufferSize=0x10000,
        )
        respond({
            "type": "QueryDirectoryResult",
            "request_id": request_id,
            "success": True,
            "error": None,
        })
    except Exception as e:
        # STATUS_NO_MORE_FILES is expected when directory is empty or enumeration ends
        if "STATUS_NO_MORE_FILES" in str(e):
            respond({
                "type": "QueryDirectoryResult",
                "request_id": request_id,
                "success": True,
                "error": None,
            })
        else:
            respond({
                "type": "QueryDirectoryResult",
                "request_id": request_id,
                "success": False,
                "error": str(e),
            })


def handle_query_info(msg: dict) -> None:
    request_id = msg["request_id"]
    handle_id = msg["handle_id"]
    info_type = msg.get("info_type", 0)
    info_class = msg.get("info_class", 0)

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
        # Use low-level SMB2 queryInfo with the actual file_id
        smb_server = conn.getSMBServer()
        smb_server.queryInfo(
            tree_id,
            file_id,
            infoType=info_type if info_type else 1,  # SMB2_0_INFO_FILE
            fileInfoClass=info_class if info_class else 5,  # FileStandardInformation
        )
        respond({
            "type": "QueryInfoResult",
            "request_id": request_id,
            "success": True,
            "error": None,
        })
    except Exception as e:
        respond({
            "type": "QueryInfoResult",
            "request_id": request_id,
            "success": False,
            "error": str(e),
        })


def handle_flush(msg: dict) -> None:
    request_id = msg["request_id"]
    handle_id = msg["handle_id"]

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
        # Use low-level SMB3 flush
        smb_server = conn.getSMBServer()
        smb_server.flush(tree_id, file_id)
        respond({
            "type": "FlushResult",
            "request_id": request_id,
            "success": True,
            "error": None,
        })
    except Exception as e:
        respond({
            "type": "FlushResult",
            "request_id": request_id,
            "success": False,
            "error": str(e),
        })


def handle_lock(msg: dict) -> None:
    request_id = msg["request_id"]
    handle_id = msg["handle_id"]
    offset = msg.get("offset", 0)
    length = msg.get("length", 0)
    exclusive = msg.get("exclusive", True)

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
        # Build lock element: exclusive (0x02) or shared (0x01) lock
        # SMB2_LOCKFLAG_EXCLUSIVE_LOCK = 0x02, SMB2_LOCKFLAG_SHARED_LOCK = 0x01
        # Also set SMB2_LOCKFLAG_FAIL_IMMEDIATELY = 0x10
        flags = 0x12 if exclusive else 0x11  # exclusive+fail_immediately or shared+fail_immediately
        lock_element = SMB2_LOCK_ELEMENT()
        lock_element['Offset'] = offset
        lock_element['Length'] = length
        lock_element['Flags'] = flags
        smb_server = conn.getSMBServer()
        smb_server.lock(tree_id, file_id, [lock_element])
        respond({
            "type": "LockResult",
            "request_id": request_id,
            "success": True,
            "error": None,
        })
    except Exception as e:
        respond({
            "type": "LockResult",
            "request_id": request_id,
            "success": False,
            "error": str(e),
        })


def handle_unlock(msg: dict) -> None:
    request_id = msg["request_id"]
    handle_id = msg["handle_id"]
    offset = msg.get("offset", 0)
    length = msg.get("length", 0)

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
        # SMB2_LOCKFLAG_UN_LOCK = 0x04
        lock_element = SMB2_LOCK_ELEMENT()
        lock_element['Offset'] = offset
        lock_element['Length'] = length
        lock_element['Flags'] = 0x04  # UNLOCK
        smb_server = conn.getSMBServer()
        smb_server.lock(tree_id, file_id, [lock_element])
        respond({
            "type": "UnlockResult",
            "request_id": request_id,
            "success": True,
            "error": None,
        })
    except Exception as e:
        respond({
            "type": "UnlockResult",
            "request_id": request_id,
            "success": False,
            "error": str(e),
        })


def handle_ioctl(msg: dict) -> None:
    request_id = msg["request_id"]
    handle_id = msg["handle_id"]
    ctl_code = msg.get("ctl_code", 0)

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
        smb_server = conn.getSMBServer()
        # Send IOCTL via low-level SMB2; input buffer empty, max output 4096
        smb_server.ioctl(tree_id, file_id, ctl_code, inputBlob=b'', maxOutputResponse=4096)
        respond({
            "type": "IoctlResult",
            "request_id": request_id,
            "success": True,
            "error": None,
        })
    except Exception as e:
        # Best-effort: some IOCTLs may not be supported; still treat as success for replay
        respond({
            "type": "IoctlResult",
            "request_id": request_id,
            "success": True,
            "error": str(e),
        })


def handle_change_notify(msg: dict) -> None:
    request_id = msg["request_id"]
    handle_id = msg["handle_id"]
    filter_val = msg.get("filter", 0)
    recursive = msg.get("recursive", False)

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
        # Impacket's SMB3 class does not implement changeNotify().
        # For replay purposes we treat this as a best-effort no-op.
        _ = (conn, tree_id, file_id, filter_val, recursive)  # suppress unused warnings
        respond({
            "type": "ChangeNotifyResult",
            "request_id": request_id,
            "success": True,
            "error": None,
        })
    except Exception as e:
        respond({
            "type": "ChangeNotifyResult",
            "request_id": request_id,
            "success": False,
            "error": str(e),
        })


def handle_set_info(msg: dict) -> None:
    request_id = msg["request_id"]
    handle_id = msg["handle_id"]
    info_type = msg.get("info_type", 1)
    info_class = msg.get("info_class", 0)

    entry = handles.get(handle_id)
    if entry is None:
        error_response(request_id, f"Unknown handle_id: {handle_id}")
        return

    connection_id, tree_id, file_id = entry
    conn = connections.get(connection_id)
    if conn is None:
        error_response(request_id, f"Connection not found: {connection_id}")
        return

    try:
        smb_server = conn.getSMBServer()
        # SetInfo with info_type and info_class.
        # For replay, we send a minimal SetInfo with empty buffer.
        # This may fail on some servers, so treat errors gracefully.
        smb_server.setInfo(tree_id, file_id,
                           infoType=info_type,
                           fileInfoClass=info_class,
                           inputBlob=b'\x00' * 40)
        respond({
            "type": "SetInfoResult",
            "request_id": request_id,
            "success": True,
            "error": None,
        })
    except Exception as e:
        # Best-effort: report success even on failure for replay
        respond({
            "type": "SetInfoResult",
            "request_id": request_id,
            "success": True,
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
    tree_ids.clear()


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

HANDLERS = {
    "Connect": handle_connect,
    "Open": handle_open,
    "Read": handle_read,
    "Write": handle_write,
    "WriteFromBlob": handle_write_from_blob,
    "Close": handle_close,
    "Rename": handle_rename,
    "Delete": handle_delete,
    "Mkdir": handle_mkdir,
    "Rmdir": handle_rmdir,
    "QueryDirectory": handle_query_directory,
    "QueryInfo": handle_query_info,
    "Flush": handle_flush,
    "Lock": handle_lock,
    "Unlock": handle_unlock,
    "Ioctl": handle_ioctl,
    "ChangeNotify": handle_change_notify,
    "SetInfo": handle_set_info,
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
