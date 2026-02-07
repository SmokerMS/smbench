#!/usr/bin/env python3
"""Mock Impacket worker for testing the JSON-line protocol.

Responds to requests with success responses, no actual SMB operations.
"""

import base64
import json
import sys
import uuid

handle_counter = 0


def respond(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def main() -> None:
    global handle_counter
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        msg = json.loads(line)
        msg_type = msg.get("type", "")
        request_id = msg.get("request_id", "unknown")

        if msg_type == "Connect":
            respond({
                "type": "Connected",
                "request_id": request_id,
                "connection_id": f"conn_{uuid.uuid4().hex[:8]}",
                "success": True,
                "error": None,
            })

        elif msg_type == "Open":
            handle_counter += 1
            respond({
                "type": "Opened",
                "request_id": request_id,
                "handle_id": f"handle_{handle_counter}",
                "success": True,
                "error": None,
            })

        elif msg_type == "Read":
            # Return some test data
            data = b"hello from mock worker"
            respond({
                "type": "ReadResult",
                "request_id": request_id,
                "data_base64": base64.b64encode(data).decode("ascii"),
                "success": True,
                "error": None,
            })

        elif msg_type == "Write":
            data = base64.b64decode(msg.get("data_base64", ""))
            respond({
                "type": "WriteResult",
                "request_id": request_id,
                "bytes_written": len(data),
                "success": True,
                "error": None,
            })

        elif msg_type == "Close":
            respond({
                "type": "Closed",
                "request_id": request_id,
                "success": True,
                "error": None,
            })

        elif msg_type == "Rename":
            respond({
                "type": "Renamed",
                "request_id": request_id,
                "success": True,
                "error": None,
            })

        elif msg_type == "Delete":
            respond({
                "type": "Deleted",
                "request_id": request_id,
                "success": True,
                "error": None,
            })

        elif msg_type == "Mkdir":
            respond({
                "type": "MkdirResult",
                "request_id": request_id,
                "success": True,
                "error": None,
            })

        elif msg_type == "Rmdir":
            respond({
                "type": "RmdirResult",
                "request_id": request_id,
                "success": True,
                "error": None,
            })

        elif msg_type == "QueryDirectory":
            respond({
                "type": "QueryDirectoryResult",
                "request_id": request_id,
                "success": True,
                "error": None,
            })

        elif msg_type == "QueryInfo":
            respond({
                "type": "QueryInfoResult",
                "request_id": request_id,
                "success": True,
                "error": None,
            })

        elif msg_type == "Flush":
            respond({
                "type": "FlushResult",
                "request_id": request_id,
                "success": True,
                "error": None,
            })

        elif msg_type == "Lock":
            respond({
                "type": "LockResult",
                "request_id": request_id,
                "success": True,
                "error": None,
            })

        elif msg_type == "Unlock":
            respond({
                "type": "UnlockResult",
                "request_id": request_id,
                "success": True,
                "error": None,
            })

        elif msg_type == "Ioctl":
            respond({
                "type": "IoctlResult",
                "request_id": request_id,
                "success": True,
                "error": None,
            })

        elif msg_type == "ChangeNotify":
            respond({
                "type": "ChangeNotifyResult",
                "request_id": request_id,
                "success": True,
                "error": None,
            })

        elif msg_type == "Shutdown":
            break

        else:
            respond({
                "type": "Error",
                "request_id": request_id,
                "error": f"Unknown type: {msg_type}",
            })


if __name__ == "__main__":
    main()
