"""
Spec Creation Router
====================

WebSocket and REST endpoints for interactive spec creation with Claude.
"""

import asyncio
import json
import logging
import re
from pathlib import Path
from typing import Any, Optional

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, HTTPException
from pydantic import BaseModel

from ..services.spec_chat_session import (
    SpecChatSession,
    get_session,
    create_session,
    remove_session,
    list_sessions,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/spec", tags=["spec-creation"])

# Root directory
ROOT_DIR = Path(__file__).parent.parent.parent


def _get_project_path(project_name: str) -> Path:
    """Get project path from registry."""
    import sys
    root = Path(__file__).parent.parent.parent
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))

    from registry import get_project_path
    return get_project_path(project_name)


def validate_project_name(name: str) -> bool:
    """Validate project name to prevent path traversal."""
    return bool(re.match(r'^[a-zA-Z0-9_-]{1,50}$', name))


# ============================================================================
# REST Endpoints
# ============================================================================

class SpecSessionStatus(BaseModel):
    """Status of a spec creation session."""
    project_name: str
    is_active: bool
    is_complete: bool
    message_count: int


@router.get("/sessions", response_model=list[str])
async def list_spec_sessions():
    """List all active spec creation sessions."""
    return list_sessions()


@router.get("/sessions/{project_name}", response_model=SpecSessionStatus)
async def get_session_status(project_name: str):
    """Get status of a spec creation session."""
    if not validate_project_name(project_name):
        raise HTTPException(status_code=400, detail="Invalid project name")

    session = get_session(project_name)
    if not session:
        raise HTTPException(status_code=404, detail="No active session for this project")

    return SpecSessionStatus(
        project_name=project_name,
        is_active=True,
        is_complete=session.is_complete(),
        message_count=len(session.get_messages()),
    )


@router.delete("/sessions/{project_name}")
async def cancel_session(project_name: str):
    """Cancel and remove a spec creation session."""
    if not validate_project_name(project_name):
        raise HTTPException(status_code=400, detail="Invalid project name")

    session = get_session(project_name)
    if not session:
        raise HTTPException(status_code=404, detail="No active session for this project")

    await remove_session(project_name)
    return {"success": True, "message": "Session cancelled"}


# ============================================================================
# WebSocket Endpoint
# ============================================================================

@router.websocket("/ws/{project_name}")
async def spec_chat_websocket(websocket: WebSocket, project_name: str):
    """
    WebSocket endpoint for interactive spec creation chat.

    Message protocol:

    Client -> Server:
    - {"type": "start"} - Start the spec creation session
    - {"type": "message", "content": "..."} - Send user message
    - {"type": "answer", "answers": {...}, "tool_id": "..."} - Answer structured question
    - {"type": "ping"} - Keep-alive ping

    Server -> Client:
    - {"type": "text", "content": "..."} - Text chunk from Claude
    - {"type": "question", "questions": [...], "tool_id": "..."} - Structured question
    - {"type": "spec_complete", "path": "..."} - Spec file created
    - {"type": "file_written", "path": "..."} - Other file written
    - {"type": "complete"} - Session complete
    - {"type": "error", "content": "..."} - Error message
    - {"type": "pong"} - Keep-alive pong
    """
    if not validate_project_name(project_name):
        await websocket.close(code=4000, reason="Invalid project name")
        return

    # Look up project directory from registry
    project_dir = _get_project_path(project_name)
    if not project_dir:
        await websocket.close(code=4004, reason="Project not found in registry")
        return

    if not project_dir.exists():
        await websocket.close(code=4004, reason="Project directory not found")
        return

    await websocket.accept()

    session: Optional[SpecChatSession] = None

    try:
        while True:
            try:
                # Receive message from client
                data = await websocket.receive_text()
                message = json.loads(data)
                msg_type = message.get("type")

                if msg_type == "ping":
                    await websocket.send_json({"type": "pong"})
                    continue

                elif msg_type == "start":
                    # Create and start a new session
                    session = await create_session(project_name, project_dir)

                    # Track spec completion state
                    spec_complete_received = False
                    spec_path = None

                    # Stream the initial greeting
                    async for chunk in session.start():
                        # Track spec_complete but don't send complete yet
                        if chunk.get("type") == "spec_complete":
                            spec_complete_received = True
                            spec_path = chunk.get("path")
                            await websocket.send_json(chunk)
                            continue

                        # When response_done arrives, send complete if spec was done
                        if chunk.get("type") == "response_done":
                            await websocket.send_json(chunk)
                            if spec_complete_received:
                                await websocket.send_json({"type": "complete", "path": spec_path})
                            continue

                        await websocket.send_json(chunk)

                elif msg_type == "message":
                    # User sent a message
                    if not session:
                        session = get_session(project_name)
                        if not session:
                            await websocket.send_json({
                                "type": "error",
                                "content": "No active session. Send 'start' first."
                            })
                            continue

                    user_content = message.get("content", "").strip()
                    if not user_content:
                        await websocket.send_json({
                            "type": "error",
                            "content": "Empty message"
                        })
                        continue

                    # Track spec completion state
                    spec_complete_received = False
                    spec_path = None

                    # Stream Claude's response
                    async for chunk in session.send_message(user_content):
                        # Track spec_complete but don't send complete yet
                        if chunk.get("type") == "spec_complete":
                            spec_complete_received = True
                            spec_path = chunk.get("path")
                            await websocket.send_json(chunk)
                            continue

                        # When response_done arrives, send complete if spec was done
                        if chunk.get("type") == "response_done":
                            await websocket.send_json(chunk)
                            if spec_complete_received:
                                await websocket.send_json({"type": "complete", "path": spec_path})
                            continue

                        await websocket.send_json(chunk)

                elif msg_type == "answer":
                    # User answered a structured question
                    if not session:
                        session = get_session(project_name)
                        if not session:
                            await websocket.send_json({
                                "type": "error",
                                "content": "No active session"
                            })
                            continue

                    # Format the answers as a natural response
                    answers = message.get("answers", {})
                    if isinstance(answers, dict):
                        # Convert structured answers to a message
                        response_parts = []
                        for question_idx, answer_value in answers.items():
                            if isinstance(answer_value, list):
                                response_parts.append(", ".join(answer_value))
                            else:
                                response_parts.append(str(answer_value))
                        user_response = "; ".join(response_parts) if response_parts else "OK"
                    else:
                        user_response = str(answers)

                    # Track spec completion state
                    spec_complete_received = False
                    spec_path = None

                    # Stream Claude's response
                    async for chunk in session.send_message(user_response):
                        # Track spec_complete but don't send complete yet
                        if chunk.get("type") == "spec_complete":
                            spec_complete_received = True
                            spec_path = chunk.get("path")
                            await websocket.send_json(chunk)
                            continue

                        # When response_done arrives, send complete if spec was done
                        if chunk.get("type") == "response_done":
                            await websocket.send_json(chunk)
                            if spec_complete_received:
                                await websocket.send_json({"type": "complete", "path": spec_path})
                            continue

                        await websocket.send_json(chunk)

                else:
                    await websocket.send_json({
                        "type": "error",
                        "content": f"Unknown message type: {msg_type}"
                    })

            except json.JSONDecodeError:
                await websocket.send_json({
                    "type": "error",
                    "content": "Invalid JSON"
                })

    except WebSocketDisconnect:
        logger.info(f"Spec chat WebSocket disconnected for {project_name}")

    except Exception as e:
        logger.exception(f"Spec chat WebSocket error for {project_name}")
        try:
            await websocket.send_json({
                "type": "error",
                "content": f"Server error: {str(e)}"
            })
        except Exception:
            pass

    finally:
        # Don't remove the session on disconnect - allow resume
        pass
