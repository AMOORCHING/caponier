"""
WebSocket module for real-time progress updates in Caponier Security Analysis Platform.

This module provides WebSocket endpoints and handlers for delivering real-time
progress updates to connected clients during repository security analysis.
"""

from .progress import ProgressWebSocketManager

__all__ = ["ProgressWebSocketManager"]
