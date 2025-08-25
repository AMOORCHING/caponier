"""
WebSocket progress manager for real-time analysis updates.

This module handles WebSocket connections and broadcasts progress updates
to connected clients during repository security analysis.
"""

import asyncio
import json
import logging
from typing import Dict, Set, Optional, Any, List
from datetime import datetime, timedelta
from collections import defaultdict
from fastapi import WebSocket, WebSocketDisconnect, HTTPException
from pydantic import BaseModel
from .progress_events import ProgressEvent, ProgressEventFactory, AnalysisStage

logger = logging.getLogger(__name__)


class ProgressMessage(BaseModel):
    """Model for progress update messages sent via WebSocket."""
    job_id: str
    status: str
    progress: int
    message: str
    stage: str
    timestamp: datetime
    details: Optional[Dict[str, Any]] = None


class ProgressWebSocketManager:
    """
    Manages WebSocket connections and broadcasts progress updates.
    
    This class handles:
    - WebSocket connection management
    - Progress message broadcasting with retry logic
    - Connection cleanup and error handling
    - Job-specific connection tracking
    - Message queuing for offline clients
    - Broadcasting performance optimization
    - Connection state tracking and reconnection support
    - Heartbeat monitoring and health checks
    """
    
    def __init__(self):
        """Initialize the WebSocket manager."""
        self.active_connections: Dict[str, Set[WebSocket]] = {}
        self.connection_jobs: Dict[WebSocket, str] = {}
        self.connection_metadata: Dict[WebSocket, Dict[str, Any]] = {}
        self.connection_states: Dict[WebSocket, str] = {}  # connected, disconnected, reconnecting
        self.message_queue: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.priority_queue: Dict[str, List[Dict[str, Any]]] = defaultdict(list)  # High-priority messages
        self.broadcast_stats: Dict[str, Dict[str, int]] = defaultdict(lambda: {"sent": 0, "failed": 0, "queued": 0})
        self.performance_stats: Dict[str, Dict[str, float]] = defaultdict(lambda: {"avg_delivery_time": 0.0, "max_delivery_time": 0.0, "min_delivery_time": float('inf')})
        self.reconnection_attempts: Dict[WebSocket, int] = {}
        self.lock = asyncio.Lock()
        
        # Configuration
        self.max_queue_size = 50  # Maximum messages to queue per job
        self.max_retry_attempts = 3
        self.retry_delay = 0.1  # seconds
        self.broadcast_timeout = 1.5  # seconds (reduced for 2-second requirement)
        self.heartbeat_interval = 30  # seconds
        self.max_reconnection_attempts = 3
        self.reconnection_delay = 1.0  # seconds
        self.connection_timeout = 300  # seconds (5 minutes)
        self.max_delivery_time = 2.0  # seconds (target delivery time)
        self.priority_queue_size = 10  # High-priority queue size
    
    async def connect(self, websocket: WebSocket, job_id: str, is_reconnection: bool = False) -> bool:
        """
        Accept a new WebSocket connection for a specific job.
        
        Args:
            websocket: The WebSocket connection
            job_id: The job ID to track progress for
            is_reconnection: Whether this is a reconnection attempt
            
        Returns:
            bool: True if connection was successful, False otherwise
        """
        try:
            await websocket.accept()
            
            async with self.lock:
                if job_id not in self.active_connections:
                    self.active_connections[job_id] = set()
                
                self.active_connections[job_id].add(websocket)
                self.connection_jobs[websocket] = job_id
                self.connection_states[websocket] = "connected"
                
                # Store connection metadata
                self.connection_metadata[websocket] = {
                    "connected_at": datetime.utcnow(),
                    "job_id": job_id,
                    "last_activity": datetime.utcnow(),
                    "message_count": 0,
                    "failed_messages": 0,
                    "is_reconnection": is_reconnection,
                    "reconnection_count": self.reconnection_attempts.get(websocket, 0)
                }
                
                # Reset reconnection attempts on successful connection
                if websocket in self.reconnection_attempts:
                    del self.reconnection_attempts[websocket]
            
            # Send any queued messages for this job
            await self._send_queued_messages(job_id, websocket)
            
            # Send connection status message
            await self._send_connection_status(websocket, "connected", is_reconnection)
            
            logger.info(f"WebSocket {'reconnected' if is_reconnection else 'connected'} for job {job_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to accept WebSocket connection for job {job_id}: {e}")
            return False
    
    async def disconnect(self, websocket: WebSocket, reason: str = "disconnected") -> None:
        """
        Remove a WebSocket connection and clean up references.
        
        Args:
            websocket: The WebSocket connection to disconnect
            reason: Reason for disconnection
        """
        async with self.lock:
            job_id = self.connection_jobs.get(websocket)
            if job_id:
                # Update connection state
                self.connection_states[websocket] = "disconnected"
                
                if job_id in self.active_connections:
                    self.active_connections[job_id].discard(websocket)
                    
                    # Clean up empty job sets
                    if not self.active_connections[job_id]:
                        del self.active_connections[job_id]
                
                del self.connection_jobs[websocket]
                
                # Clean up connection metadata
                if websocket in self.connection_metadata:
                    metadata = self.connection_metadata[websocket]
                    logger.info(f"WebSocket {reason} from job {job_id} (messages: {metadata['message_count']}, failed: {metadata['failed_messages']})")
                    del self.connection_metadata[websocket]
                else:
                    logger.info(f"WebSocket {reason} from job {job_id}")
                
                # Clean up connection state
                if websocket in self.connection_states:
                    del self.connection_states[websocket]
    
    async def mark_for_reconnection(self, websocket: WebSocket) -> None:
        """
        Mark a WebSocket connection for potential reconnection.
        
        Args:
            websocket: The WebSocket connection
        """
        job_id = self.connection_jobs.get(websocket)
        if job_id:
            current_attempts = self.reconnection_attempts.get(websocket, 0)
            if current_attempts < self.max_reconnection_attempts:
                self.reconnection_attempts[websocket] = current_attempts + 1
                self.connection_states[websocket] = "reconnecting"
                logger.info(f"Marked WebSocket for reconnection (attempt {current_attempts + 1}/{self.max_reconnection_attempts}) for job {job_id}")
            else:
                logger.warning(f"Max reconnection attempts reached for WebSocket in job {job_id}")
                await self.disconnect(websocket, "max_reconnection_attempts_reached")
    
    async def broadcast_progress(self, job_id: str, progress_message: ProgressMessage) -> None:
        """
        Broadcast a progress message to all connected clients for a specific job.
        
        Args:
            job_id: The job ID to broadcast to
            progress_message: The progress message to send
        """
        start_time = datetime.utcnow()
        
        if job_id not in self.active_connections:
            # Queue message for future connections
            await self._queue_message(job_id, progress_message, is_priority=True)
            return
        
        # Convert message to JSON
        message_data = progress_message.dict()
        message_json = json.dumps(message_data)
        
        # Get connections to broadcast to
        connections = self.active_connections[job_id].copy()
        
        if not connections:
            # Queue message if no active connections
            await self._queue_message(job_id, progress_message, is_priority=True)
            return
        
        # Determine if this is a high-priority message (completion, error, etc.)
        is_priority = self._is_priority_message(progress_message)
        
        # Broadcast to all connected clients with optimized delivery
        delivery_tasks = []
        for websocket in connections:
            task = asyncio.create_task(
                self._send_with_retry_optimized(websocket, message_json, job_id, start_time)
            )
            delivery_tasks.append(task)
        
        # Wait for all broadcasts to complete with strict timeout
        try:
            results = await asyncio.wait_for(
                asyncio.gather(*delivery_tasks, return_exceptions=True),
                timeout=self.broadcast_timeout
            )
            
            # Calculate delivery performance
            delivery_time = (datetime.utcnow() - start_time).total_seconds()
            await self._update_performance_stats(job_id, delivery_time)
            
            # Log performance metrics
            if delivery_time > self.max_delivery_time:
                logger.warning(f"Progress update delivery exceeded 2-second target: {delivery_time:.3f}s for job {job_id}")
            else:
                logger.debug(f"Progress update delivered in {delivery_time:.3f}s for job {job_id}")
            
        except asyncio.TimeoutError:
            logger.error(f"Broadcast timeout ({self.broadcast_timeout}s) exceeded for job {job_id}")
            # Mark slow connections for potential cleanup
            await self._mark_slow_connections(job_id, connections)
        
        # Update broadcast statistics
        await self._update_broadcast_stats(job_id, len(connections))
        
        # Clean up any disconnected websockets
        await self._cleanup_disconnected_connections(job_id)
    
    async def _send_with_retry_optimized(self, websocket: WebSocket, message: str, job_id: str, start_time: datetime) -> bool:
        """
        Send message to WebSocket with optimized retry logic for fast delivery.
        
        Args:
            websocket: The WebSocket connection
            message: The message to send
            job_id: The job ID for logging
            start_time: Start time for delivery tracking
            
        Returns:
            bool: True if sent successfully, False otherwise
        """
        for attempt in range(self.max_retry_attempts):
            try:
                # Check if we're approaching the 2-second limit
                elapsed_time = (datetime.utcnow() - start_time).total_seconds()
                if elapsed_time > self.max_delivery_time * 0.8:  # 80% of max time
                    logger.warning(f"Approaching delivery time limit ({elapsed_time:.3f}s) for job {job_id}")
                
                await websocket.send_text(message)
                
                # Update connection metadata
                if websocket in self.connection_metadata:
                    self.connection_metadata[websocket]["last_activity"] = datetime.utcnow()
                    self.connection_metadata[websocket]["message_count"] += 1
                
                return True
                
            except Exception as e:
                if attempt < self.max_retry_attempts - 1:
                    # Use shorter delays for faster retry
                    await asyncio.sleep(self.retry_delay * (0.5 ** attempt))  # Exponential backoff
                    continue
                else:
                    logger.warning(f"Failed to send message to WebSocket for job {job_id} after {self.max_retry_attempts} attempts: {e}")
                    
                    # Update connection metadata
                    if websocket in self.connection_metadata:
                        self.connection_metadata[websocket]["failed_messages"] += 1
                    
                    return False
        
        return False
    
    def _is_priority_message(self, progress_message: ProgressMessage) -> bool:
        """
        Determine if a progress message is high priority.
        
        Args:
            progress_message: The progress message to check
            
        Returns:
            bool: True if high priority
        """
        # High priority stages
        priority_stages = [
            "completion", "error", "retry", "initialization"
        ]
        
        return progress_message.stage in priority_stages or progress_message.progress_percentage in [0, 100]
    
    async def _update_performance_stats(self, job_id: str, delivery_time: float) -> None:
        """
        Update performance statistics for a job.
        
        Args:
            job_id: The job ID
            delivery_time: Delivery time in seconds
        """
        stats = self.performance_stats[job_id]
        
        # Update min/max delivery times
        if delivery_time < stats["min_delivery_time"]:
            stats["min_delivery_time"] = delivery_time
        if delivery_time > stats["max_delivery_time"]:
            stats["max_delivery_time"] = delivery_time
        
        # Update average delivery time (simple moving average)
        current_avg = stats["avg_delivery_time"]
        message_count = self.broadcast_stats[job_id]["sent"]
        
        if message_count == 0:
            stats["avg_delivery_time"] = delivery_time
        else:
            stats["avg_delivery_time"] = (current_avg * (message_count - 1) + delivery_time) / message_count
    
    async def _mark_slow_connections(self, job_id: str, connections: Set[WebSocket]) -> None:
        """
        Mark slow connections for potential cleanup.
        
        Args:
            job_id: The job ID
            connections: Set of connections to check
        """
        for websocket in connections:
            if websocket in self.connection_metadata:
                metadata = self.connection_metadata[websocket]
                failed_count = metadata.get("failed_messages", 0)
                total_count = metadata.get("message_count", 0) + failed_count
                
                # Mark for cleanup if failure rate is high
                if total_count > 10 and (failed_count / total_count) > 0.3:
                    logger.warning(f"Marking slow connection for cleanup in job {job_id} (failure rate: {failed_count/total_count:.2%})")
                    await self.mark_for_reconnection(websocket)
    
    async def _queue_message(self, job_id: str, progress_message: ProgressMessage, is_priority: bool = False) -> None:
        """
        Queue a message for a job when no active connections exist.
        
        Args:
            job_id: The job ID
            progress_message: The progress message to queue
            is_priority: Whether this is a priority message
        """
        message_data = progress_message.dict()
        
        async with self.lock:
            if is_priority:
                # Add to priority queue
                if len(self.priority_queue[job_id]) < self.priority_queue_size:
                    self.priority_queue[job_id].append(message_data)
                    self.broadcast_stats[job_id]["queued"] += 1
                    logger.debug(f"Queued priority message for job {job_id}")
                else:
                    # Remove oldest priority message if queue is full
                    self.priority_queue[job_id].pop(0)
                    self.priority_queue[job_id].append(message_data)
                    logger.debug(f"Replaced oldest priority message for job {job_id}")
            else:
                # Add to regular queue
                if len(self.message_queue[job_id]) < self.max_queue_size:
                    self.message_queue[job_id].append(message_data)
                    self.broadcast_stats[job_id]["queued"] += 1
                    logger.debug(f"Queued message for job {job_id}")
                else:
                    # Remove oldest message if queue is full
                    self.message_queue[job_id].pop(0)
                    self.message_queue[job_id].append(message_data)
                    logger.debug(f"Replaced oldest queued message for job {job_id}")
    
    async def _send_queued_messages(self, job_id: str, websocket: WebSocket) -> None:
        """
        Send queued messages to a newly connected client.
        
        Args:
            job_id: The job ID
            websocket: The WebSocket connection
        """
        async with self.lock:
            priority_messages = self.priority_queue[job_id].copy()
            regular_messages = self.message_queue[job_id].copy()
        
        total_messages = len(priority_messages) + len(regular_messages)
        if total_messages > 0:
            logger.info(f"Sending {total_messages} queued messages ({len(priority_messages)} priority) to new connection for job {job_id}")
            
            # Send priority messages first
            for message_data in priority_messages:
                try:
                    message_json = json.dumps(message_data)
                    await websocket.send_text(message_json)
                    await asyncio.sleep(0.005)  # Shorter delay for priority messages
                except Exception as e:
                    logger.warning(f"Failed to send priority queued message to WebSocket for job {job_id}: {e}")
                    break
            
            # Send regular messages
            for message_data in regular_messages:
                try:
                    message_json = json.dumps(message_data)
                    await websocket.send_text(message_json)
                    await asyncio.sleep(0.01)  # Small delay between messages
                except Exception as e:
                    logger.warning(f"Failed to send queued message to WebSocket for job {job_id}: {e}")
                    break
    
    async def _update_broadcast_stats(self, job_id: str, connection_count: int) -> None:
        """
        Update broadcasting statistics.
        
        Args:
            job_id: The job ID
            connection_count: Number of connections that received the message
        """
        self.broadcast_stats[job_id]["sent"] += connection_count
    
    async def _cleanup_disconnected_connections(self, job_id: str) -> None:
        """
        Clean up any disconnected WebSocket connections.
        
        Args:
            job_id: The job ID
        """
        if job_id not in self.active_connections:
            return
        
        connections = self.active_connections[job_id].copy()
        disconnected = set()
        
        for websocket in connections:
            try:
                # Try to send a ping to check connection health
                await websocket.ping()
            except Exception:
                disconnected.add(websocket)
        
        # Clean up disconnected websockets
        for websocket in disconnected:
            await self.disconnect(websocket)
    
    async def send_immediate_progress(
        self, 
        job_id: str, 
        status: str, 
        progress: int, 
        message: str, 
        stage: str,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Send an immediate progress update for a job.
        
        Args:
            job_id: The job ID
            status: Current job status
            progress: Progress percentage (0-100)
            message: Human-readable progress message
            stage: Current analysis stage
            details: Optional additional details
        """
        progress_message = ProgressMessage(
            job_id=job_id,
            status=status,
            progress=progress,
            message=message,
            stage=stage,
            timestamp=datetime.utcnow(),
            details=details
        )
        
        await self.broadcast_progress(job_id, progress_message)
    
    async def send_progress_event(self, job_id: str, progress_event: ProgressEvent) -> None:
        """
        Send a structured progress event for a job.
        
        Args:
            job_id: The job ID
            progress_event: The progress event to send
        """
        try:
            # Convert progress event to message format
            status = self._get_status_from_stage(progress_event.stage)
            
            progress_message = ProgressMessage(
                job_id=job_id,
                status=status,
                progress=progress_event.progress_percentage,
                message=progress_event.message,
                stage=progress_event.stage.value,
                timestamp=progress_event.timestamp,
                details=progress_event.details
            )
            
            await self.broadcast_progress(job_id, progress_message)
            
        except Exception as e:
            logger.warning(f"Failed to send progress event for job {job_id}: {e}")
    
    def _get_status_from_stage(self, stage: AnalysisStage) -> str:
        """
        Determine status from analysis stage.
        
        Args:
            stage: The analysis stage
            
        Returns:
            Status string for the stage
        """
        if stage == AnalysisStage.COMPLETION:
            return "completed"
        elif stage == AnalysisStage.ERROR:
            return "failed"
        elif stage == AnalysisStage.RETRY:
            return "retrying"
        elif stage == AnalysisStage.INITIALIZATION:
            return "pending"
        else:
            return "in_progress"
    
    def get_connection_count(self, job_id: str) -> int:
        """
        Get the number of active connections for a job.
        
        Args:
            job_id: The job ID
            
        Returns:
            int: Number of active connections
        """
        return len(self.active_connections.get(job_id, set()))
    
    def get_total_connections(self) -> int:
        """
        Get the total number of active WebSocket connections.
        
        Returns:
            int: Total number of active connections
        """
        return len(self.connection_jobs)
    
    def get_broadcast_stats(self, job_id: str = None) -> Dict[str, Any]:
        """
        Get broadcasting statistics.
        
        Args:
            job_id: Optional job ID to get stats for specific job
            
        Returns:
            Dictionary with broadcasting statistics
        """
        if job_id:
            return {
                "job_id": job_id,
                "stats": self.broadcast_stats.get(job_id, {"sent": 0, "failed": 0, "queued": 0}),
                "performance": self.performance_stats.get(job_id, {"avg_delivery_time": 0.0, "max_delivery_time": 0.0, "min_delivery_time": float('inf')}),
                "active_connections": self.get_connection_count(job_id),
                "queued_messages": len(self.message_queue.get(job_id, [])),
                "priority_messages": len(self.priority_queue.get(job_id, []))
            }
        else:
            return {
                "total_connections": self.get_total_connections(),
                "active_jobs": len(self.active_connections),
                "total_stats": {
                    "sent": sum(stats["sent"] for stats in self.broadcast_stats.values()),
                    "failed": sum(stats["failed"] for stats in self.broadcast_stats.values()),
                    "queued": sum(stats["queued"] for stats in self.broadcast_stats.values())
                },
                "performance_summary": {
                    "avg_delivery_time": sum(stats["avg_delivery_time"] for stats in self.performance_stats.values()) / max(len(self.performance_stats), 1),
                    "max_delivery_time": max((stats["max_delivery_time"] for stats in self.performance_stats.values()), default=0.0),
                    "jobs_within_target": sum(1 for stats in self.performance_stats.values() if stats["avg_delivery_time"] <= self.max_delivery_time)
                },
                "job_stats": dict(self.broadcast_stats),
                "performance_stats": dict(self.performance_stats)
            }
    
    def get_connection_health(self, job_id: str = None) -> Dict[str, Any]:
        """
        Get connection health information.
        
        Args:
            job_id: Optional job ID to get health for specific job
            
        Returns:
            Dictionary with connection health information
        """
        if job_id and job_id in self.active_connections:
            connections = self.active_connections[job_id]
            health_data = []
            
            for websocket in connections:
                metadata = self.connection_metadata.get(websocket, {})
                health_data.append({
                    "connected_at": metadata.get("connected_at"),
                    "last_activity": metadata.get("last_activity"),
                    "message_count": metadata.get("message_count", 0),
                    "failed_messages": metadata.get("failed_messages", 0),
                    "success_rate": self._calculate_success_rate(metadata)
                })
            
            return {
                "job_id": job_id,
                "connection_count": len(connections),
                "connections": health_data
            }
        else:
            return {
                "total_connections": self.get_total_connections(),
                "active_jobs": len(self.active_connections),
                "connection_details": {
                    job_id: len(connections) for job_id, connections in self.active_connections.items()
                }
            }
    
    def _calculate_success_rate(self, metadata: Dict[str, Any]) -> float:
        """
        Calculate message success rate for a connection.
        
        Args:
            metadata: Connection metadata
            
        Returns:
            float: Success rate as percentage
        """
        total_messages = metadata.get("message_count", 0) + metadata.get("failed_messages", 0)
        if total_messages == 0:
            return 100.0
        
        successful = metadata.get("message_count", 0)
        return (successful / total_messages) * 100.0
    
    async def cleanup_stale_connections(self, max_idle_time: int = 300) -> int:
        """
        Clean up stale connections that haven't had activity.
        
        Args:
            max_idle_time: Maximum idle time in seconds (default: 5 minutes)
            
        Returns:
            int: Number of connections cleaned up
        """
        cutoff_time = datetime.utcnow() - timedelta(seconds=max_idle_time)
        cleaned_count = 0
        
        async with self.lock:
            for websocket, metadata in list(self.connection_metadata.items()):
                if metadata.get("last_activity", datetime.utcnow()) < cutoff_time:
                    await self.disconnect(websocket)
                    cleaned_count += 1
        
        if cleaned_count > 0:
            logger.info(f"Cleaned up {cleaned_count} stale WebSocket connections")
        
        return cleaned_count
    
    async def _send_connection_status(self, websocket: WebSocket, status: str, is_reconnection: bool = False) -> None:
        """
        Send connection status message to client.
        
        Args:
            websocket: The WebSocket connection
            status: Connection status
            is_reconnection: Whether this is a reconnection
        """
        try:
            status_message = {
                "type": "connection_status",
                "status": status,
                "is_reconnection": is_reconnection,
                "timestamp": datetime.utcnow().isoformat(),
                "heartbeat_interval": self.heartbeat_interval
            }
            
            await websocket.send_text(json.dumps(status_message))
        except Exception as e:
            logger.warning(f"Failed to send connection status: {e}")
    
    async def send_heartbeat(self, websocket: WebSocket) -> bool:
        """
        Send heartbeat to WebSocket connection.
        
        Args:
            websocket: The WebSocket connection
            
        Returns:
            bool: True if heartbeat was sent successfully
        """
        try:
            heartbeat_message = {
                "type": "heartbeat",
                "timestamp": datetime.utcnow().isoformat()
            }
            
            await websocket.send_text(json.dumps(heartbeat_message))
            
            # Update last activity
            if websocket in self.connection_metadata:
                self.connection_metadata[websocket]["last_activity"] = datetime.utcnow()
            
            return True
        except Exception as e:
            logger.warning(f"Failed to send heartbeat: {e}")
            return False
    
    def get_connection_state(self, websocket: WebSocket) -> str:
        """
        Get the current state of a WebSocket connection.
        
        Args:
            websocket: The WebSocket connection
            
        Returns:
            str: Connection state (connected, disconnected, reconnecting)
        """
        return self.connection_states.get(websocket, "unknown")
    
    def is_connection_healthy(self, websocket: WebSocket) -> bool:
        """
        Check if a WebSocket connection is healthy.
        
        Args:
            websocket: The WebSocket connection
            
        Returns:
            bool: True if connection is healthy
        """
        if websocket not in self.connection_metadata:
            return False
        
        metadata = self.connection_metadata[websocket]
        last_activity = metadata.get("last_activity", datetime.utcnow())
        time_since_activity = (datetime.utcnow() - last_activity).total_seconds()
        
        return time_since_activity < self.connection_timeout


# Global WebSocket manager instance
websocket_manager = ProgressWebSocketManager()


async def handle_websocket_connection(websocket: WebSocket, job_id: str) -> None:
    """
    Handle a WebSocket connection for progress updates.
    
    Args:
        websocket: The WebSocket connection
        job_id: The job ID to track progress for
    """
    try:
        # Check if this is a reconnection attempt
        is_reconnection = websocket_manager.get_connection_state(websocket) == "reconnecting"
        
        # Accept the connection
        success = await websocket_manager.connect(websocket, job_id, is_reconnection)
        if not success:
            return
        
        # Send initial connection confirmation
        await websocket.send_text(json.dumps({
            "type": "connection_confirmed",
            "job_id": job_id,
            "timestamp": datetime.utcnow().isoformat(),
            "is_reconnection": is_reconnection
        }))
        
        # Start heartbeat monitoring
        heartbeat_task = asyncio.create_task(_heartbeat_monitor(websocket, job_id))
        
        # Keep connection alive and handle incoming messages
        while True:
            try:
                # Wait for any message from client with timeout
                data = await asyncio.wait_for(websocket.receive_text(), timeout=60.0)
                
                # Update last activity
                if websocket in websocket_manager.connection_metadata:
                    websocket_manager.connection_metadata[websocket]["last_activity"] = datetime.utcnow()
                
                # Handle different message types
                if data == "ping":
                    await websocket.send_text("pong")
                elif data == "heartbeat":
                    await websocket_manager.send_heartbeat(websocket)
                elif data == "reconnect_request":
                    # Handle explicit reconnection request
                    await _handle_reconnection_request(websocket, job_id)
                else:
                    # Handle other messages (could be JSON commands)
                    try:
                        message_data = json.loads(data)
                        await _handle_client_message(websocket, job_id, message_data)
                    except json.JSONDecodeError:
                        logger.debug(f"Received non-JSON message from client: {data}")
                    
            except asyncio.TimeoutError:
                # Send heartbeat to keep connection alive
                if not await websocket_manager.send_heartbeat(websocket):
                    logger.warning(f"Heartbeat failed for job {job_id}, connection may be stale")
                    break
            except WebSocketDisconnect:
                logger.info(f"WebSocket disconnected for job {job_id}")
                break
            except Exception as e:
                logger.error(f"Error handling WebSocket message for job {job_id}: {e}")
                # Mark for reconnection on certain errors
                if "connection" in str(e).lower() or "timeout" in str(e).lower():
                    await websocket_manager.mark_for_reconnection(websocket)
                break
                
    except Exception as e:
        logger.error(f"Error in WebSocket connection for job {job_id}: {e}")
        
    finally:
        # Cancel heartbeat task
        if 'heartbeat_task' in locals():
            heartbeat_task.cancel()
        
        # Clean up connection
        await websocket_manager.disconnect(websocket, "connection_ended")


async def _heartbeat_monitor(websocket: WebSocket, job_id: str) -> None:
    """
    Monitor WebSocket connection health with periodic heartbeats.
    
    Args:
        websocket: The WebSocket connection
        job_id: The job ID
    """
    try:
        while True:
            await asyncio.sleep(websocket_manager.heartbeat_interval)
            
            # Check if connection is still active
            if websocket not in websocket_manager.connection_jobs:
                break
            
            # Send heartbeat
            if not await websocket_manager.send_heartbeat(websocket):
                logger.warning(f"Heartbeat failed for job {job_id}, marking for reconnection")
                await websocket_manager.mark_for_reconnection(websocket)
                break
                
    except asyncio.CancelledError:
        # Task was cancelled, which is expected
        pass
    except Exception as e:
        logger.error(f"Error in heartbeat monitor for job {job_id}: {e}")


async def _handle_reconnection_request(websocket: WebSocket, job_id: str) -> None:
    """
    Handle explicit reconnection request from client.
    
    Args:
        websocket: The WebSocket connection
        job_id: The job ID
    """
    try:
        await websocket_manager.mark_for_reconnection(websocket)
        
        # Send reconnection acknowledgment
        await websocket.send_text(json.dumps({
            "type": "reconnection_acknowledged",
            "job_id": job_id,
            "timestamp": datetime.utcnow().isoformat()
        }))
        
        logger.info(f"Reconnection request acknowledged for job {job_id}")
        
    except Exception as e:
        logger.error(f"Error handling reconnection request for job {job_id}: {e}")


async def _handle_client_message(websocket: WebSocket, job_id: str, message_data: Dict[str, Any]) -> None:
    """
    Handle structured client messages.
    
    Args:
        websocket: The WebSocket connection
        job_id: The job ID
        message_data: Parsed message data
    """
    try:
        message_type = message_data.get("type")
        
        if message_type == "get_status":
            # Send current job status
            await _send_job_status(websocket, job_id)
        elif message_type == "get_queued_messages":
            # Send queued messages count
            await _send_queued_messages_count(websocket, job_id)
        else:
            logger.debug(f"Unknown message type from client: {message_type}")
            
    except Exception as e:
        logger.error(f"Error handling client message for job {job_id}: {e}")


async def _send_job_status(websocket: WebSocket, job_id: str) -> None:
    """
    Send current job status to client.
    
    Args:
        websocket: The WebSocket connection
        job_id: The job ID
    """
    try:
        # This would integrate with the job manager to get actual status
        status_message = {
            "type": "job_status",
            "job_id": job_id,
            "timestamp": datetime.utcnow().isoformat(),
            "status": "active"  # Placeholder
        }
        
        await websocket.send_text(json.dumps(status_message))
        
    except Exception as e:
        logger.error(f"Error sending job status for job {job_id}: {e}")


async def _send_queued_messages_count(websocket: WebSocket, job_id: str) -> None:
    """
    Send queued messages count to client.
    
    Args:
        websocket: The WebSocket connection
        job_id: The job ID
    """
    try:
        queued_count = len(websocket_manager.message_queue.get(job_id, []))
        
        status_message = {
            "type": "queued_messages_count",
            "job_id": job_id,
            "count": queued_count,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        await websocket.send_text(json.dumps(status_message))
        
    except Exception as e:
        logger.error(f"Error sending queued messages count for job {job_id}: {e}")
