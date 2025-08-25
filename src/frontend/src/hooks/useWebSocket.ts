import { useEffect, useRef, useState, useCallback } from 'react'
import { AnalysisProgress } from '@/lib/api'

export interface WebSocketMessage {
  type: 'progress' | 'connection_status' | 'heartbeat' | 'error'
  job_id: string
  status: string
  progress_percentage: number
  message: string
  stage: string
  timestamp: string
  details?: Record<string, any>
}

export interface UseWebSocketOptions {
  jobId: string
  token?: string
  onMessage?: (message: WebSocketMessage) => void
  onError?: (error: Event) => void
  onClose?: (event: CloseEvent) => void
  onOpen?: () => void
}

export function useWebSocket({
  jobId,
  token,
  onMessage,
  onError,
  onClose,
  onOpen
}: UseWebSocketOptions) {
  const [isConnected, setIsConnected] = useState(false)
  const [isConnecting, setIsConnecting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [lastMessage, setLastMessage] = useState<WebSocketMessage | null>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null)
  const reconnectAttempts = useRef(0)
  const maxReconnectAttempts = 5

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      return
    }

    setIsConnecting(true)
    setError(null)

    try {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
      const host = process.env.NEXT_PUBLIC_API_URL?.replace(/^https?:\/\//, '') || 'localhost:8000'
      const tokenParam = token ? `?token=${token}` : ''
      const url = `${protocol}//${host}/ws/progress/${jobId}${tokenParam}`

      const ws = new WebSocket(url)
      wsRef.current = ws

      ws.onopen = () => {
        setIsConnected(true)
        setIsConnecting(false)
        reconnectAttempts.current = 0
        onOpen?.()
      }

      ws.onmessage = (event) => {
        try {
          const data: WebSocketMessage = JSON.parse(event.data)
          setLastMessage(data)
          onMessage?.(data)
        } catch (err) {
          console.error('Failed to parse WebSocket message:', err)
        }
      }

      ws.onerror = (event) => {
        setError('WebSocket connection error')
        onError?.(event)
      }

      ws.onclose = (event) => {
        setIsConnected(false)
        setIsConnecting(false)
        
        // Attempt to reconnect if not a normal closure
        if (event.code !== 1000 && reconnectAttempts.current < maxReconnectAttempts) {
          reconnectAttempts.current++
          const delay = Math.min(1000 * Math.pow(2, reconnectAttempts.current - 1), 10000)
          
          reconnectTimeoutRef.current = setTimeout(() => {
            connect()
          }, delay)
        }
        
        onClose?.(event)
      }
    } catch (err) {
      setError('Failed to create WebSocket connection')
      setIsConnecting(false)
    }
  }, [jobId, token, onMessage, onError, onClose, onOpen])

  const disconnect = useCallback(() => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current)
      reconnectTimeoutRef.current = null
    }
    
    if (wsRef.current) {
      wsRef.current.close(1000, 'User disconnected')
      wsRef.current = null
    }
    
    setIsConnected(false)
    setIsConnecting(false)
    reconnectAttempts.current = 0
  }, [])

  const sendMessage = useCallback((message: string) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(message)
    }
  }, [])

  useEffect(() => {
    connect()

    return () => {
      disconnect()
    }
  }, [connect, disconnect])

  return {
    isConnected,
    isConnecting,
    error,
    lastMessage,
    sendMessage,
    connect,
    disconnect
  }
}
