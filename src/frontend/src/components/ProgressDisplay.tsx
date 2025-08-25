'use client'

import { useState, useEffect } from 'react'
import { Clock, CheckCircle, AlertTriangle, Wifi, WifiOff } from 'lucide-react'
import { useWebSocket, WebSocketMessage } from '@/hooks/useWebSocket'
import { apiClient, AnalysisResult } from '@/lib/api'
import { formatDuration } from '@/lib/utils'

interface ProgressDisplayProps {
  jobId: string
  repositoryUrl: string
  onComplete: (result: AnalysisResult) => void
  onError: (error: string) => void
}

export function ProgressDisplay({ 
  jobId, 
  repositoryUrl, 
  onComplete, 
  onError 
}: ProgressDisplayProps) {
  const [progress, setProgress] = useState<WebSocketMessage | null>(null)
  const [startTime] = useState(Date.now())
  const [elapsedTime, setElapsedTime] = useState(0)

  const { isConnected, isConnecting, error: wsError } = useWebSocket({
    jobId,
    onMessage: (message) => {
      setProgress(message)
      
      // Check if analysis is complete
      if (message.status === 'completed') {
        // Fetch the final result
        fetchResult()
      } else if (message.status === 'failed') {
        onError(message.message || 'Analysis failed')
      }
    },
    onError: (error) => {
      console.error('WebSocket error:', error)
    }
  })

  // Update elapsed time
  useEffect(() => {
    const interval = setInterval(() => {
      setElapsedTime(Math.floor((Date.now() - startTime) / 1000))
    }, 1000)

    return () => clearInterval(interval)
  }, [startTime])

  const fetchResult = async () => {
    try {
      const result = await apiClient.getAnalysisResult(jobId)
      onComplete(result)
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to fetch analysis result'
      onError(errorMessage)
    }
  }

  const getProgressColor = (percentage: number) => {
    if (percentage >= 80) return 'bg-green-500'
    if (percentage >= 60) return 'bg-blue-500'
    if (percentage >= 40) return 'bg-yellow-500'
    return 'bg-orange-500'
  }

  const getStageIcon = (stage: string) => {
    const stageLower = stage.toLowerCase()
    if (stageLower.includes('complete') || stageLower.includes('done')) {
      return <CheckCircle className="h-5 w-5 text-green-600" />
    }
    if (stageLower.includes('error') || stageLower.includes('fail')) {
      return <AlertTriangle className="h-5 w-5 text-red-600" />
    }
    return <Clock className="h-5 w-5 text-blue-600" />
  }

  return (
    <div className="bg-white rounded-xl shadow-lg p-8">
      {/* Header */}
      <div className="text-center mb-8">
        <h3 className="text-2xl font-bold text-gray-900 mb-2">
          Analyzing Repository
        </h3>
        <p className="text-gray-600 mb-4">{repositoryUrl}</p>
        
        {/* Connection Status */}
        <div className="flex items-center justify-center space-x-2 mb-4">
          {isConnected ? (
            <>
              <Wifi className="h-4 w-4 text-green-600" />
              <span className="text-sm text-green-600">Connected</span>
            </>
          ) : isConnecting ? (
            <>
              <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-blue-600"></div>
              <span className="text-sm text-blue-600">Connecting...</span>
            </>
          ) : (
            <>
              <WifiOff className="h-4 w-4 text-red-600" />
              <span className="text-sm text-red-600">Disconnected</span>
            </>
          )}
        </div>

        {/* Elapsed Time */}
        <div className="text-sm text-gray-500">
          Elapsed time: {formatDuration(elapsedTime)}
        </div>
      </div>

      {/* Progress Bar */}
      <div className="mb-8">
        <div className="flex justify-between items-center mb-2">
          <span className="text-sm font-medium text-gray-700">Progress</span>
          <span className="text-sm text-gray-500">
            {progress?.progress_percentage || 0}%
          </span>
        </div>
        <div className="w-full bg-gray-200 rounded-full h-3">
          <div
            className={`h-3 rounded-full transition-all duration-500 ease-out ${getProgressColor(progress?.progress_percentage || 0)}`}
            style={{ width: `${progress?.progress_percentage || 0}%` }}
          ></div>
        </div>
      </div>

      {/* Current Stage */}
      {progress && (
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 mb-6">
          <div className="flex items-center">
            {getStageIcon(progress.stage)}
            <div className="ml-3">
              <h4 className="text-sm font-medium text-blue-900">
                {progress.stage}
              </h4>
              <p className="text-sm text-blue-700 mt-1">
                {progress.message}
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Analysis Stages */}
      <div className="space-y-4">
        <h4 className="text-lg font-semibold text-gray-900">Analysis Stages</h4>
        
        {[
          { name: 'Repository Validation', completed: progress?.progress_percentage && progress.progress_percentage >= 10 },
          { name: 'Dependency Discovery', completed: progress?.progress_percentage && progress.progress_percentage >= 25 },
          { name: 'Vulnerability Scanning', completed: progress?.progress_percentage && progress.progress_percentage >= 50 },
          { name: 'Security Scoring', completed: progress?.progress_percentage && progress.progress_percentage >= 75 },
          { name: 'Report Generation', completed: progress?.progress_percentage && progress.progress_percentage >= 90 }
        ].map((stage, index) => (
          <div key={index} className="flex items-center">
            <div className={`w-6 h-6 rounded-full flex items-center justify-center mr-3 ${
              stage.completed 
                ? 'bg-green-500 text-white' 
                : 'bg-gray-200 text-gray-400'
            }`}>
              {stage.completed ? (
                <CheckCircle className="h-4 w-4" />
              ) : (
                <span className="text-xs">{index + 1}</span>
              )}
            </div>
            <span className={`text-sm ${
              stage.completed ? 'text-gray-900' : 'text-gray-500'
            }`}>
              {stage.name}
            </span>
          </div>
        ))}
      </div>

      {/* Error Display */}
      {wsError && (
        <div className="mt-6 bg-red-50 border border-red-200 rounded-lg p-4">
          <div className="flex items-center">
            <AlertTriangle className="h-5 w-5 text-red-600 mr-2" />
            <span className="text-sm text-red-700">
              Connection error: {wsError}
            </span>
          </div>
        </div>
      )}

      {/* Estimated Time */}
      <div className="mt-8 text-center">
        <p className="text-sm text-gray-500">
          Estimated completion time: 1-2 minutes
        </p>
      </div>
    </div>
  )
}
