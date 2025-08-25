'use client'

import { useState } from 'react'
import { Shield, Search, AlertTriangle, CheckCircle, Clock, Github } from 'lucide-react'
import { AnalysisForm } from '@/components/AnalysisForm'
import { ProgressDisplay } from '@/components/ProgressDisplay'
import { ResultsDisplay } from '@/components/ResultsDisplay'
import { AnalysisResponse, AnalysisResult } from '@/lib/api'

export default function Home() {
  const [analysisState, setAnalysisState] = useState<'idle' | 'analyzing' | 'completed' | 'error'>('idle')
  const [analysisResponse, setAnalysisResponse] = useState<AnalysisResponse | null>(null)
  const [analysisResult, setAnalysisResult] = useState<AnalysisResult | null>(null)
  const [error, setError] = useState<string | null>(null)

  const handleAnalysisStart = (response: AnalysisResponse) => {
    setAnalysisResponse(response)
    setAnalysisState('analyzing')
    setError(null)
  }

  const handleAnalysisComplete = (result: AnalysisResult) => {
    setAnalysisResult(result)
    setAnalysisState('completed')
  }

  const handleAnalysisError = (errorMessage: string) => {
    setError(errorMessage)
    setAnalysisState('error')
  }

  const handleReset = () => {
    setAnalysisState('idle')
    setAnalysisResponse(null)
    setAnalysisResult(null)
    setError(null)
  }

  return (
    <main className="min-h-screen bg-gradient-to-br from-slate-50 to-blue-50">
      {/* Header */}
      <header className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-6">
            <div className="flex items-center space-x-3">
              <div className="p-2 bg-blue-600 rounded-lg">
                <Shield className="h-6 w-6 text-white" />
              </div>
              <div>
                <h1 className="text-2xl font-bold text-gray-900">Caponier</h1>
                <p className="text-sm text-gray-600">GitHub Repository Security Analysis</p>
              </div>
            </div>
            <div className="flex items-center space-x-4">
              <a
                href="https://github.com/your-org/caponier"
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center space-x-2 text-gray-600 hover:text-gray-900 transition-colors"
              >
                <Github className="h-5 w-5" />
                <span className="text-sm font-medium">GitHub</span>
              </a>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        {/* Hero Section */}
        {analysisState === 'idle' && (
          <div className="text-center mb-12">
            <div className="mx-auto max-w-3xl">
              <h2 className="text-4xl font-bold text-gray-900 mb-6">
                Secure Your Code with Confidence
              </h2>
              <p className="text-xl text-gray-600 mb-8">
                Analyze your GitHub repositories for security vulnerabilities, 
                dependency risks, and get actionable recommendations to improve your code security.
              </p>
              
              {/* Features Grid */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-8 mb-12">
                <div className="text-center">
                  <div className="mx-auto w-12 h-12 bg-blue-100 rounded-lg flex items-center justify-center mb-4">
                    <Search className="h-6 w-6 text-blue-600" />
                  </div>
                  <h3 className="text-lg font-semibold text-gray-900 mb-2">Comprehensive Scanning</h3>
                  <p className="text-gray-600">Deep analysis of dependencies, vulnerabilities, and security patterns</p>
                </div>
                <div className="text-center">
                  <div className="mx-auto w-12 h-12 bg-green-100 rounded-lg flex items-center justify-center mb-4">
                    <CheckCircle className="h-6 w-6 text-green-600" />
                  </div>
                  <h3 className="text-lg font-semibold text-gray-900 mb-2">Real-time Results</h3>
                  <p className="text-gray-600">Get instant feedback with live progress updates and detailed reports</p>
                </div>
                <div className="text-center">
                  <div className="mx-auto w-12 h-12 bg-orange-100 rounded-lg flex items-center justify-center mb-4">
                    <AlertTriangle className="h-6 w-6 text-orange-600" />
                  </div>
                  <h3 className="text-lg font-semibold text-gray-900 mb-2">Risk Assessment</h3>
                  <p className="text-gray-600">Understand your security posture with detailed scoring and recommendations</p>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Analysis Form */}
        {analysisState === 'idle' && (
          <div className="max-w-2xl mx-auto">
            <AnalysisForm 
              onAnalysisStart={handleAnalysisStart}
              onError={handleAnalysisError}
            />
          </div>
        )}

        {/* Progress Display */}
        {analysisState === 'analyzing' && analysisResponse && (
          <div className="max-w-4xl mx-auto">
            <ProgressDisplay 
              jobId={analysisResponse.job_id}
              repositoryUrl={analysisResponse.repository_url}
              onComplete={handleAnalysisComplete}
              onError={handleAnalysisError}
            />
          </div>
        )}

        {/* Results Display */}
        {analysisState === 'completed' && analysisResult && (
          <div className="max-w-6xl mx-auto">
            <ResultsDisplay 
              result={analysisResult}
              onReset={handleReset}
            />
          </div>
        )}

        {/* Error Display */}
        {analysisState === 'error' && (
          <div className="max-w-2xl mx-auto text-center">
            <div className="bg-red-50 border border-red-200 rounded-lg p-6 mb-6">
              <AlertTriangle className="h-12 w-12 text-red-600 mx-auto mb-4" />
              <h3 className="text-lg font-semibold text-red-900 mb-2">Analysis Failed</h3>
              <p className="text-red-700 mb-4">{error}</p>
              <button
                onClick={handleReset}
                className="bg-red-600 text-white px-4 py-2 rounded-lg hover:bg-red-700 transition-colors"
              >
                Try Again
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Footer */}
      <footer className="bg-white border-t mt-20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <div className="text-center text-gray-600">
            <p>&copy; 2024 Caponier. Secure your code with confidence.</p>
          </div>
        </div>
      </footer>
    </main>
  )
}
