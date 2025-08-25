'use client'

import { useState } from 'react'
import { 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  ExternalLink, 
  Download, 
  Share2, 
  RefreshCw,
  Clock,
  Users,
  Package,
  GitBranch
} from 'lucide-react'
import { AnalysisResult } from '@/lib/api'
import { 
  getSecurityScoreColor, 
  getSecurityScoreBgColor, 
  getSeverityColor,
  formatDate,
  formatDuration
} from '@/lib/utils'

interface ResultsDisplayProps {
  result: AnalysisResult
  onReset: () => void
}

export function ResultsDisplay({ result, onReset }: ResultsDisplayProps) {
  const [activeTab, setActiveTab] = useState<'overview' | 'vulnerabilities' | 'recommendations'>('overview')

  const criticalVulns = result.vulnerabilities.filter(v => v.severity === 'CRITICAL')
  const highVulns = result.vulnerabilities.filter(v => v.severity === 'HIGH')
  const mediumVulns = result.vulnerabilities.filter(v => v.severity === 'MEDIUM')
  const lowVulns = result.vulnerabilities.filter(v => v.severity === 'LOW')

  const getScoreLabel = (score: number) => {
    if (score >= 80) return 'Excellent'
    if (score >= 60) return 'Good'
    if (score >= 40) return 'Fair'
    if (score >= 20) return 'Poor'
    return 'Critical'
  }

  const getScoreEmoji = (score: number) => {
    if (score >= 80) return '🟢'
    if (score >= 60) return '🟡'
    if (score >= 40) return '🟠'
    return '🔴'
  }

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="bg-white rounded-xl shadow-lg p-8">
        <div className="flex items-center justify-between mb-6">
          <div>
            <h2 className="text-3xl font-bold text-gray-900 mb-2">
              Analysis Complete
            </h2>
            <p className="text-gray-600">
              {result.owner}/{result.repository}
            </p>
          </div>
          <button
            onClick={onReset}
            className="flex items-center space-x-2 bg-gray-100 hover:bg-gray-200 text-gray-700 px-4 py-2 rounded-lg transition-colors"
          >
            <RefreshCw className="h-4 w-4" />
            <span>New Analysis</span>
          </button>
        </div>

        {/* Security Score */}
        <div className={`rounded-lg p-6 ${getSecurityScoreBgColor(result.security_score.overall_score)}`}>
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-lg font-semibold text-gray-900 mb-1">
                Overall Security Score
              </h3>
              <p className="text-sm text-gray-600">
                {getScoreEmoji(result.security_score.overall_score)} {getScoreLabel(result.security_score.overall_score)}
              </p>
            </div>
            <div className="text-right">
              <div className={`text-4xl font-bold ${getSecurityScoreColor(result.security_score.overall_score)}`}>
                {result.security_score.overall_score}/100
              </div>
            </div>
          </div>
        </div>

        {/* Quick Stats */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-6">
          <div className="bg-red-50 border border-red-200 rounded-lg p-4 text-center">
            <div className="text-2xl font-bold text-red-600">{criticalVulns.length}</div>
            <div className="text-sm text-red-700">Critical</div>
          </div>
          <div className="bg-orange-50 border border-orange-200 rounded-lg p-4 text-center">
            <div className="text-2xl font-bold text-orange-600">{highVulns.length}</div>
            <div className="text-sm text-orange-700">High</div>
          </div>
          <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4 text-center">
            <div className="text-2xl font-bold text-yellow-600">{mediumVulns.length}</div>
            <div className="text-sm text-yellow-700">Medium</div>
          </div>
          <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 text-center">
            <div className="text-2xl font-bold text-blue-600">{lowVulns.length}</div>
            <div className="text-sm text-blue-700">Low</div>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="bg-white rounded-xl shadow-lg">
        <div className="border-b border-gray-200">
          <nav className="flex space-x-8 px-8">
            {[
              { id: 'overview', label: 'Overview', icon: Shield },
              { id: 'vulnerabilities', label: 'Vulnerabilities', icon: AlertTriangle },
              { id: 'recommendations', label: 'Recommendations', icon: CheckCircle }
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                className={`flex items-center space-x-2 py-4 px-1 border-b-2 font-medium text-sm ${
                  activeTab === tab.id
                    ? 'border-blue-500 text-blue-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                }`}
              >
                <tab.icon className="h-4 w-4" />
                <span>{tab.label}</span>
              </button>
            ))}
          </nav>
        </div>

        <div className="p-8">
          {/* Overview Tab */}
          {activeTab === 'overview' && (
            <div className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="bg-gray-50 rounded-lg p-6">
                  <h4 className="text-lg font-semibold text-gray-900 mb-4">Repository Information</h4>
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-600">Last Commit</span>
                      <span className="text-sm font-medium">{formatDate(result.metadata.last_commit_date)}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-600">Contributors</span>
                      <span className="text-sm font-medium">{result.metadata.contributor_count}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-600">Dependencies</span>
                      <span className="text-sm font-medium">{result.metadata.dependency_count}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-600">Ecosystems</span>
                      <span className="text-sm font-medium">{result.metadata.ecosystem_count}</span>
                    </div>
                  </div>
                </div>

                <div className="bg-gray-50 rounded-lg p-6">
                  <h4 className="text-lg font-semibold text-gray-900 mb-4">Analysis Details</h4>
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-600">Analysis Duration</span>
                      <span className="text-sm font-medium">{formatDuration(result.analysis_duration)}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-600">Completed At</span>
                      <span className="text-sm font-medium">{formatDate(result.completed_at)}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-600">Total Vulnerabilities</span>
                      <span className="text-sm font-medium">{result.vulnerabilities.length}</span>
                    </div>
                  </div>
                </div>
              </div>

              <div className="bg-blue-50 border border-blue-200 rounded-lg p-6">
                <h4 className="text-lg font-semibold text-blue-900 mb-2">Security Score Breakdown</h4>
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-blue-700">Vulnerability Score</span>
                    <span className="text-sm font-medium text-blue-900">
                      {result.security_score.vulnerability_score}/100
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-blue-700">Maintenance Score</span>
                    <span className="text-sm font-medium text-blue-900">
                      {result.security_score.maintenance_score}/100
                    </span>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Vulnerabilities Tab */}
          {activeTab === 'vulnerabilities' && (
            <div className="space-y-4">
              {result.vulnerabilities.length === 0 ? (
                <div className="text-center py-8">
                  <CheckCircle className="h-12 w-12 text-green-600 mx-auto mb-4" />
                  <h3 className="text-lg font-semibold text-gray-900 mb-2">No Vulnerabilities Found</h3>
                  <p className="text-gray-600">Great job! No security vulnerabilities were detected in this repository.</p>
                </div>
              ) : (
                <div className="space-y-4">
                  {result.vulnerabilities.map((vuln, index) => (
                    <div key={index} className="border border-gray-200 rounded-lg p-6">
                      <div className="flex items-start justify-between mb-4">
                        <div className="flex-1">
                          <div className="flex items-center space-x-3 mb-2">
                            <span className={`px-2 py-1 rounded-full text-xs font-medium border ${getSeverityColor(vuln.severity)}`}>
                              {vuln.severity}
                            </span>
                            <h4 className="text-lg font-semibold text-gray-900">{vuln.cve_id}</h4>
                          </div>
                          <p className="text-gray-600 mb-2">{vuln.description}</p>
                          <div className="text-sm text-gray-500">
                            Package: {vuln.package_name}@{vuln.package_version}
                          </div>
                        </div>
                        <a
                          href={vuln.cve_url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="flex items-center space-x-1 text-blue-600 hover:text-blue-700"
                        >
                          <span className="text-sm">Details</span>
                          <ExternalLink className="h-4 w-4" />
                        </a>
                      </div>
                      
                      {vuln.cvss_score && (
                        <div className="bg-gray-50 rounded-lg p-3">
                          <div className="text-sm text-gray-600">
                            CVSS Score: <span className="font-medium">{vuln.cvss_score}</span>
                          </div>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Recommendations Tab */}
          {activeTab === 'recommendations' && (
            <div className="space-y-4">
              {result.recommendations.length === 0 ? (
                <div className="text-center py-8">
                  <CheckCircle className="h-12 w-12 text-green-600 mx-auto mb-4" />
                  <h3 className="text-lg font-semibold text-gray-900 mb-2">No Recommendations</h3>
                  <p className="text-gray-600">Your repository is already following security best practices!</p>
                </div>
              ) : (
                <div className="space-y-4">
                  {result.recommendations.map((recommendation, index) => (
                    <div key={index} className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                      <div className="flex items-start">
                        <CheckCircle className="h-5 w-5 text-blue-600 mt-0.5 mr-3 flex-shrink-0" />
                        <p className="text-blue-900">{recommendation}</p>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Action Buttons */}
      <div className="bg-white rounded-xl shadow-lg p-6">
        <div className="flex flex-wrap gap-4 justify-center">
          <button className="flex items-center space-x-2 bg-blue-600 text-white px-6 py-3 rounded-lg hover:bg-blue-700 transition-colors">
            <Download className="h-4 w-4" />
            <span>Export Report</span>
          </button>
          <button className="flex items-center space-x-2 bg-green-600 text-white px-6 py-3 rounded-lg hover:bg-green-700 transition-colors">
            <Share2 className="h-4 w-4" />
            <span>Share Results</span>
          </button>
        </div>
      </div>
    </div>
  )
}
