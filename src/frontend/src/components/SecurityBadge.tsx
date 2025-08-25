'use client'

import { useState } from 'react'
import { Shield, Copy, Check, ExternalLink, Download } from 'lucide-react'
import { AnalysisResult } from '@/lib/api'
import { sharingManager } from '@/lib/sharing'
import { getSecurityScoreColor, getSecurityScoreBgColor } from '@/lib/utils'

interface SecurityBadgeProps {
  analysis: AnalysisResult
  showEmbedCode?: boolean
  showSharing?: boolean
}

export function SecurityBadge({ analysis, showEmbedCode = true, showSharing = true }: SecurityBadgeProps) {
  const [copied, setCopied] = useState<'markdown' | 'html' | 'url' | null>(null)
  const [activeTab, setActiveTab] = useState<'badge' | 'embed'>('badge')

  const criticalVulns = analysis.vulnerabilities.filter(v => v.severity === 'CRITICAL')
  const highVulns = analysis.vulnerabilities.filter(v => v.severity === 'HIGH')

  const shareableAnalysis = {
    job_id: analysis.job_id,
    repository_url: analysis.repository_url,
    owner: analysis.owner,
    repository: analysis.repository,
    security_score: analysis.security_score.overall_score,
    vulnerability_count: analysis.vulnerabilities.length,
    critical_count: criticalVulns.length,
    high_count: highVulns.length,
    completed_at: analysis.completed_at
  }

  const shareUrl = sharingManager.generateShareableUrl(shareableAnalysis)
  const markdownEmbed = sharingManager.generateMarkdownEmbed(shareableAnalysis)
  const htmlEmbed = sharingManager.generateHtmlEmbed(shareableAnalysis)

  const copyToClipboard = async (text: string, type: 'markdown' | 'html' | 'url') => {
    try {
      await sharingManager.copyToClipboard(text)
      setCopied(type)
      setTimeout(() => setCopied(null), 2000)
    } catch (error) {
      console.error('Failed to copy to clipboard:', error)
    }
  }

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
    <div className="bg-white rounded-xl shadow-lg overflow-hidden">
      {/* Header */}
      <div className="bg-gradient-to-r from-blue-600 to-purple-600 text-white p-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <Shield className="h-8 w-8" />
            <div>
              <h3 className="text-xl font-bold">Security Badge</h3>
              <p className="text-blue-100 text-sm">Embed this badge in your README or website</p>
            </div>
          </div>
          <div className="text-right">
            <div className="text-3xl font-bold">{analysis.security_score.overall_score}/100</div>
            <div className="text-blue-100 text-sm">{getScoreLabel(analysis.security_score.overall_score)}</div>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="border-b border-gray-200">
        <nav className="flex">
          <button
            onClick={() => setActiveTab('badge')}
            className={`flex-1 py-3 px-4 text-sm font-medium ${
              activeTab === 'badge'
                ? 'text-blue-600 border-b-2 border-blue-600'
                : 'text-gray-500 hover:text-gray-700'
            }`}
          >
            Badge Preview
          </button>
          {showEmbedCode && (
            <button
              onClick={() => setActiveTab('embed')}
              className={`flex-1 py-3 px-4 text-sm font-medium ${
                activeTab === 'embed'
                  ? 'text-blue-600 border-b-2 border-blue-600'
                  : 'text-gray-500 hover:text-gray-700'
              }`}
            >
              Embed Code
            </button>
          )}
        </nav>
      </div>

      {/* Content */}
      <div className="p-6">
        {activeTab === 'badge' && (
          <div className="space-y-6">
            {/* Badge Preview */}
            <div>
              <h4 className="text-lg font-semibold text-gray-900 mb-4">Badge Preview</h4>
              <div className="flex justify-center">
                <a
                  href={shareUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center space-x-2 bg-white border border-gray-300 rounded-lg px-4 py-2 hover:border-gray-400 transition-colors"
                >
                  <Shield className="h-5 w-5 text-blue-600" />
                  <span className="text-sm font-medium text-gray-700">
                    Security Score: {analysis.security_score.overall_score}/100
                  </span>
                  <span className={`px-2 py-1 rounded text-xs font-medium ${getSecurityScoreColor(analysis.security_score.overall_score)} ${getSecurityScoreBgColor(analysis.security_score.overall_score)}`}>
                    {getScoreEmoji(analysis.security_score.overall_score)} {getScoreLabel(analysis.security_score.overall_score)}
                  </span>
                </a>
              </div>
            </div>

            {/* Badge Information */}
            <div className="bg-gray-50 rounded-lg p-4">
              <h5 className="font-medium text-gray-900 mb-2">Badge Information</h5>
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <span className="text-gray-600">Repository:</span>
                  <div className="font-medium">{analysis.owner}/{analysis.repository}</div>
                </div>
                <div>
                  <span className="text-gray-600">Vulnerabilities:</span>
                  <div className="font-medium">{analysis.vulnerabilities.length} total</div>
                </div>
                <div>
                  <span className="text-gray-600">Critical:</span>
                  <div className="font-medium text-red-600">{criticalVulns.length}</div>
                </div>
                <div>
                  <span className="text-gray-600">High:</span>
                  <div className="font-medium text-orange-600">{highVulns.length}</div>
                </div>
              </div>
            </div>

            {/* Quick Actions */}
            {showSharing && (
              <div className="space-y-3">
                <h5 className="font-medium text-gray-900">Quick Actions</h5>
                <div className="flex flex-wrap gap-2">
                  <button
                    onClick={() => copyToClipboard(shareUrl, 'url')}
                    className="flex items-center space-x-2 bg-blue-600 text-white px-3 py-2 rounded-lg hover:bg-blue-700 transition-colors text-sm"
                  >
                    {copied === 'url' ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
                    <span>Copy URL</span>
                  </button>
                  <a
                    href={shareUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center space-x-2 bg-gray-600 text-white px-3 py-2 rounded-lg hover:bg-gray-700 transition-colors text-sm"
                  >
                    <ExternalLink className="h-4 w-4" />
                    <span>View Report</span>
                  </a>
                </div>
              </div>
            )}
          </div>
        )}

        {activeTab === 'embed' && (
          <div className="space-y-6">
            {/* Markdown Embed */}
            <div>
              <div className="flex items-center justify-between mb-3">
                <h4 className="text-lg font-semibold text-gray-900">Markdown</h4>
                <button
                  onClick={() => copyToClipboard(markdownEmbed, 'markdown')}
                  className="flex items-center space-x-2 bg-gray-100 hover:bg-gray-200 text-gray-700 px-3 py-1 rounded text-sm transition-colors"
                >
                  {copied === 'markdown' ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
                  <span>Copy</span>
                </button>
              </div>
              <div className="bg-gray-50 border border-gray-200 rounded-lg p-4">
                <pre className="text-sm text-gray-800 overflow-x-auto whitespace-pre-wrap break-all">
                  {markdownEmbed}
                </pre>
              </div>
            </div>

            {/* HTML Embed */}
            <div>
              <div className="flex items-center justify-between mb-3">
                <h4 className="text-lg font-semibold text-gray-900">HTML</h4>
                <button
                  onClick={() => copyToClipboard(htmlEmbed, 'html')}
                  className="flex items-center space-x-2 bg-gray-100 hover:bg-gray-200 text-gray-700 px-3 py-1 rounded text-sm transition-colors"
                >
                  {copied === 'html' ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
                  <span>Copy</span>
                </button>
              </div>
              <div className="bg-gray-50 border border-gray-200 rounded-lg p-4">
                <pre className="text-sm text-gray-800 overflow-x-auto whitespace-pre-wrap break-all">
                  {htmlEmbed}
                </pre>
              </div>
            </div>

            {/* Usage Instructions */}
            <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
              <h5 className="font-medium text-blue-900 mb-2">Usage Instructions</h5>
              <div className="text-sm text-blue-800 space-y-2">
                <p><strong>Markdown:</strong> Add the markdown code to your README.md file</p>
                <p><strong>HTML:</strong> Include the HTML code in your website or documentation</p>
                <p><strong>Features:</strong> The badge automatically updates with your latest security score and links to the full analysis report</p>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Footer */}
      <div className="bg-gray-50 px-6 py-4 border-t border-gray-200">
        <div className="flex items-center justify-between text-sm text-gray-600">
          <span>Powered by Caponier Security Analysis</span>
          <span>Last updated: {new Date(analysis.completed_at).toLocaleDateString()}</span>
        </div>
      </div>
    </div>
  )
}
