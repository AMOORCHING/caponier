'use client'

import { useState } from 'react'
import { Search, AlertCircle, Github } from 'lucide-react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { apiClient, AnalysisResponse } from '@/lib/api'
import { validateGitHubUrl, extractGitHubInfo } from '@/lib/utils'
import React from 'react'

const analysisSchema = z.object({
  repository_url: z
    .string()
    .min(1, 'Repository URL is required')
    .url('Please enter a valid URL')
    .refine(validateGitHubUrl, 'Please enter a valid GitHub repository URL')
})

type AnalysisFormData = z.infer<typeof analysisSchema>

interface AnalysisFormProps {
  onAnalysisStart: (response: AnalysisResponse) => void
  onError: (error: string) => void
}

export function AnalysisForm({ onAnalysisStart, onError }: AnalysisFormProps) {
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [githubInfo, setGithubInfo] = useState<{ owner: string; repo: string } | null>(null)

  const {
    register,
    handleSubmit,
    watch,
    formState: { errors },
    setValue
  } = useForm<AnalysisFormData>({
    resolver: zodResolver(analysisSchema)
  })

  const watchedUrl = watch('repository_url')

  // Update GitHub info when URL changes
  React.useEffect(() => {
    if (watchedUrl && validateGitHubUrl(watchedUrl)) {
      const info = extractGitHubInfo(watchedUrl)
      setGithubInfo(info)
    } else {
      setGithubInfo(null)
    }
  }, [watchedUrl])

  const onSubmit = async (data: AnalysisFormData) => {
    setIsSubmitting(true)
    
    try {
      const response = await apiClient.startAnalysis(data)
      onAnalysisStart(response)
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to start analysis'
      onError(errorMessage)
    } finally {
      setIsSubmitting(false)
    }
  }

  const handleExampleClick = (exampleUrl: string) => {
    setValue('repository_url', exampleUrl)
  }

  return (
    <div className="bg-white rounded-xl shadow-lg p-8">
      <div className="text-center mb-8">
        <h3 className="text-2xl font-bold text-gray-900 mb-2">
          Analyze Your Repository
        </h3>
        <p className="text-gray-600">
          Enter a GitHub repository URL to start security analysis
        </p>
      </div>

      <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
        <div>
          <label htmlFor="repository_url" className="block text-sm font-medium text-gray-700 mb-2">
            GitHub Repository URL
          </label>
          <div className="relative">
            <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
              <Github className="h-5 w-5 text-gray-400" />
            </div>
            <input
              {...register('repository_url')}
              type="url"
              id="repository_url"
              placeholder="https://github.com/username/repository"
              className={`block w-full pl-10 pr-3 py-3 border rounded-lg shadow-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 ${
                errors.repository_url ? 'border-red-300' : 'border-gray-300'
              }`}
            />
          </div>
          {errors.repository_url && (
            <div className="flex items-center mt-2 text-sm text-red-600">
              <AlertCircle className="h-4 w-4 mr-1" />
              {errors.repository_url.message}
            </div>
          )}
        </div>

        {/* GitHub Repository Preview */}
        {githubInfo && (
          <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
            <div className="flex items-center">
              <Github className="h-5 w-5 text-blue-600 mr-2" />
              <div>
                <p className="text-sm font-medium text-blue-900">
                  {githubInfo.owner}/{githubInfo.repo}
                </p>
                <p className="text-xs text-blue-700">Repository found</p>
              </div>
            </div>
          </div>
        )}

        {/* Example Repositories */}
        <div>
          <p className="text-sm text-gray-600 mb-3">Try with these examples:</p>
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              onClick={() => handleExampleClick('https://github.com/facebook/react')}
              className="text-xs bg-gray-100 hover:bg-gray-200 text-gray-700 px-3 py-1 rounded-full transition-colors"
            >
              React
            </button>
            <button
              type="button"
              onClick={() => handleExampleClick('https://github.com/vercel/next.js')}
              className="text-xs bg-gray-100 hover:bg-gray-200 text-gray-700 px-3 py-1 rounded-full transition-colors"
            >
              Next.js
            </button>
            <button
              type="button"
              onClick={() => handleExampleClick('https://github.com/microsoft/vscode')}
              className="text-xs bg-gray-100 hover:bg-gray-200 text-gray-700 px-3 py-1 rounded-full transition-colors"
            >
              VS Code
            </button>
          </div>
        </div>

        <button
          type="submit"
          disabled={isSubmitting || !watchedUrl}
          className={`w-full flex items-center justify-center px-6 py-3 border border-transparent text-base font-medium rounded-lg text-white ${
            isSubmitting || !watchedUrl
              ? 'bg-gray-400 cursor-not-allowed'
              : 'bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500'
          } transition-colors`}
        >
          {isSubmitting ? (
            <>
              <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
              Starting Analysis...
            </>
          ) : (
            <>
              <Search className="h-4 w-4 mr-2" />
              Start Security Analysis
            </>
          )}
        </button>
      </form>

      <div className="mt-6 text-center">
        <p className="text-xs text-gray-500">
          Analysis typically takes 1-2 minutes to complete
        </p>
      </div>
    </div>
  )
}
