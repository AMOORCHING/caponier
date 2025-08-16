"""
Synchronous repository validation and metadata extraction service for Celery tasks

This module provides a synchronous version of the repository analyzer specifically
designed for use in Celery tasks to avoid asyncio.run() performance issues.
"""

import logging
import re
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timedelta

from .github_client_sync import SyncGitHubClient, get_sync_github_client
from ..models import RepositoryMetadata
from ..utils.exceptions import (
    RepositoryNotFoundError, 
    RepositoryAccessDeniedError,
    GitHubAPIError,
    AnalysisError
)

logger = logging.getLogger(__name__)


class SyncRepositoryAnalyzer:
    """
    Synchronous repository analysis and validation service for Celery tasks
    """
    
    def __init__(self, github_client: Optional[SyncGitHubClient] = None):
        """
        Initialize synchronous repository analyzer
        
        Args:
            github_client: Optional synchronous GitHub client (will create one if not provided)
        """
        self.github_client = github_client or get_sync_github_client()
        self._client_owned = github_client is None
    
    def close(self):
        """Clean up resources"""
        if self._client_owned and self.github_client:
            self.github_client.close()
    
    def analyze_repository(self, repository_url: str, owner: str, repo: str) -> RepositoryMetadata:
        """
        Comprehensive repository validation and analysis
        
        Args:
            repository_url: GitHub repository URL
            owner: Repository owner
            repo: Repository name
            
        Returns:
            Repository metadata
            
        Raises:
            RepositoryNotFoundError: If repository doesn't exist
            RepositoryAccessDeniedError: If repository is not accessible
            AnalysisError: If analysis fails
        """
        try:
            logger.info(f"Starting repository analysis for {owner}/{repo}")
            
            # Get comprehensive repository metadata
            repo_data = self._get_repository_metadata(owner, repo)
            
            # Get detailed commit information
            commit_info = self._get_commit_analysis(owner, repo)
            
            # Get contributor analysis
            contributor_info = self._get_contributor_analysis(owner, repo)
            
            # Compile comprehensive analysis
            metadata = RepositoryMetadata(
                owner=owner,
                name=repo,
                full_name=f"{owner}/{repo}",
                description=repo_data.get('description', ''),
                url=repository_url,
                stars_count=repo_data.get('stargazers_count', 0),
                forks_count=repo_data.get('forks_count', 0),
                open_issues_count=repo_data.get('open_issues_count', 0),
                language=repo_data.get('language', 'Unknown'),
                created_at=self._parse_github_date(repo_data.get('created_at')),
                updated_at=self._parse_github_date(repo_data.get('updated_at')),
                pushed_at=self._parse_github_date(repo_data.get('pushed_at')),
                size=repo_data.get('size', 0),
                default_branch=repo_data.get('default_branch', 'main'),
                is_private=repo_data.get('private', False),
                is_fork=repo_data.get('fork', False),
                has_issues=repo_data.get('has_issues', True),
                has_projects=repo_data.get('has_projects', True),
                has_wiki=repo_data.get('has_wiki', True),
                has_downloads=repo_data.get('has_downloads', True),
                archived=repo_data.get('archived', False),
                disabled=repo_data.get('disabled', False),
                license_name=repo_data.get('license', {}).get('name') if repo_data.get('license') else None,
                topics=repo_data.get('topics', []),
                last_commit_date=commit_info.get('last_commit_date'),
                commit_count=commit_info.get('commit_count', 0),
                contributor_count=contributor_info.get('contributor_count', 0),
                recent_activity_score=self._calculate_activity_score(repo_data, commit_info)
            )
            
            logger.info(f"Repository analysis completed for {owner}/{repo}")
            return metadata
            
        except (RepositoryNotFoundError, RepositoryAccessDeniedError):
            # Re-raise our custom exceptions
            raise
        except Exception as e:
            logger.error(f"Repository analysis failed for {owner}/{repo}: {str(e)}")
            raise AnalysisError(f"Failed to analyze repository: {str(e)}")
    
    def _get_repository_metadata(self, owner: str, repo: str) -> Dict[str, Any]:
        """
        Get basic repository metadata
        
        Args:
            owner: Repository owner
            repo: Repository name
            
        Returns:
            Repository metadata dictionary
        """
        try:
            repo_data = self.github_client.get_repository(owner, repo)
            logger.debug(f"Retrieved repository metadata for {owner}/{repo}")
            return repo_data
            
        except Exception as e:
            logger.error(f"Failed to get repository metadata for {owner}/{repo}: {e}")
            raise
    
    def _get_commit_analysis(self, owner: str, repo: str) -> Dict[str, Any]:
        """
        Analyze repository commit history
        
        Args:
            owner: Repository owner
            repo: Repository name
            
        Returns:
            Commit analysis data
        """
        try:
            commits = self.github_client.get_commits(owner, repo, per_page=100)
            
            if not commits:
                return {
                    'commit_count': 0,
                    'last_commit_date': None
                }
            
            # Get the most recent commit date
            last_commit_date = None
            if commits:
                last_commit = commits[0].get('commit', {})
                commit_date_str = last_commit.get('author', {}).get('date')
                if commit_date_str:
                    last_commit_date = self._parse_github_date(commit_date_str)
            
            return {
                'commit_count': len(commits),
                'last_commit_date': last_commit_date
            }
            
        except Exception as e:
            logger.warning(f"Failed to analyze commits for {owner}/{repo}: {e}")
            return {
                'commit_count': 0,
                'last_commit_date': None
            }
    
    def _get_contributor_analysis(self, owner: str, repo: str) -> Dict[str, Any]:
        """
        Analyze repository contributors
        
        Args:
            owner: Repository owner
            repo: Repository name
            
        Returns:
            Contributor analysis data
        """
        try:
            contributors = self.github_client.get_contributors(owner, repo, per_page=100)
            
            return {
                'contributor_count': len(contributors) if contributors else 0
            }
            
        except Exception as e:
            logger.warning(f"Failed to analyze contributors for {owner}/{repo}: {e}")
            return {
                'contributor_count': 0
            }
    
    def _parse_github_date(self, date_str: Optional[str]) -> Optional[datetime]:
        """
        Parse GitHub date string to datetime
        
        Args:
            date_str: GitHub date string (ISO format)
            
        Returns:
            Parsed datetime or None
        """
        if not date_str:
            return None
        
        try:
            # GitHub dates are in ISO format: 2023-01-01T12:00:00Z
            if date_str.endswith('Z'):
                date_str = date_str[:-1] + '+00:00'
            
            return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
            
        except (ValueError, AttributeError) as e:
            logger.warning(f"Failed to parse GitHub date '{date_str}': {e}")
            return None
    
    def _calculate_activity_score(self, repo_data: Dict[str, Any], commit_info: Dict[str, Any]) -> float:
        """
        Calculate repository activity score
        
        Args:
            repo_data: Repository metadata
            commit_info: Commit analysis data
            
        Returns:
            Activity score (0.0 to 1.0)
        """
        try:
            score = 0.0
            
            # Factor in recent commits
            last_commit_date = commit_info.get('last_commit_date')
            if last_commit_date:
                days_since_commit = (datetime.now(last_commit_date.tzinfo) - last_commit_date).days
                if days_since_commit <= 30:
                    score += 0.4  # Recent activity
                elif days_since_commit <= 90:
                    score += 0.2  # Moderately recent
            
            # Factor in repository popularity
            stars = repo_data.get('stargazers_count', 0)
            if stars >= 1000:
                score += 0.3
            elif stars >= 100:
                score += 0.2
            elif stars >= 10:
                score += 0.1
            
            # Factor in community engagement
            open_issues = repo_data.get('open_issues_count', 0)
            if open_issues > 0:
                score += 0.1  # Active issue tracking
            
            # Factor in forks
            forks = repo_data.get('forks_count', 0)
            if forks >= 100:
                score += 0.2
            elif forks >= 10:
                score += 0.1
            
            return min(score, 1.0)  # Cap at 1.0
            
        except Exception as e:
            logger.warning(f"Failed to calculate activity score: {e}")
            return 0.0
    
    def validate_repository_access(self, owner: str, repo: str) -> bool:
        """
        Validate that repository exists and is accessible
        
        Args:
            owner: Repository owner
            repo: Repository name
            
        Returns:
            True if repository is accessible
            
        Raises:
            RepositoryNotFoundError: If repository doesn't exist
            RepositoryAccessDeniedError: If repository is not accessible
        """
        try:
            self.github_client.get_repository(owner, repo)
            logger.info(f"Repository {owner}/{repo} is accessible")
            return True
            
        except (RepositoryNotFoundError, RepositoryAccessDeniedError):
            # Re-raise these specific exceptions
            raise
        except Exception as e:
            logger.error(f"Unexpected error validating repository {owner}/{repo}: {e}")
            raise AnalysisError(f"Failed to validate repository access: {str(e)}")
    
    def extract_owner_repo(self, repository_url: str) -> Tuple[str, str]:
        """
        Extract owner and repo from GitHub URL
        
        Args:
            repository_url: GitHub repository URL
            
        Returns:
            Tuple of (owner, repo)
            
        Raises:
            AnalysisError: If URL format is invalid
        """
        try:
            # Handle various GitHub URL formats
            patterns = [
                r'github\.com[/:]([^/]+)/([^/\s\.]+)(?:\.git)?/?$',
                r'api\.github\.com/repos/([^/]+)/([^/\s]+)/?$'
            ]
            
            for pattern in patterns:
                match = re.search(pattern, repository_url.strip())
                if match:
                    owner, repo = match.groups()
                    # Clean up repo name (remove .git suffix if present)
                    repo = repo.rstrip('.git')
                    return owner, repo
            
            raise AnalysisError(f"Invalid GitHub repository URL format: {repository_url}")
            
        except Exception as e:
            logger.error(f"Failed to extract owner/repo from URL {repository_url}: {e}")
            raise AnalysisError(f"Failed to parse repository URL: {str(e)}")
