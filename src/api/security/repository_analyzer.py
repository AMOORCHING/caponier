"""
Repository validation and metadata extraction service

This module provides comprehensive repository analysis including:
- Repository existence and accessibility validation
- Detailed metadata extraction (commits, contributors, issues)
- Repository health assessment
- Security-relevant metadata collection
"""

import logging
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
import asyncio

from .github_client import get_github_client, GitHubAPIClient
from ..models import RepositoryMetadata
from ..utils.exceptions import (
    RepositoryNotFoundError, 
    RepositoryAccessDeniedError,
    GitHubAPIError,
    AnalysisError
)

logger = logging.getLogger(__name__)


class RepositoryAnalyzer:
    """
    Comprehensive repository analysis and validation service
    """
    
    def __init__(self, github_client: Optional[GitHubAPIClient] = None):
        """
        Initialize repository analyzer
        
        Args:
            github_client: Optional GitHub client (will create one if not provided)
        """
        self.github_client = github_client
        self._client_owned = github_client is None
    
    async def __aenter__(self):
        """Async context manager entry"""
        if self._client_owned:
            self.github_client = await get_github_client()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        # Only close if we own the client
        if self._client_owned and self.github_client:
            await self.github_client.close()
    
    async def validate_and_analyze_repository(self, repository_url: str) -> Dict[str, Any]:
        """
        Comprehensive repository validation and analysis
        
        Args:
            repository_url: GitHub repository URL
            
        Returns:
            Complete repository analysis data
            
        Raises:
            RepositoryNotFoundError: If repository doesn't exist
            RepositoryAccessDeniedError: If repository is not accessible
            AnalysisError: If analysis fails
        """
        try:
            # Extract owner and repo from URL
            owner, repo = self._extract_owner_repo(repository_url)
            
            logger.info(f"Starting repository analysis for {owner}/{repo}")
            
            # Validate repository exists and is accessible
            await self._validate_repository_access(owner, repo)
            
            # Get comprehensive repository metadata
            metadata = await self._extract_repository_metadata(owner, repo)
            
            # Get detailed commit information
            commit_info = await self._get_commit_analysis(owner, repo)
            
            # Get contributor analysis
            contributor_info = await self._get_contributor_analysis(owner, repo)
            
            # Get issue and security analysis
            issue_info = await self._get_issue_analysis(owner, repo)
            
            # Get repository structure analysis
            structure_info = await self._get_repository_structure(owner, repo)
            
            # Compile comprehensive analysis
            analysis_result = {
                "repository_url": repository_url,
                "owner": owner,
                "repository": repo,
                "metadata": metadata.dict(),
                "commits": commit_info,
                "contributors": contributor_info,
                "issues": issue_info,
                "structure": structure_info,
                "analysis_timestamp": datetime.utcnow().isoformat(),
                "security_indicators": self._assess_security_indicators(
                    metadata, commit_info, contributor_info, issue_info
                )
            }
            
            logger.info(f"Repository analysis completed for {owner}/{repo}")
            return analysis_result
            
        except (RepositoryNotFoundError, RepositoryAccessDeniedError):
            # Re-raise validation errors
            raise
        except Exception as e:
            logger.error(f"Repository analysis failed for {repository_url}: {str(e)}")
            raise AnalysisError(
                f"Failed to analyze repository: {str(e)}",
                stage="repository_analysis",
                original_error=e
            )
    
    def _extract_owner_repo(self, repository_url: str) -> tuple[str, str]:
        """
        Extract owner and repository name from GitHub URL
        
        Args:
            repository_url: GitHub repository URL
            
        Returns:
            Tuple of (owner, repository)
        """
        # Handle various GitHub URL formats
        if repository_url.startswith("https://github.com/"):
            path = repository_url.replace("https://github.com/", "")
        elif repository_url.startswith("github.com/"):
            path = repository_url.replace("github.com/", "")
        else:
            path = repository_url
        
        parts = path.strip("/").split("/")
        if len(parts) < 2:
            raise AnalysisError(
                f"Invalid repository URL format: {repository_url}",
                stage="url_parsing"
            )
        
        return parts[0], parts[1]
    
    async def _validate_repository_access(self, owner: str, repo: str):
        """
        Validate that repository exists and is accessible
        
        Args:
            owner: Repository owner
            repo: Repository name
            
        Raises:
            RepositoryNotFoundError: If repository doesn't exist
            RepositoryAccessDeniedError: If repository is not accessible
        """
        if not self.github_client:
            self.github_client = await get_github_client()
        
        exists = await self.github_client.check_repository_exists(owner, repo)
        if not exists:
            raise RepositoryNotFoundError(f"https://github.com/{owner}/{repo}")
    
    async def _extract_repository_metadata(self, owner: str, repo: str) -> RepositoryMetadata:
        """
        Extract comprehensive repository metadata
        
        Args:
            owner: Repository owner
            repo: Repository name
            
        Returns:
            Repository metadata
        """
        if not self.github_client:
            self.github_client = await get_github_client()
        
        return await self.github_client.get_repository_info(owner, repo)
    
    async def _get_commit_analysis(self, owner: str, repo: str) -> Dict[str, Any]:
        """
        Analyze repository commit history and activity
        
        Args:
            owner: Repository owner
            repo: Repository name
            
        Returns:
            Commit analysis data
        """
        try:
            if not self.github_client:
                self.github_client = await get_github_client()
            
            # Get recent commits (last 100)
            commits_data = await self.github_client._make_request(
                "GET", 
                f"repos/{owner}/{repo}/commits",
                params={"per_page": "100"}
            )
            
            if not commits_data:
                return {
                    "total_commits_analyzed": 0,
                    "last_commit_date": None,
                    "commit_frequency": "unknown",
                    "recent_activity": "none"
                }
            
            # Analyze commit patterns
            commit_dates = []
            committers = set()
            
            for commit in commits_data:
                if commit.get("commit", {}).get("author", {}).get("date"):
                    commit_date = self._parse_github_datetime(
                        commit["commit"]["author"]["date"]
                    )
                    if commit_date:
                        commit_dates.append(commit_date)
                
                # Track unique committers
                if commit.get("author", {}).get("login"):
                    committers.add(commit["author"]["login"])
            
            # Calculate commit frequency and activity
            frequency_analysis = self._analyze_commit_frequency(commit_dates)
            
            return {
                "total_commits_analyzed": len(commits_data),
                "last_commit_date": commit_dates[0].isoformat() if commit_dates else None,
                "unique_committers_recent": len(committers),
                "commit_frequency": frequency_analysis["frequency"],
                "commits_last_month": frequency_analysis["last_month"],
                "commits_last_week": frequency_analysis["last_week"],
                "recent_activity": frequency_analysis["activity_level"]
            }
            
        except Exception as e:
            logger.warning(f"Failed to analyze commits for {owner}/{repo}: {str(e)}")
            return {
                "total_commits_analyzed": 0,
                "last_commit_date": None,
                "commit_frequency": "unknown",
                "recent_activity": "unknown",
                "error": str(e)
            }
    
    async def _get_contributor_analysis(self, owner: str, repo: str) -> Dict[str, Any]:
        """
        Analyze repository contributors and collaboration patterns
        
        Args:
            owner: Repository owner
            repo: Repository name
            
        Returns:
            Contributor analysis data
        """
        try:
            if not self.github_client:
                self.github_client = await get_github_client()
            
            # Get contributors
            contributors_data = await self.github_client._make_request(
                "GET",
                f"repos/{owner}/{repo}/contributors",
                params={"per_page": "100"}
            )
            
            if not contributors_data:
                return {
                    "total_contributors": 0,
                    "active_contributors": 0,
                    "collaboration_level": "unknown"
                }
            
            # Analyze contributor distribution
            total_contributors = len(contributors_data)
            top_contributors = contributors_data[:10]  # Top 10 contributors
            
            # Calculate contribution distribution
            total_contributions = sum(c.get("contributions", 0) for c in contributors_data)
            top_10_contributions = sum(c.get("contributions", 0) for c in top_contributors)
            
            concentration_ratio = (
                top_10_contributions / total_contributions 
                if total_contributions > 0 else 0
            )
            
            # Assess collaboration level
            if total_contributors == 1:
                collaboration_level = "solo"
            elif total_contributors < 5:
                collaboration_level = "small_team"
            elif total_contributors < 20:
                collaboration_level = "medium_team"
            else:
                collaboration_level = "large_community"
            
            return {
                "total_contributors": total_contributors,
                "active_contributors": min(total_contributors, 10),
                "collaboration_level": collaboration_level,
                "contribution_concentration": round(concentration_ratio, 2),
                "top_contributors": [
                    {
                        "login": c.get("login"),
                        "contributions": c.get("contributions", 0)
                    }
                    for c in top_contributors[:5]  # Top 5 for summary
                ]
            }
            
        except Exception as e:
            logger.warning(f"Failed to analyze contributors for {owner}/{repo}: {str(e)}")
            return {
                "total_contributors": 0,
                "active_contributors": 0,
                "collaboration_level": "unknown",
                "error": str(e)
            }
    
    async def _get_issue_analysis(self, owner: str, repo: str) -> Dict[str, Any]:
        """
        Analyze repository issues and maintenance indicators
        
        Args:
            owner: Repository owner
            repo: Repository name
            
        Returns:
            Issue analysis data
        """
        try:
            if not self.github_client:
                self.github_client = await get_github_client()
            
            # Get recent issues (both open and closed)
            open_issues = await self.github_client._make_request(
                "GET",
                f"repos/{owner}/{repo}/issues",
                params={"state": "open", "per_page": "100"}
            )
            
            closed_issues = await self.github_client._make_request(
                "GET",
                f"repos/{owner}/{repo}/issues",
                params={"state": "closed", "per_page": "100"}
            )
            
            # Analyze issue patterns
            security_related = 0
            bug_related = 0
            total_open = len(open_issues) if open_issues else 0
            total_closed = len(closed_issues) if closed_issues else 0
            
            # Look for security-related issues
            security_keywords = ["security", "vulnerability", "cve", "exploit", "malicious"]
            bug_keywords = ["bug", "error", "crash", "fail"]
            
            for issue in (open_issues or []):
                title = issue.get("title", "").lower()
                body = issue.get("body", "").lower()
                text = f"{title} {body}"
                
                if any(keyword in text for keyword in security_keywords):
                    security_related += 1
                elif any(keyword in text for keyword in bug_keywords):
                    bug_related += 1
            
            # Calculate issue resolution ratio
            total_issues = total_open + total_closed
            resolution_ratio = total_closed / total_issues if total_issues > 0 else 0
            
            return {
                "open_issues": total_open,
                "closed_issues": total_closed,
                "security_related_issues": security_related,
                "bug_related_issues": bug_related,
                "issue_resolution_ratio": round(resolution_ratio, 2),
                "maintenance_activity": self._assess_maintenance_activity(
                    total_open, total_closed, resolution_ratio
                )
            }
            
        except Exception as e:
            logger.warning(f"Failed to analyze issues for {owner}/{repo}: {str(e)}")
            return {
                "open_issues": 0,
                "closed_issues": 0,
                "security_related_issues": 0,
                "bug_related_issues": 0,
                "issue_resolution_ratio": 0,
                "maintenance_activity": "unknown",
                "error": str(e)
            }
    
    async def _get_repository_structure(self, owner: str, repo: str) -> Dict[str, Any]:
        """
        Analyze repository structure and identify dependency files
        
        Args:
            owner: Repository owner
            repo: Repository name
            
        Returns:
            Repository structure analysis
        """
        try:
            if not self.github_client:
                self.github_client = await get_github_client()
            
            # Get root directory contents
            files = await self.github_client.get_repository_files(owner, repo)
            
            # Identify dependency files and project types
            dependency_files = []
            project_types = []
            has_security_files = False
            
            dependency_patterns = {
                "package.json": "Node.js/npm",
                "package-lock.json": "Node.js/npm",
                "yarn.lock": "Node.js/Yarn",
                "requirements.txt": "Python/pip",
                "Pipfile": "Python/Pipenv",
                "poetry.lock": "Python/Poetry",
                "Cargo.toml": "Rust/Cargo",
                "Cargo.lock": "Rust/Cargo",
                "pom.xml": "Java/Maven",
                "build.gradle": "Java/Gradle",
                "go.mod": "Go",
                "composer.json": "PHP/Composer",
                "Gemfile": "Ruby/Bundler"
            }
            
            security_files = [
                "SECURITY.md", "security.md", ".github/SECURITY.md",
                "CODE_OF_CONDUCT.md", "CONTRIBUTING.md"
            ]
            
            for file_info in files:
                file_name = file_info.get("name", "")
                
                # Check for dependency files
                if file_name in dependency_patterns:
                    dependency_files.append({
                        "file": file_name,
                        "type": dependency_patterns[file_name],
                        "path": file_info.get("path", file_name)
                    })
                    
                    if dependency_patterns[file_name] not in project_types:
                        project_types.append(dependency_patterns[file_name])
                
                # Check for security-related files
                if file_name in security_files:
                    has_security_files = True
            
            return {
                "dependency_files": dependency_files,
                "project_types": project_types,
                "has_security_policy": has_security_files,
                "total_files": len(files)
            }
            
        except Exception as e:
            logger.warning(f"Failed to analyze repository structure for {owner}/{repo}: {str(e)}")
            return {
                "dependency_files": [],
                "project_types": [],
                "has_security_policy": False,
                "total_files": 0,
                "error": str(e)
            }
    
    def _parse_github_datetime(self, date_str: str) -> Optional[datetime]:
        """Parse GitHub API datetime string"""
        try:
            return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        except (ValueError, AttributeError):
            return None
    
    def _analyze_commit_frequency(self, commit_dates: List[datetime]) -> Dict[str, Any]:
        """
        Analyze commit frequency patterns
        
        Args:
            commit_dates: List of commit dates (sorted newest first)
            
        Returns:
            Frequency analysis
        """
        if not commit_dates:
            return {
                "frequency": "none",
                "last_month": 0,
                "last_week": 0,
                "activity_level": "inactive"
            }
        
        now = datetime.now(commit_dates[0].tzinfo)
        last_week = now - timedelta(days=7)
        last_month = now - timedelta(days=30)
        
        commits_last_week = sum(1 for date in commit_dates if date >= last_week)
        commits_last_month = sum(1 for date in commit_dates if date >= last_month)
        
        # Determine frequency
        if commits_last_week >= 5:
            frequency = "very_high"
            activity_level = "very_active"
        elif commits_last_week >= 2:
            frequency = "high"
            activity_level = "active"
        elif commits_last_month >= 5:
            frequency = "moderate"
            activity_level = "moderately_active"
        elif commits_last_month >= 1:
            frequency = "low"
            activity_level = "low_activity"
        else:
            frequency = "very_low"
            activity_level = "inactive"
        
        return {
            "frequency": frequency,
            "last_month": commits_last_month,
            "last_week": commits_last_week,
            "activity_level": activity_level
        }
    
    def _assess_maintenance_activity(
        self, 
        open_issues: int, 
        closed_issues: int, 
        resolution_ratio: float
    ) -> str:
        """
        Assess repository maintenance activity level
        
        Args:
            open_issues: Number of open issues
            closed_issues: Number of closed issues
            resolution_ratio: Ratio of closed to total issues
            
        Returns:
            Maintenance activity assessment
        """
        if resolution_ratio >= 0.8 and closed_issues > 0:
            return "excellent"
        elif resolution_ratio >= 0.6 and closed_issues > 0:
            return "good"
        elif resolution_ratio >= 0.4:
            return "moderate"
        elif open_issues > 20:
            return "poor"
        else:
            return "minimal"
    
    def _assess_security_indicators(
        self,
        metadata: RepositoryMetadata,
        commit_info: Dict[str, Any],
        contributor_info: Dict[str, Any],
        issue_info: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Assess security-relevant indicators from repository analysis
        
        Args:
            metadata: Repository metadata
            commit_info: Commit analysis results
            contributor_info: Contributor analysis results
            issue_info: Issue analysis results
            
        Returns:
            Security indicators assessment
        """
        indicators = {
            "activity_score": 0,
            "maintenance_score": 0,
            "community_score": 0,
            "security_awareness": 0,
            "overall_health": "unknown"
        }
        
        try:
            # Activity score (0-10)
            activity_level = commit_info.get("recent_activity", "unknown")
            activity_scores = {
                "very_active": 10,
                "active": 8,
                "moderately_active": 6,
                "low_activity": 4,
                "inactive": 1,
                "unknown": 0
            }
            indicators["activity_score"] = activity_scores.get(activity_level, 0)
            
            # Maintenance score (0-10)
            maintenance = issue_info.get("maintenance_activity", "unknown")
            maintenance_scores = {
                "excellent": 10,
                "good": 8,
                "moderate": 6,
                "poor": 3,
                "minimal": 1,
                "unknown": 0
            }
            indicators["maintenance_score"] = maintenance_scores.get(maintenance, 0)
            
            # Community score (0-10)
            contributors = contributor_info.get("total_contributors", 0)
            if contributors >= 50:
                indicators["community_score"] = 10
            elif contributors >= 20:
                indicators["community_score"] = 8
            elif contributors >= 10:
                indicators["community_score"] = 6
            elif contributors >= 5:
                indicators["community_score"] = 4
            elif contributors >= 2:
                indicators["community_score"] = 2
            else:
                indicators["community_score"] = 1
            
            # Security awareness (0-10)
            security_issues = issue_info.get("security_related_issues", 0)
            if security_issues > 0:
                indicators["security_awareness"] = min(10, security_issues * 2)
            else:
                indicators["security_awareness"] = 5  # Neutral
            
            # Overall health assessment
            avg_score = (
                indicators["activity_score"] + 
                indicators["maintenance_score"] + 
                indicators["community_score"]
            ) / 3
            
            if avg_score >= 8:
                indicators["overall_health"] = "excellent"
            elif avg_score >= 6:
                indicators["overall_health"] = "good"
            elif avg_score >= 4:
                indicators["overall_health"] = "moderate"
            elif avg_score >= 2:
                indicators["overall_health"] = "poor"
            else:
                indicators["overall_health"] = "concerning"
            
        except Exception as e:
            logger.warning(f"Failed to assess security indicators: {str(e)}")
        
        return indicators
