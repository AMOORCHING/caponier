from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum
from pydantic import BaseModel, HttpUrl, Field, validator


class SeverityLevel(str, Enum):
    """Vulnerability severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class JobStatus(str, Enum):
    """Analysis job status"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"


class AnalysisRequest(BaseModel):
    """Request model for repository analysis"""
    repository_url: str = Field(..., description="GitHub repository URL")
    
    @validator('repository_url')
    def validate_github_url(cls, v):
        """Validate and normalize GitHub repository URL"""
        if not v:
            raise ValueError("Repository URL is required")
        
        # Remove trailing slash and normalize
        v = v.strip().rstrip('/')
        
        # Convert various GitHub URL formats to standard format
        if v.startswith('https://github.com/'):
            return v
        elif v.startswith('github.com/'):
            return f"https://{v}"
        elif '/' in v and not v.startswith('http'):
            # Assume owner/repo format
            return f"https://github.com/{v}"
        else:
            raise ValueError("Invalid GitHub repository URL format")


class VulnerabilityData(BaseModel):
    """Individual vulnerability information"""
    cve_id: str = Field(..., description="CVE identifier")
    package_name: str = Field(..., description="Affected package name")
    package_version: str = Field(..., description="Affected package version")
    severity: SeverityLevel = Field(..., description="Vulnerability severity level")
    cvss_score: Optional[float] = Field(None, description="CVSS base score")
    description: str = Field(..., description="Vulnerability description")
    cve_url: str = Field(..., description="Link to CVE database entry")
    published_date: Optional[datetime] = Field(None, description="CVE publication date")
    last_modified: Optional[datetime] = Field(None, description="CVE last modified date")


class DependencyInfo(BaseModel):
    """Dependency package information"""
    name: str = Field(..., description="Package name")
    version: str = Field(..., description="Package version")
    ecosystem: str = Field(..., description="Package ecosystem (npm, pip, cargo, etc.)")
    manifest_file: str = Field(..., description="Source manifest file")


class RepositoryMetadata(BaseModel):
    """GitHub repository metadata"""
    owner: str = Field(..., description="Repository owner")
    name: str = Field(..., description="Repository name")
    full_name: str = Field(..., description="Full repository name (owner/repo)")
    description: Optional[str] = Field(None, description="Repository description")
    language: Optional[str] = Field(None, description="Primary programming language")
    stars: int = Field(0, description="Number of stars")
    forks: int = Field(0, description="Number of forks")
    last_commit_date: Optional[datetime] = Field(None, description="Last commit date")
    contributor_count: int = Field(0, description="Number of contributors")
    open_issues_count: int = Field(0, description="Number of open issues")
    created_at: Optional[datetime] = Field(None, description="Repository creation date")
    updated_at: Optional[datetime] = Field(None, description="Repository last update date")


class SecurityScore(BaseModel):
    """Security scoring breakdown"""
    overall_score: int = Field(..., ge=0, le=100, description="Overall security score (0-100)")
    vulnerability_score: int = Field(..., description="Score based on vulnerabilities")
    maintenance_score: int = Field(..., description="Score based on maintenance indicators")
    critical_vulnerabilities: int = Field(0, description="Number of critical vulnerabilities")
    high_vulnerabilities: int = Field(0, description="Number of high vulnerabilities")
    score_breakdown: Dict[str, Any] = Field(..., description="Detailed score calculation")
    comparative_context: str = Field(..., description="Comparison with similar repositories")


class RecommendationItem(BaseModel):
    """Individual security recommendation"""
    category: str = Field(..., description="Recommendation category")
    priority: str = Field(..., description="Priority level (high, medium, low)")
    title: str = Field(..., description="Recommendation title")
    description: str = Field(..., description="Detailed recommendation description")
    action_items: List[str] = Field(..., description="Specific action items")


class AnalysisProgress(BaseModel):
    """Real-time analysis progress"""
    job_id: str = Field(..., description="Analysis job identifier")
    status: JobStatus = Field(..., description="Current job status")
    progress_percentage: int = Field(..., ge=0, le=100, description="Progress percentage")
    current_stage: str = Field(..., description="Current analysis stage")
    stage_message: str = Field(..., description="Detailed stage message")
    started_at: datetime = Field(..., description="Analysis start time")
    estimated_completion: Optional[datetime] = Field(None, description="Estimated completion time")


class AnalysisResult(BaseModel):
    """Complete analysis result"""
    job_id: str = Field(..., description="Analysis job identifier")
    repository_url: str = Field(..., description="Analyzed repository URL")
    repository_metadata: RepositoryMetadata = Field(..., description="Repository information")
    dependencies: List[DependencyInfo] = Field(..., description="Discovered dependencies")
    vulnerabilities: List[VulnerabilityData] = Field(..., description="Found vulnerabilities")
    security_score: SecurityScore = Field(..., description="Security scoring details")
    recommendations: List[RecommendationItem] = Field(..., description="Security recommendations")
    analysis_timestamp: datetime = Field(..., description="Analysis completion timestamp")
    analysis_duration: float = Field(..., description="Analysis duration in seconds")
    share_url: Optional[str] = Field(None, description="Shareable result URL")


class AnalysisResponse(BaseModel):
    """Response for analysis initiation"""
    job_id: str = Field(..., description="Analysis job identifier")
    status: JobStatus = Field(..., description="Initial job status")
    repository_url: str = Field(..., description="Repository URL being analyzed")
    estimated_duration: int = Field(..., description="Estimated analysis duration in seconds")
    progress_url: str = Field(..., description="WebSocket URL for progress updates")
    result_url: str = Field(..., description="URL to retrieve results")


class SecurityBadge(BaseModel):
    """Embeddable security badge"""
    svg_content: str = Field(..., description="SVG badge content")
    markdown_snippet: str = Field(..., description="Markdown embedding snippet")
    html_snippet: str = Field(..., description="HTML embedding snippet")
    badge_url: str = Field(..., description="Direct badge image URL")


class ErrorResponse(BaseModel):
    """API error response"""
    error_code: str = Field(..., description="Error code identifier")
    message: str = Field(..., description="Human-readable error message")
    details: Optional[Dict[str, Any]] = Field(None, description="Additional error details")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Error timestamp")


class HealthCheckResponse(BaseModel):
    """Health check response"""
    status: str = Field(..., description="Service status")
    service: str = Field(..., description="Service name")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Health check timestamp")
    dependencies: Optional[Dict[str, str]] = Field(None, description="Dependency status")