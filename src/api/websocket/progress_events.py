"""
Progress event definitions for WebSocket updates

This module defines the progress events and messages that are sent
during different stages of repository security analysis.
"""

from typing import Dict, Any, Optional, List
from enum import Enum
from datetime import datetime


class AnalysisStage(Enum):
    """Enumeration of analysis stages with their progress percentages"""
    
    # Initial stages (0-10%)
    INITIALIZATION = "initialization"
    REPOSITORY_VALIDATION = "repository_validation"
    REPOSITORY_METADATA = "repository_metadata"
    
    # Dependency analysis (10-30%)
    DEPENDENCY_SCANNING = "dependency_scanning"
    DEPENDENCY_DISCOVERY = "dependency_discovery"
    DEPENDENCY_PARSING = "dependency_parsing"
    DEPENDENCY_AGGREGATION = "dependency_aggregation"
    
    # Vulnerability analysis (30-70%)
    VULNERABILITY_LOOKUP = "vulnerability_lookup"
    VULNERABILITY_SCANNING = "vulnerability_scanning"
    VULNERABILITY_FILTERING = "vulnerability_filtering"
    CVE_ENRICHMENT = "cve_enrichment"
    CVSS_ANALYSIS = "cvss_analysis"
    
    # Scoring and reporting (70-100%)
    SCORING_CALCULATION = "scoring_calculation"
    RISK_ASSESSMENT = "risk_assessment"
    REPORT_GENERATION = "report_generation"
    RECOMMENDATION_GENERATION = "recommendation_generation"
    COMPLETION = "completion"
    
    # Error states
    ERROR = "error"
    RETRY = "retry"


class ProgressEvent:
    """Base class for progress events"""
    
    def __init__(
        self,
        stage: AnalysisStage,
        progress_percentage: int,
        message: str,
        details: Optional[Dict[str, Any]] = None
    ):
        self.stage = stage
        self.progress_percentage = progress_percentage
        self.message = message
        self.details = details or {}
        self.timestamp = datetime.utcnow()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary for WebSocket transmission"""
        return {
            "stage": self.stage.value,
            "progress_percentage": self.progress_percentage,
            "message": self.message,
            "details": self.details,
            "timestamp": self.timestamp.isoformat()
        }


class ProgressEventFactory:
    """Factory for creating progress events with predefined messages"""
    
    @staticmethod
    def initialization(job_id: str) -> ProgressEvent:
        """Create initialization event"""
        return ProgressEvent(
            stage=AnalysisStage.INITIALIZATION,
            progress_percentage=0,
            message="🚀 Starting security analysis...",
            details={
                "job_id": job_id,
                "stage_description": "Setting up analysis environment and validating inputs",
                "estimated_duration": "2-3 minutes",
                "next_stage": "repository_validation"
            }
        )
    
    @staticmethod
    def repository_validation(repository_url: str, owner: str, repo: str) -> ProgressEvent:
        """Create repository validation event"""
        return ProgressEvent(
            stage=AnalysisStage.REPOSITORY_VALIDATION,
            progress_percentage=5,
            message=f"🔍 Validating repository {owner}/{repo}...",
            details={
                "repository_url": repository_url,
                "owner": owner,
                "repository": repo,
                "stage_description": "Verifying repository accessibility and extracting metadata",
                "next_stage": "repository_metadata"
            }
        )
    
    @staticmethod
    def repository_metadata(owner: str, repo: str, last_commit: str = None, contributors: int = None) -> ProgressEvent:
        """Create repository metadata extraction event"""
        message = f"📊 Extracting metadata from {owner}/{repo}..."
        if last_commit:
            message += f" (Last commit: {last_commit})"
        
        return ProgressEvent(
            stage=AnalysisStage.REPOSITORY_METADATA,
            progress_percentage=8,
            message=message,
            details={
                "owner": owner,
                "repository": repo,
                "last_commit_date": last_commit,
                "contributor_count": contributors,
                "stage_description": "Analyzing repository activity and contributor information",
                "next_stage": "dependency_scanning"
            }
        )
    
    @staticmethod
    def dependency_scanning(owner: str, repo: str) -> ProgressEvent:
        """Create dependency scanning event"""
        return ProgressEvent(
            stage=AnalysisStage.DEPENDENCY_SCANNING,
            progress_percentage=15,
            message=f"🔎 Scanning for dependency files in {owner}/{repo}...",
            details={
                "owner": owner,
                "repository": repo,
                "stage_description": "Discovering package manifest files (package.json, requirements.txt, etc.)",
                "next_stage": "dependency_discovery"
            }
        )
    
    @staticmethod
    def dependency_discovery(ecosystems_found: List[str]) -> ProgressEvent:
        """Create dependency discovery event"""
        ecosystem_names = ", ".join(ecosystems_found) if ecosystems_found else "None found"
        return ProgressEvent(
            stage=AnalysisStage.DEPENDENCY_DISCOVERY,
            progress_percentage=18,
            message=f"📦 Found dependency files: {ecosystem_names}",
            details={
                "ecosystems_found": ecosystems_found,
                "stage_description": "Identified package ecosystems and manifest files",
                "next_stage": "dependency_parsing"
            }
        )
    
    @staticmethod
    def dependency_parsing(ecosystem: str, file_count: int, dependency_count: int = 0) -> ProgressEvent:
        """Create dependency parsing event"""
        message = f"📋 Parsing {ecosystem} dependencies from {file_count} files..."
        if dependency_count > 0:
            message += f" Found {dependency_count} dependencies"
        
        return ProgressEvent(
            stage=AnalysisStage.DEPENDENCY_PARSING,
            progress_percentage=25,
            message=message,
            details={
                "ecosystem": ecosystem,
                "files_processed": file_count,
                "dependencies_found": dependency_count,
                "stage_description": "Extracting dependency information from manifest files",
                "next_stage": "dependency_aggregation"
            }
        )
    
    @staticmethod
    def dependency_aggregation(total_dependencies: int, ecosystems: List[str]) -> ProgressEvent:
        """Create dependency aggregation event"""
        ecosystem_list = ", ".join(ecosystems)
        return ProgressEvent(
            stage=AnalysisStage.DEPENDENCY_AGGREGATION,
            progress_percentage=28,
            message=f"📊 Aggregating {total_dependencies} dependencies from {ecosystem_list}",
            details={
                "total_dependencies": total_dependencies,
                "ecosystems": ecosystems,
                "stage_description": "Combining dependencies from all ecosystems for analysis",
                "next_stage": "vulnerability_lookup"
            }
        )
    
    @staticmethod
    def vulnerability_lookup(dependency_count: int) -> ProgressEvent:
        """Create vulnerability lookup event"""
        return ProgressEvent(
            stage=AnalysisStage.VULNERABILITY_LOOKUP,
            progress_percentage=35,
            message=f"🔍 Checking {dependency_count} dependencies for known vulnerabilities...",
            details={
                "dependencies_to_scan": dependency_count,
                "stage_description": "Querying National Vulnerability Database (NVD) for known CVEs",
                "next_stage": "vulnerability_scanning"
            }
        )
    
    @staticmethod
    def vulnerability_scanning_batch(
        batch_number: int, 
        total_batches: int, 
        batch_size: int,
        vulnerabilities_found: int
    ) -> ProgressEvent:
        """Create vulnerability scanning batch event"""
        progress = 40 + int((batch_number / total_batches) * 20)  # 40-60% range
        
        message = f"🔍 Scanning batch {batch_number}/{total_batches} ({batch_size} dependencies)..."
        if vulnerabilities_found > 0:
            message += f" Found {vulnerabilities_found} vulnerabilities so far"
        
        return ProgressEvent(
            stage=AnalysisStage.VULNERABILITY_SCANNING,
            progress_percentage=progress,
            message=message,
            details={
                "batch_number": batch_number,
                "total_batches": total_batches,
                "batch_size": batch_size,
                "vulnerabilities_found_so_far": vulnerabilities_found,
                "stage_description": "Processing dependencies in batches for vulnerability detection",
                "next_stage": "vulnerability_filtering"
            }
        )
    
    @staticmethod
    def vulnerability_filtering(total_vulnerabilities: int, critical_count: int, high_count: int) -> ProgressEvent:
        """Create vulnerability filtering event"""
        message = f"⚡ Filtering {total_vulnerabilities} vulnerabilities..."
        if critical_count > 0 or high_count > 0:
            message += f" Found {critical_count} critical, {high_count} high severity"
        
        return ProgressEvent(
            stage=AnalysisStage.VULNERABILITY_FILTERING,
            progress_percentage=60,
            message=message,
            details={
                "total_vulnerabilities": total_vulnerabilities,
                "critical_vulnerabilities": critical_count,
                "high_vulnerabilities": high_count,
                "stage_description": "Filtering vulnerabilities by severity (Critical and High only)",
                "next_stage": "cve_enrichment"
            }
        )
    
    @staticmethod
    def cve_enrichment(vulnerability_count: int) -> ProgressEvent:
        """Create CVE enrichment event"""
        return ProgressEvent(
            stage=AnalysisStage.CVE_ENRICHMENT,
            progress_percentage=65,
            message=f"📚 Enriching {vulnerability_count} vulnerabilities with CVE details...",
            details={
                "vulnerabilities_to_enrich": vulnerability_count,
                "stage_description": "Fetching detailed CVE information and CVSS scores",
                "next_stage": "cvss_analysis"
            }
        )
    
    @staticmethod
    def cvss_analysis(vulnerability_count: int, avg_cvss_score: float = None) -> ProgressEvent:
        """Create CVSS analysis event"""
        message = f"📊 Analyzing CVSS scores for {vulnerability_count} vulnerabilities..."
        if avg_cvss_score:
            message += f" Average score: {avg_cvss_score:.1f}"
        
        return ProgressEvent(
            stage=AnalysisStage.CVSS_ANALYSIS,
            progress_percentage=68,
            message=message,
            details={
                "vulnerabilities_analyzed": vulnerability_count,
                "average_cvss_score": avg_cvss_score,
                "stage_description": "Calculating CVSS scores and impact analysis",
                "next_stage": "scoring_calculation"
            }
        )
    
    @staticmethod
    def scoring_calculation(vulnerability_count: int, dependency_count: int) -> ProgressEvent:
        """Create scoring calculation event"""
        return ProgressEvent(
            stage=AnalysisStage.SCORING_CALCULATION,
            progress_percentage=75,
            message=f"🧮 Calculating security score for {vulnerability_count} vulnerabilities and {dependency_count} dependencies...",
            details={
                "vulnerability_count": vulnerability_count,
                "dependency_count": dependency_count,
                "stage_description": "Computing weighted security score and risk assessment",
                "next_stage": "risk_assessment"
            }
        )
    
    @staticmethod
    def risk_assessment(security_score: float, risk_level: str) -> ProgressEvent:
        """Create risk assessment event"""
        emoji = "🔴" if risk_level == "HIGH" else "🟡" if risk_level == "MEDIUM" else "🟢"
        return ProgressEvent(
            stage=AnalysisStage.RISK_ASSESSMENT,
            progress_percentage=78,
            message=f"{emoji} Risk assessment: {risk_level} risk (Score: {security_score:.1f})",
            details={
                "security_score": security_score,
                "risk_level": risk_level,
                "stage_description": "Determining overall risk level based on security score",
                "next_stage": "report_generation"
            }
        )
    
    @staticmethod
    def report_generation(security_score: float) -> ProgressEvent:
        """Create report generation event"""
        return ProgressEvent(
            stage=AnalysisStage.REPORT_GENERATION,
            progress_percentage=85,
            message=f"📄 Generating comprehensive security report (Score: {security_score:.1f})...",
            details={
                "security_score": security_score,
                "stage_description": "Creating detailed analysis report with vulnerability breakdown",
                "next_stage": "recommendation_generation"
            }
        )
    
    @staticmethod
    def recommendation_generation(vulnerability_count: int) -> ProgressEvent:
        """Create recommendation generation event"""
        return ProgressEvent(
            stage=AnalysisStage.RECOMMENDATION_GENERATION,
            progress_percentage=90,
            message=f"💡 Generating actionable recommendations for {vulnerability_count} vulnerabilities...",
            details={
                "vulnerabilities_with_recommendations": vulnerability_count,
                "stage_description": "Creating specific recommendations for vulnerability remediation",
                "next_stage": "completion"
            }
        )
    
    @staticmethod
    def completion(
        vulnerability_count: int, 
        security_score: float, 
        analysis_duration: float
    ) -> ProgressEvent:
        """Create completion event"""
        duration_str = f"{analysis_duration:.1f}s" if analysis_duration < 60 else f"{analysis_duration/60:.1f}m"
        
        if vulnerability_count == 0:
            message = f"✅ Analysis completed! No vulnerabilities found. Security score: {security_score:.1f} ({duration_str})"
        else:
            message = f"✅ Analysis completed! Found {vulnerability_count} vulnerabilities. Security score: {security_score:.1f} ({duration_str})"
        
        return ProgressEvent(
            stage=AnalysisStage.COMPLETION,
            progress_percentage=100,
            message=message,
            details={
                "vulnerabilities_found": vulnerability_count,
                "security_score": security_score,
                "analysis_duration_seconds": analysis_duration,
                "analysis_duration_formatted": duration_str,
                "stage_description": "Analysis completed successfully",
                "status": "completed"
            }
        )
    
    @staticmethod
    def error(stage: AnalysisStage, error_message: str, error_details: Optional[Dict[str, Any]] = None) -> ProgressEvent:
        """Create error event"""
        # Map stages to user-friendly names
        stage_names = {
            AnalysisStage.REPOSITORY_VALIDATION: "repository validation",
            AnalysisStage.DEPENDENCY_SCANNING: "dependency scanning",
            AnalysisStage.VULNERABILITY_LOOKUP: "vulnerability lookup",
            AnalysisStage.SCORING_CALCULATION: "scoring calculation"
        }
        
        stage_name = stage_names.get(stage, stage.value.replace("_", " "))
        
        return ProgressEvent(
            stage=AnalysisStage.ERROR,
            progress_percentage=0,
            message=f"❌ Error during {stage_name}: {error_message}",
            details={
                "failed_stage": stage.value,
                "failed_stage_name": stage_name,
                "error_message": error_message,
                "error_details": error_details or {},
                "stage_description": "Analysis encountered an error",
                "status": "failed"
            }
        )
    
    @staticmethod
    def retry(stage: AnalysisStage, retry_attempt: int, max_retries: int) -> ProgressEvent:
        """Create retry event"""
        # Map stages to user-friendly names
        stage_names = {
            AnalysisStage.REPOSITORY_VALIDATION: "repository validation",
            AnalysisStage.DEPENDENCY_SCANNING: "dependency scanning",
            AnalysisStage.VULNERABILITY_LOOKUP: "vulnerability lookup",
            AnalysisStage.SCORING_CALCULATION: "scoring calculation"
        }
        
        stage_name = stage_names.get(stage, stage.value.replace("_", " "))
        
        return ProgressEvent(
            stage=AnalysisStage.RETRY,
            progress_percentage=0,
            message=f"🔄 Retrying {stage_name} (attempt {retry_attempt}/{max_retries})...",
            details={
                "retry_stage": stage.value,
                "retry_stage_name": stage_name,
                "retry_attempt": retry_attempt,
                "max_retries": max_retries,
                "stage_description": "Retrying failed operation",
                "status": "retrying"
            }
        )


# Convenience functions for common progress updates
def create_progress_update(
    job_id: str,
    stage: AnalysisStage,
    progress_percentage: int,
    message: str,
    details: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Create a progress update message for WebSocket transmission
    
    Args:
        job_id: The job ID
        stage: Current analysis stage
        progress_percentage: Progress percentage (0-100)
        message: Human-readable message
        details: Optional additional details
        
    Returns:
        Dictionary ready for WebSocket transmission
    """
    return {
        "job_id": job_id,
        "stage": stage.value,
        "progress_percentage": progress_percentage,
        "message": message,
        "details": details or {},
        "timestamp": datetime.utcnow().isoformat()
    }
