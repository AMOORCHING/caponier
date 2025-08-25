"""
Celery task definitions for repository security analysis

Defines background tasks for analyzing repositories, scanning dependencies,
checking vulnerabilities, and generating security reports.
"""

import logging
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
import traceback

from celery import current_task
from celery.exceptions import Retry

from ..config import celery_app, redis_manager
from ..models import AnalysisResult, VulnerabilityData, SecurityScore, JobStatus
from ..jobs.job_manager import JobManager
from ..jobs.worker import CaponierTask
from ..security.repository_analyzer import RepositoryAnalyzer
from ..security.dependency_parser import DependencyParser
from ..security.vulnerability_scanner import VulnerabilityScanner
from ..security.scoring import SecurityScorer
from ..security.reporting import ReportGenerator
from ..utils.exceptions import AnalysisError, RepositoryError, VulnerabilityLookupError

logger = logging.getLogger(__name__)

# Initialize components
job_manager = JobManager(redis_manager)


@celery_app.task(bind=True, base=CaponierTask, name='caponier.analysis.analyze_repository', time_limit=300, soft_time_limit=270)
def analyze_repository_task(self, job_id: str, repository_url: str, owner: str, repo: str) -> Dict[str, Any]:
    """
    Main task for complete repository security analysis
    
    Coordinates the full analysis pipeline including repository validation,
    dependency scanning, vulnerability checking, and report generation.
    
    Args:
        job_id: Unique job identifier
        repository_url: Repository URL to analyze
        owner: Repository owner
        repo: Repository name
        
    Returns:
        Dictionary with analysis results
        
    Raises:
        AnalysisError: If analysis fails
    """
    worker_id = self.worker_id or "unknown"
    
    def run_analysis():
        """Synchronous analysis pipeline for Celery worker"""
        logger.info(f"Starting repository analysis for job {job_id}: {repository_url}")
        


        # Start job processing
        if not job_manager.start_job_processing(job_id, worker_id):
            raise AnalysisError(f"Could not acquire lock for job {job_id}", job_id=job_id)
        
        # Initialize analysis components with synchronous versions
        from ..security.repository_analyzer_sync import SyncRepositoryAnalyzer
        from ..security.dependency_parser_sync import SyncDependencyParser
        from ..security.vulnerability_scanner_sync import SyncVulnerabilityScanner
        from ..security.scoring import SecurityScorer
        from ..security.reporting import ReportGenerator
        from ..security.github_client_sync import SyncGitHubClient
        
        def execute_stage(stage_name: str, stage_func, *args, **kwargs):
            """Execute an analysis stage with error handling and retry logic"""
            try:
                return stage_func(*args, **kwargs)
            except Exception as e:
                logger.error(f"Stage {stage_name} failed for job {job_id}: {e}")
                # Use the task's intelligent retry logic
                self.handle_task_error(e, job_id, stage_name)
                # If we get here, the error was not retryable
                raise
        
        # Stage 1: Repository validation and metadata extraction
        job_manager.update_job_progress(
            job_id=job_id,
            progress_percentage=10,
            current_stage="repository_validation",
            stage_message="Validating repository and extracting metadata..."
        )
        
        repo_analyzer = SyncRepositoryAnalyzer()
        try:
            repo_metadata = repo_analyzer.analyze_repository(repository_url, owner, repo)
            logger.info(f"Repository metadata extracted for {owner}/{repo}: {repo_metadata.last_commit_date}")
        finally:
            repo_analyzer.close()
        
        # Stage 2: Dependency scanning
        job_manager.update_job_progress(
            job_id=job_id,
            progress_percentage=25,
            current_stage="dependency_scanning",
            stage_message="Scanning repository dependencies..."
        )
        
        github_client = SyncGitHubClient()
        try:
            dependency_parser = SyncDependencyParser(github_client)
            dependencies = dependency_parser.parse_repository_dependencies(owner, repo)
        finally:
            github_client.close()
            
        logger.info(f"Found {len(dependencies)} dependencies in {owner}/{repo}")
        
        # Stage 3: Vulnerability scanning
        job_manager.update_job_progress(
            job_id=job_id,
            progress_percentage=50,
            current_stage="vulnerability_lookup",
            stage_message="Checking dependencies for known vulnerabilities..."
        )
        
        vulnerabilities = []
        
        # Use the vulnerability scanner's batch processing capability
        if dependencies:
            vuln_scanner = SyncVulnerabilityScanner()
            try:
                # Process dependencies in batches for better progress tracking
                batch_size = 10
                total_deps = len(dependencies)
                
                for batch_start in range(0, total_deps, batch_size):
                    batch_end = min(batch_start + batch_size, total_deps)
                    batch_deps = dependencies[batch_start:batch_end]
                    
                    # Update progress for this batch
                    progress = 50 + int((batch_start / total_deps) * 30)  # 50-80% range
                    job_manager.update_job_progress(
                        job_id=job_id,
                        progress_percentage=progress,
                        current_stage="vulnerability_lookup",
                        stage_message=f"Scanning vulnerabilities for dependencies {batch_start + 1}-{batch_end} of {total_deps}..."
                    )
                    
                    try:
                        # Scan batch of dependencies  
                        batch_matches = vuln_scanner.scan_dependencies(
                            batch_deps,
                            severity_filter=None,  # Use default (Critical and High)
                            include_low_confidence=False
                        )
                        
                        # Convert VulnerabilityMatch objects to VulnerabilityData
                        for match in batch_matches:
                            if hasattr(match, 'vulnerability_data') and match.vulnerability_data:
                                vulnerabilities.append(match.vulnerability_data)
                            else:
                                # Create VulnerabilityData from match data
                                from ..models import VulnerabilityData, SeverityLevel
                                
                                vuln_data = VulnerabilityData(
                                    cve_id=match.cve_id,
                                    package_name=match.package_name,
                                    package_version=match.package_version,
                                    severity=SeverityLevel.HIGH,  # Default severity
                                    description=f"Vulnerability found in {match.package_name}",
                                    cve_url=f"https://nvd.nist.gov/vuln/detail/{match.cve_id}",
                                    cvss_score=None,
                                    published_date=None,
                                    last_modified=None
                                )
                                vulnerabilities.append(vuln_data)
                                
                    except Exception as e:
                        logger.warning(f"Failed to scan dependency batch {batch_start}-{batch_end}: {e}")
                        # Continue with next batch
            finally:
                vuln_scanner.close()
        
        logger.info(f"Found {len(vulnerabilities)} vulnerabilities in {owner}/{repo}")
        
        # Stage 4: Security scoring
        job_manager.update_job_progress(
            job_id=job_id,
            progress_percentage=85,
            current_stage="scoring_calculation",
            stage_message="Calculating security scores and risk assessment..."
        )
        
        scorer = SecurityScorer()
        security_score = scorer.calculate_security_score(
            vulnerabilities=vulnerabilities,
            dependencies=dependencies,
            repository_metadata=repo_metadata
        )
        
        logger.info(f"Security score calculated for {owner}/{repo}: {security_score.overall_score}")
        
        # Stage 5: Report generation
        job_manager.update_job_progress(
            job_id=job_id,
            progress_percentage=95,
            current_stage="report_generation",
            stage_message="Generating comprehensive security analysis report..."
        )
        
        report_generator = ReportGenerator()
        analysis_result = report_generator.generate_analysis_report(
            job_id=job_id,
            repository_url=repository_url,
            owner=owner,
            repository=repo,
            repository_metadata=repo_metadata,
            dependencies=dependencies,
            vulnerabilities=vulnerabilities,
            security_score=security_score
        )
        
        # Complete the job
        job_manager.complete_job(job_id, worker_id, analysis_result)
        
        logger.info(f"Completed repository analysis for job {job_id}: {repository_url}")
        
        return {
            "job_id": job_id,
            "status": "completed",
            "repository_url": repository_url,
            "vulnerabilities_found": len(vulnerabilities),
            "security_score": security_score.overall_score,
            "completed_at": datetime.utcnow().isoformat()
        }
    
    # Run the synchronous analysis function
    try:
        return run_analysis()
        
    except Exception as e:
        logger.error(f"Repository analysis failed for job {job_id}: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        
        # Fail the job
        job_manager.fail_job(
            job_id=job_id,
            worker_id=worker_id,
            error_message=str(e),
            error_details={
                "stage": "analysis_execution",
                "exception_type": type(e).__name__,
                "traceback": traceback.format_exc()
            }
        )
        
        raise AnalysisError(f"Repository analysis failed: {str(e)}", job_id=job_id)


@celery_app.task(bind=True, base=CaponierTask, name='caponier.analysis.scan_dependencies', time_limit=120, soft_time_limit=100)
def scan_dependencies_task(self, repository_url: str, owner: str, repo: str) -> List[Dict[str, Any]]:
    """
    Task for scanning repository dependencies
    
    Args:
        repository_url: Repository URL to scan
        owner: Repository owner
        repo: Repository name
        
    Returns:
        List of dependency information
    """
    try:
        logger.info(f"Scanning dependencies for {owner}/{repo}")
        
        # Use synchronous clients for Celery tasks
        from ..security.github_client_sync import SyncGitHubClient
        from ..security.dependency_parser_sync import SyncDependencyParser
        
        github_client = SyncGitHubClient()
        try:
            dependency_parser = SyncDependencyParser(github_client)
            dependencies = dependency_parser.parse_repository_dependencies(owner, repo)
            
            result = []
            for dep_result in dependencies:
                for dep in dep_result.dependencies:
                    result.append({
                        "name": dep.name,
                        "version": dep.version,
                        "ecosystem": dep_result.ecosystem.value,
                        "file_path": dep_result.manifest_file
                    })
            
            logger.info(f"Found {len(result)} dependencies for {owner}/{repo}")
            return result
        finally:
            github_client.close()
        
    except Exception as e:
        logger.error(f"Dependency scanning failed for {owner}/{repo}: {e}")
        raise


@celery_app.task(bind=True, base=CaponierTask, name='caponier.analysis.check_vulnerabilities', time_limit=180, soft_time_limit=150)
def check_vulnerabilities_task(self, dependencies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Task for checking vulnerabilities in dependencies
    
    Args:
        dependencies: List of dependency information
        
    Returns:
        List of vulnerability information
    """
    try:
        logger.info(f"Checking vulnerabilities for {len(dependencies)} dependencies")
        
        # Use synchronous vulnerability scanner for Celery tasks
        from ..security.vulnerability_scanner_sync import SyncVulnerabilityScanner
        from ..security.dependency_parser import ParsedDependency, PackageEcosystem
        
        vuln_scanner = SyncVulnerabilityScanner()
        try:
            vulnerabilities = []
            
            # Convert dependency info to ParsedDependency objects
            parsed_deps = []
            for dep_info in dependencies:
                try:
                    ecosystem = PackageEcosystem(dep_info["ecosystem"])
                except ValueError:
                    ecosystem = PackageEcosystem.NPM  # Default fallback
                
                dependency = ParsedDependency(
                    name=dep_info["name"],
                    version=dep_info["version"],
                    ecosystem=ecosystem,
                    file_path=dep_info["file_path"],
                    is_dev_dependency=False,
                    constraint="",
                    source_line="",
                    line_number=0
                )
                parsed_deps.append(dependency)
            
            # Scan for vulnerabilities
            vuln_matches = vuln_scanner.scan_dependencies(parsed_deps)
            
            # Convert matches to response format
            for match in vuln_matches:
                if match.vulnerability_data:
                    vulnerabilities.append({
                        "cve_id": match.cve_id,
                        "severity": match.vulnerability_data.severity.value if hasattr(match.vulnerability_data.severity, 'value') else str(match.vulnerability_data.severity),
                        "score": match.vulnerability_data.cvss_score,
                        "description": match.vulnerability_data.description,
                        "affected_dependency": match.package_name,
                        "confidence": match.confidence_score,
                        "match_method": match.match_method
                    })
            
            logger.info(f"Found {len(vulnerabilities)} vulnerabilities")
            return vulnerabilities
            
        finally:
            vuln_scanner.close()
        
    except Exception as e:
        logger.error(f"Vulnerability checking failed: {e}")
        raise


@celery_app.task(bind=True, base=CaponierTask, name='caponier.maintenance.cleanup_jobs', time_limit=60, soft_time_limit=45)
def cleanup_jobs_task(self) -> Dict[str, Any]:
    """
    Maintenance task for cleaning up expired jobs and data
    
    Returns:
        Dictionary with cleanup statistics
    """
    try:
        logger.info("Starting job cleanup task")
        
        cleanup_count = job_manager.cleanup_expired_jobs()
        
        result = {
            "jobs_cleaned": cleanup_count,
            "cleanup_time": datetime.utcnow().isoformat(),
            "status": "completed"
        }
        
        logger.info(f"Job cleanup completed: {cleanup_count} jobs processed")
        return result
        
    except Exception as e:
        logger.error(f"Job cleanup failed: {e}")
        raise


@celery_app.task(bind=True, base=CaponierTask, name='caponier.monitoring.health_check', time_limit=30, soft_time_limit=25)
def health_check_task(self) -> Dict[str, Any]:
    """
    Health check task for monitoring worker status
    
    Returns:
        Dictionary with health information
    """
    try:
        # Perform basic health checks
        system_status = job_manager.get_system_status()
        
        result = {
            "worker_id": self.worker_id,
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "system_status": system_status
        }
        
        return result
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return {
            "worker_id": self.worker_id,
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }


@celery_app.task(bind=True, base=CaponierTask, name='caponier.test.simple_test', time_limit=60, soft_time_limit=45)
def simple_test_task(self, test_data: str = "Hello from Celery!") -> Dict[str, Any]:
    """
    Simple test task to verify Celery is working
    
    Args:
        test_data: Test data to echo back
        
    Returns:
        Dictionary with test results
    """
    import time
    
    logger.info(f"Running simple test task with data: {test_data}")
    
    # Simulate some work
    time.sleep(2)
    
    return {
        "worker_id": self.worker_id,
        "test_data": test_data,
        "status": "completed",
        "timestamp": datetime.utcnow().isoformat(),
        "message": "Test task completed successfully"
    }


# Task composition utilities
def schedule_repository_analysis(job_id: str, repository_url: str, owner: str, repo: str) -> None:
    """
    Schedule a complete repository analysis
    
    Args:
        job_id: Job identifier
        repository_url: Repository URL
        owner: Repository owner  
        repo: Repository name
    """
    logger.info(f"Scheduling repository analysis for job {job_id}: {repository_url}")
    
    # Schedule the main analysis task
    analyze_repository_task.delay(
        job_id=job_id,
        repository_url=repository_url,
        owner=owner,
        repo=repo
    )


def schedule_maintenance_tasks() -> None:
    """Schedule periodic maintenance tasks"""
    logger.info("Scheduling maintenance tasks")
    
    # Schedule job cleanup
    cleanup_jobs_task.delay()


def get_task_status(task_id: str) -> Dict[str, Any]:
    """
    Get status of a Celery task
    
    Args:
        task_id: Celery task ID
        
    Returns:
        Dictionary with task status information
    """
    try:
        result = celery_app.AsyncResult(task_id)
        
        return {
            "task_id": task_id,
            "status": result.status,
            "result": result.result if result.ready() else None,
            "traceback": result.traceback if result.failed() else None
        }
        
    except Exception as e:
        logger.error(f"Failed to get task status for {task_id}: {e}")
        return {
            "task_id": task_id,
            "status": "unknown",
            "error": str(e)
        }


def revoke_task(task_id: str, terminate: bool = False) -> bool:
    """
    Revoke a Celery task
    
    Args:
        task_id: Celery task ID
        terminate: Whether to terminate if task is running
        
    Returns:
        True if task was revoked successfully
    """
    try:
        celery_app.control.revoke(task_id, terminate=terminate)
        logger.info(f"Revoked task {task_id} (terminate={terminate})")
        return True
        
    except Exception as e:
        logger.error(f"Failed to revoke task {task_id}: {e}")
        return False
