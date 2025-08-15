"""
Security Scoring Algorithm and Reporting System

This module implements a comprehensive security scoring system that evaluates
repository security based on multiple factors:

- Vulnerability analysis with weighted severity scoring
- Maintenance health assessment based on repository activity
- Overall security score calculation (0-100 scale)
- Actionable recommendations generation
- Comparative context against similar repositories
- Security badge generation for public display

The scoring system provides both technical and business-oriented insights
to help developers and security teams prioritize remediation efforts.
"""

import logging
import math
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum

from ..models import RepositoryMetadata, SeverityLevel
from .vulnerability_enrichment import EnrichedVulnerabilityData

logger = logging.getLogger(__name__)


class ScoreComponent(str, Enum):
    """Security score components"""
    VULNERABILITY = "vulnerability"
    MAINTENANCE = "maintenance"  
    DEPENDENCY = "dependency"
    OVERALL = "overall"


class RecommendationPriority(str, Enum):
    """Recommendation priority levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class RecommendationCategory(str, Enum):
    """Recommendation categories"""
    VULNERABILITY_PATCH = "vulnerability_patch"
    DEPENDENCY_UPDATE = "dependency_update"
    SECURITY_PRACTICE = "security_practice" 
    MAINTENANCE = "maintenance"
    MONITORING = "monitoring"


@dataclass
class VulnerabilityScore:
    """Vulnerability scoring breakdown"""
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    
    # Weighted scoring
    critical_points: int = 0
    high_points: int = 0
    medium_points: int = 0
    low_points: int = 0
    
    total_vulnerabilities: int = 0
    total_points: int = 0
    vulnerability_score: int = 0  # 0-100 scale
    
    # Additional metrics
    exploitable_count: int = 0
    patch_available_count: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "counts": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "total": self.total_vulnerabilities
            },
            "points": {
                "critical": self.critical_points,
                "high": self.high_points,
                "medium": self.medium_points,
                "low": self.low_points,
                "total": self.total_points
            },
            "score": self.vulnerability_score,
            "metrics": {
                "exploitable_vulnerabilities": self.exploitable_count,
                "patches_available": self.patch_available_count,
                "patch_coverage": self.patch_available_count / max(self.total_vulnerabilities, 1)
            }
        }


@dataclass
class MaintenanceScore:
    """Maintenance health scoring"""
    last_commit_days: Optional[int] = None
    contributor_count: int = 0
    commit_frequency_score: int = 0
    contributor_diversity_score: int = 0
    issue_response_score: int = 0
    maintenance_score: int = 0  # 0-100 scale
    
    # Health indicators
    is_actively_maintained: bool = False
    maintenance_status: str = "unknown"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "last_commit_days": self.last_commit_days,
            "contributor_count": self.contributor_count,
            "scores": {
                "commit_frequency": self.commit_frequency_score,
                "contributor_diversity": self.contributor_diversity_score,
                "issue_response": self.issue_response_score,
                "overall": self.maintenance_score
            },
            "status": {
                "actively_maintained": self.is_actively_maintained,
                "maintenance_status": self.maintenance_status
            }
        }


@dataclass
class SecurityRecommendation:
    """Individual security recommendation"""
    title: str
    description: str
    priority: RecommendationPriority
    category: RecommendationCategory
    impact: str
    effort: str
    
    # Optional specific details
    affected_packages: List[str] = field(default_factory=list)
    cve_ids: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "title": self.title,
            "description": self.description,
            "priority": self.priority.value,
            "category": self.category.value,
            "impact": self.impact,
            "effort": self.effort,
            "affected_packages": self.affected_packages,
            "cve_ids": self.cve_ids,
            "references": self.references
        }


@dataclass 
class SecurityBadge:
    """Security badge information for display"""
    grade: str  # A, B, C, D, F
    score: int  # 0-100
    label: str
    color: str
    svg_url: str
    shield_url: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "grade": self.grade,
            "score": self.score,
            "label": self.label,
            "color": self.color,
            "svg_url": self.svg_url,
            "shield_url": self.shield_url
        }


@dataclass
class SecurityScoreBreakdown:
    """Complete security score breakdown"""
    overall_score: int  # 0-100
    grade: str  # A, B, C, D, F
    
    # Component scores
    vulnerability_score: VulnerabilityScore
    maintenance_score: MaintenanceScore
    
    # Comparative context
    percentile: Optional[float] = None
    comparison_text: str = ""
    
    # Recommendations
    recommendations: List[SecurityRecommendation] = field(default_factory=list)
    
    # Badge
    security_badge: Optional[SecurityBadge] = None
    
    # Metadata
    calculated_at: datetime = field(default_factory=datetime.now)
    
    def get_critical_recommendations(self) -> List[SecurityRecommendation]:
        """Get only critical priority recommendations"""
        return [r for r in self.recommendations if r.priority == RecommendationPriority.CRITICAL]
    
    def get_high_recommendations(self) -> List[SecurityRecommendation]:
        """Get high priority recommendations"""
        return [r for r in self.recommendations if r.priority == RecommendationPriority.HIGH]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses"""
        return {
            "overall_score": self.overall_score,
            "grade": self.grade,
            "calculated_at": self.calculated_at.isoformat(),
            "vulnerability_analysis": self.vulnerability_score.to_dict(),
            "maintenance_analysis": self.maintenance_score.to_dict(),
            "comparative_context": {
                "percentile": self.percentile,
                "comparison_text": self.comparison_text
            },
            "recommendations": {
                "critical": [r.to_dict() for r in self.get_critical_recommendations()],
                "high": [r.to_dict() for r in self.get_high_recommendations()],
                "all": [r.to_dict() for r in self.recommendations]
            },
            "security_badge": self.security_badge.to_dict() if self.security_badge else None
        }


class SecurityScorer:
    """
    Comprehensive security scoring system for repository analysis
    """
    
    # Vulnerability scoring weights
    VULNERABILITY_WEIGHTS = {
        SeverityLevel.CRITICAL: 10,
        SeverityLevel.HIGH: 5,
        SeverityLevel.MEDIUM: 2,
        SeverityLevel.LOW: 1
    }
    
    # Score thresholds for grades
    GRADE_THRESHOLDS = {
        90: "A",  # Excellent
        80: "B",  # Good
        70: "C",  # Fair
        60: "D",  # Poor
        0: "F"    # Failing
    }
    
    def __init__(self):
        """Initialize security scorer"""
        self.stats = {
            "scores_calculated": 0,
            "recommendations_generated": 0,
            "badges_created": 0
        }
    
    def calculate_security_score(
        self,
        vulnerabilities: List[EnrichedVulnerabilityData],
        repository_metadata: RepositoryMetadata,
        dependency_count: int = 0
    ) -> SecurityScoreBreakdown:
        """
        Calculate comprehensive security score
        
        Args:
            vulnerabilities: List of enriched vulnerability data
            repository_metadata: Repository metadata and statistics
            dependency_count: Total number of dependencies
            
        Returns:
            Complete security score breakdown with recommendations
        """
        self.stats["scores_calculated"] += 1
        
        # Calculate vulnerability score
        vuln_score = self._calculate_vulnerability_score(vulnerabilities)
        
        # Calculate maintenance score
        maint_score = self._calculate_maintenance_score(repository_metadata)
        
        # Calculate overall score (weighted combination)
        overall_score = self._calculate_overall_score(vuln_score, maint_score, dependency_count)
        
        # Determine grade
        grade = self._calculate_grade(overall_score)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(
            vulnerabilities, repository_metadata, vuln_score, maint_score
        )
        
        # Generate comparative context
        percentile, comparison_text = self._generate_comparative_context(overall_score, grade)
        
        # Create security badge
        security_badge = self._create_security_badge(overall_score, grade)
        
        return SecurityScoreBreakdown(
            overall_score=overall_score,
            grade=grade,
            vulnerability_score=vuln_score,
            maintenance_score=maint_score,
            percentile=percentile,
            comparison_text=comparison_text,
            recommendations=recommendations,
            security_badge=security_badge
        )
    
    def _calculate_vulnerability_score(self, vulnerabilities: List[EnrichedVulnerabilityData]) -> VulnerabilityScore:
        """Calculate vulnerability-based security score"""
        score = VulnerabilityScore()
        
        # Count vulnerabilities by severity
        for vuln in vulnerabilities:
            score.total_vulnerabilities += 1
            
            if vuln.severity == SeverityLevel.CRITICAL:
                score.critical_count += 1
                score.critical_points += self.VULNERABILITY_WEIGHTS[SeverityLevel.CRITICAL]
            elif vuln.severity == SeverityLevel.HIGH:
                score.high_count += 1
                score.high_points += self.VULNERABILITY_WEIGHTS[SeverityLevel.HIGH]
            elif vuln.severity == SeverityLevel.MEDIUM:
                score.medium_count += 1
                score.medium_points += self.VULNERABILITY_WEIGHTS[SeverityLevel.MEDIUM]
            elif vuln.severity == SeverityLevel.LOW:
                score.low_count += 1
                score.low_points += self.VULNERABILITY_WEIGHTS[SeverityLevel.LOW]
            
            # Track exploitability
            if "High" in vuln.get_exploitability_rating() or "Functional" in vuln.get_exploitability_rating():
                score.exploitable_count += 1
            
            # Track patch availability
            if vuln.patch_available:
                score.patch_available_count += 1
        
        # Calculate total points
        score.total_points = (score.critical_points + score.high_points + 
                             score.medium_points + score.low_points)
        
        # Calculate vulnerability score (0-100, inverse scale - fewer vulns = higher score)
        if score.total_vulnerabilities == 0:
            score.vulnerability_score = 100
        else:
            # Use logarithmic scale to avoid harsh penalties for repos with many deps
            # Base penalty per vulnerability, with higher penalties for more severe vulns
            base_penalty = min(score.total_points * 2, 100)  # Cap at 100
            
            # Additional penalty for exploitable vulnerabilities
            exploitability_penalty = score.exploitable_count * 5
            
            # Bonus for available patches
            patch_bonus = score.patch_available_count * 2
            
            # Calculate final score
            raw_score = 100 - base_penalty - exploitability_penalty + patch_bonus
            score.vulnerability_score = max(0, min(100, raw_score))
        
        return score
    
    def _calculate_maintenance_score(self, repo_metadata: RepositoryMetadata) -> MaintenanceScore:
        """Calculate maintenance health score"""
        score = MaintenanceScore()
        
        # Calculate days since last commit
        if repo_metadata.last_commit_date:
            days_since_commit = (datetime.now() - repo_metadata.last_commit_date).days
            score.last_commit_days = days_since_commit
        else:
            score.last_commit_days = None
            days_since_commit = 365  # Default to 1 year if unknown
        
        score.contributor_count = repo_metadata.contributor_count
        
        # Commit frequency score (0-40 points)
        if score.last_commit_days is not None:
            if days_since_commit <= 7:
                score.commit_frequency_score = 40  # Very active
            elif days_since_commit <= 30:
                score.commit_frequency_score = 35  # Active
            elif days_since_commit <= 90:
                score.commit_frequency_score = 25  # Moderate
            elif days_since_commit <= 180:
                score.commit_frequency_score = 15  # Slow
            elif days_since_commit <= 365:
                score.commit_frequency_score = 5   # Very slow
            else:
                score.commit_frequency_score = 0   # Abandoned
        else:
            score.commit_frequency_score = 0
        
        # Contributor diversity score (0-30 points)
        if score.contributor_count >= 10:
            score.contributor_diversity_score = 30
        elif score.contributor_count >= 5:
            score.contributor_diversity_score = 25
        elif score.contributor_count >= 3:
            score.contributor_diversity_score = 20
        elif score.contributor_count >= 2:
            score.contributor_diversity_score = 15
        elif score.contributor_count >= 1:
            score.contributor_diversity_score = 10
        else:
            score.contributor_diversity_score = 0
        
        # Issue response score (0-30 points) - simplified based on available metadata
        if repo_metadata.open_issues_count is not None:
            # Use stars as a proxy for project size to evaluate issue count
            if repo_metadata.stars > 0:
                issue_ratio = repo_metadata.open_issues_count / max(repo_metadata.stars, 1)
                if issue_ratio < 0.1:
                    score.issue_response_score = 30  # Very good
                elif issue_ratio < 0.2:
                    score.issue_response_score = 25  # Good
                elif issue_ratio < 0.5:
                    score.issue_response_score = 20  # Fair
                elif issue_ratio < 1.0:
                    score.issue_response_score = 15  # Poor
                else:
                    score.issue_response_score = 10  # Very poor
            else:
                score.issue_response_score = 15  # Default for new repos
        else:
            score.issue_response_score = 15  # Default when unknown
        
        # Calculate overall maintenance score
        score.maintenance_score = (score.commit_frequency_score + 
                                 score.contributor_diversity_score + 
                                 score.issue_response_score)
        
        # Determine maintenance status
        if score.maintenance_score >= 80:
            score.maintenance_status = "excellent"
            score.is_actively_maintained = True
        elif score.maintenance_score >= 60:
            score.maintenance_status = "good"
            score.is_actively_maintained = True
        elif score.maintenance_score >= 40:
            score.maintenance_status = "fair"
            score.is_actively_maintained = True
        elif score.maintenance_score >= 20:
            score.maintenance_status = "poor"
            score.is_actively_maintained = False
        else:
            score.maintenance_status = "abandoned"
            score.is_actively_maintained = False
        
        return score
    
    def _calculate_overall_score(
        self, 
        vuln_score: VulnerabilityScore, 
        maint_score: MaintenanceScore,
        dependency_count: int
    ) -> int:
        """Calculate weighted overall security score"""
        
        # Weighted combination of scores
        # Vulnerability score: 70% weight (most important)
        # Maintenance score: 30% weight
        vulnerability_weight = 0.7
        maintenance_weight = 0.3
        
        weighted_score = (
            vuln_score.vulnerability_score * vulnerability_weight +
            maint_score.maintenance_score * maintenance_weight
        )
        
        # Apply dependency complexity bonus/penalty
        if dependency_count > 0:
            # Small bonus for having dependency management
            dependency_bonus = min(dependency_count * 0.1, 5)  # Max 5 points
            
            # But penalty if many dependencies with vulnerabilities
            if vuln_score.total_vulnerabilities > 0:
                vuln_ratio = vuln_score.total_vulnerabilities / dependency_count
                if vuln_ratio > 0.1:  # More than 10% of deps have vulns
                    dependency_penalty = min(vuln_ratio * 10, 10)  # Max 10 points
                    weighted_score -= dependency_penalty
            else:
                weighted_score += dependency_bonus
        
        return max(0, min(100, int(weighted_score)))
    
    def _calculate_grade(self, overall_score: int) -> str:
        """Calculate letter grade from numeric score"""
        for threshold, grade in self.GRADE_THRESHOLDS.items():
            if overall_score >= threshold:
                return grade
        return "F"
    
    def _generate_recommendations(
        self,
        vulnerabilities: List[EnrichedVulnerabilityData],
        repo_metadata: RepositoryMetadata,
        vuln_score: VulnerabilityScore,
        maint_score: MaintenanceScore
    ) -> List[SecurityRecommendation]:
        """Generate actionable security recommendations"""
        recommendations = []
        
        # Critical vulnerability recommendations
        critical_vulns = [v for v in vulnerabilities if v.severity == SeverityLevel.CRITICAL]
        if critical_vulns:
            for vuln in critical_vulns[:3]:  # Top 3 critical
                if vuln.patch_available:
                    rec = SecurityRecommendation(
                        title=f"URGENT: Patch {vuln.cve_id} in {vuln.package_name}",
                        description=f"Critical vulnerability with CVSS score {vuln.get_primary_cvss_score()}. Patch is available.",
                        priority=RecommendationPriority.CRITICAL,
                        category=RecommendationCategory.VULNERABILITY_PATCH,
                        impact="High - Critical security vulnerability",
                        effort="Low - Patch available",
                        affected_packages=[vuln.package_name],
                        cve_ids=[vuln.cve_id],
                        references=vuln.patch_urls
                    )
                    recommendations.append(rec)
        
        # High severity vulnerability recommendations
        high_vulns = [v for v in vulnerabilities if v.severity == SeverityLevel.HIGH]
        if high_vulns:
            patchable_high = [v for v in high_vulns if v.patch_available]
            if patchable_high:
                rec = SecurityRecommendation(
                    title=f"Update {len(patchable_high)} packages with high-severity vulnerabilities",
                    description=f"High-severity vulnerabilities found with available patches.",
                    priority=RecommendationPriority.HIGH,
                    category=RecommendationCategory.VULNERABILITY_PATCH,
                    impact="Medium - High severity vulnerabilities",
                    effort="Low - Patches available",
                    affected_packages=[v.package_name for v in patchable_high[:5]],
                    cve_ids=[v.cve_id for v in patchable_high[:5]]
                )
                recommendations.append(rec)
        
        # Maintenance recommendations
        if not maint_score.is_actively_maintained:
            if maint_score.last_commit_days and maint_score.last_commit_days > 180:
                rec = SecurityRecommendation(
                    title="Improve repository maintenance",
                    description=f"Repository hasn't been updated in {maint_score.last_commit_days} days. Regular maintenance is crucial for security.",
                    priority=RecommendationPriority.HIGH,
                    category=RecommendationCategory.MAINTENANCE,
                    impact="Medium - Outdated dependencies and missed security patches",
                    effort="Medium - Establish regular maintenance schedule"
                )
                recommendations.append(rec)
        
        # Dependency update recommendations
        if vuln_score.total_vulnerabilities > 5:
            rec = SecurityRecommendation(
                title="Implement automated dependency scanning",
                description="Consider using automated tools to scan for vulnerabilities in dependencies regularly.",
                priority=RecommendationPriority.MEDIUM,
                category=RecommendationCategory.SECURITY_PRACTICE,
                impact="Medium - Proactive vulnerability detection",
                effort="Low - Automated tooling available"
            )
            recommendations.append(rec)
        
        # Security practice recommendations
        if vuln_score.exploitable_count > 0:
            rec = SecurityRecommendation(
                title="Prioritize vulnerabilities with known exploits",
                description=f"{vuln_score.exploitable_count} vulnerabilities have known exploits. These should be patched immediately.",
                priority=RecommendationPriority.HIGH,
                category=RecommendationCategory.SECURITY_PRACTICE,
                impact="High - Active exploitation possible",
                effort="Variable - Depends on patch availability"
            )
            recommendations.append(rec)
        
        self.stats["recommendations_generated"] += len(recommendations)
        return recommendations
    
    def _generate_comparative_context(self, overall_score: int, grade: str) -> Tuple[Optional[float], str]:
        """Generate comparative context against similar repositories"""
        
        # Simplified percentile calculation (in production, this would query actual data)
        if overall_score >= 90:
            percentile = 95.0
            comparison_text = "Excellent! This repository scores better than 95% of similar projects."
        elif overall_score >= 80:
            percentile = 80.0
            comparison_text = "Good security posture. Better than 80% of similar repositories."
        elif overall_score >= 70:
            percentile = 60.0
            comparison_text = "Fair security score. Better than 60% of similar repositories."
        elif overall_score >= 60:
            percentile = 40.0
            comparison_text = "Below average security. Consider addressing the recommendations."
        else:
            percentile = 20.0
            comparison_text = "Poor security score. Immediate attention needed for security improvements."
        
        return percentile, comparison_text
    
    def _create_security_badge(self, overall_score: int, grade: str) -> SecurityBadge:
        """Create security badge for display"""
        
        # Color mapping for grades
        color_map = {
            "A": "brightgreen",
            "B": "green", 
            "C": "yellow",
            "D": "orange",
            "F": "red"
        }
        
        color = color_map.get(grade, "lightgrey")
        label = f"Security: {grade} ({overall_score}/100)"
        
        # Generate shield URLs (shields.io format)
        shield_url = f"https://img.shields.io/badge/Security-{grade}%20({overall_score}%2F100)-{color}"
        svg_url = f"https://img.shields.io/badge/Security-{grade}-{color}.svg"
        
        badge = SecurityBadge(
            grade=grade,
            score=overall_score,
            label=label,
            color=color,
            svg_url=svg_url,
            shield_url=shield_url
        )
        
        self.stats["badges_created"] += 1
        return badge
    
    def get_stats(self) -> Dict[str, Any]:
        """Get scoring service statistics"""
        return dict(self.stats)


# Convenience functions for easy integration

def calculate_repository_security_score(
    vulnerabilities: List[EnrichedVulnerabilityData],
    repository_metadata: RepositoryMetadata,
    dependency_count: int = 0
) -> SecurityScoreBreakdown:
    """
    Convenience function to calculate repository security score
    
    Args:
        vulnerabilities: List of enriched vulnerability data
        repository_metadata: Repository metadata
        dependency_count: Total number of dependencies
        
    Returns:
        Complete security score breakdown
    """
    scorer = SecurityScorer()
    return scorer.calculate_security_score(
        vulnerabilities, repository_metadata, dependency_count
    )


def generate_security_report(score_breakdown: SecurityScoreBreakdown) -> Dict[str, Any]:
    """
    Generate a comprehensive security report
    
    Args:
        score_breakdown: Security score breakdown
        
    Returns:
        Formatted security report
    """
    return {
        "summary": {
            "overall_score": score_breakdown.overall_score,
            "grade": score_breakdown.grade,
            "status": "PASS" if score_breakdown.overall_score >= 70 else "FAIL",
            "calculated_at": score_breakdown.calculated_at.isoformat()
        },
        "detailed_analysis": score_breakdown.to_dict(),
        "executive_summary": {
            "critical_issues": len(score_breakdown.get_critical_recommendations()),
            "high_priority_issues": len(score_breakdown.get_high_recommendations()),
            "maintenance_status": score_breakdown.maintenance_score.maintenance_status,
            "comparison": score_breakdown.comparison_text
        }
    }
