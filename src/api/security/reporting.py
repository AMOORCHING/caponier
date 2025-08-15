"""
Detailed Analysis Report Structure and Generation

This module provides comprehensive report generation for security analysis results,
including detailed vulnerability lists, metadata, executive summaries, and
various export formats for different audiences.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

from ..models import RepositoryMetadata, SeverityLevel
from .scoring import SecurityScoreBreakdown, SecurityRecommendation, RecommendationPriority
from .vulnerability_enrichment import EnrichedVulnerabilityData

logger = logging.getLogger(__name__)


class ReportFormat(str, Enum):
    """Supported report formats"""
    JSON = "json"
    HTML = "html"
    MARKDOWN = "markdown"
    PDF = "pdf"
    EXECUTIVE = "executive"


class ReportAudience(str, Enum):
    """Target audience for reports"""
    TECHNICAL = "technical"
    EXECUTIVE = "executive"
    SECURITY = "security"
    COMPLIANCE = "compliance"


@dataclass
class VulnerabilityDetail:
    """Detailed vulnerability information for reports"""
    cve_id: str
    package_name: str
    package_version: str
    severity: SeverityLevel
    cvss_score: float
    description: str
    impact: str
    exploitability: str
    patch_available: bool
    patch_urls: List[str]
    discovery_date: Optional[datetime] = None
    last_modified: Optional[datetime] = None
    cwe_ids: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    
    @classmethod
    def from_enriched_vulnerability(cls, vuln: EnrichedVulnerabilityData) -> 'VulnerabilityDetail':
        """Create from enriched vulnerability data"""
        
        # Extract CWE IDs from weaknesses
        cwe_ids = []
        if hasattr(vuln, 'weaknesses') and vuln.weaknesses:
            cwe_ids = [w.cwe_id for w in vuln.weaknesses if hasattr(w, 'cwe_id')]
        
        # Extract reference URLs
        reference_urls = []
        if hasattr(vuln, 'references') and vuln.references:
            reference_urls = [r.url for r in vuln.references if hasattr(r, 'url')]
        
        return cls(
            cve_id=vuln.cve_id,
            package_name=vuln.package_name,
            package_version=vuln.package_version,
            severity=vuln.severity,
            cvss_score=vuln.get_primary_cvss_score(),
            description=vuln.description,
            impact=vuln.get_impact_summary(),
            exploitability=vuln.get_exploitability_rating(),
            patch_available=vuln.patch_available or False,
            patch_urls=vuln.patch_urls or [],
            discovery_date=vuln.published_date,
            last_modified=vuln.last_modified,
            cwe_ids=cwe_ids,
            references=reference_urls
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "cve_id": self.cve_id,
            "package": {
                "name": self.package_name,
                "version": self.package_version
            },
            "severity": self.severity.value,
            "cvss_score": self.cvss_score,
            "description": self.description,
            "impact": self.impact,
            "exploitability": self.exploitability,
            "patch_info": {
                "available": self.patch_available,
                "urls": self.patch_urls
            },
            "dates": {
                "discovered": self.discovery_date.isoformat() if self.discovery_date else None,
                "last_modified": self.last_modified.isoformat() if self.last_modified else None
            },
            "weaknesses": self.cwe_ids,
            "references": self.references
        }


@dataclass
class DependencyAnalysis:
    """Dependency analysis summary"""
    total_dependencies: int
    direct_dependencies: int
    transitive_dependencies: int
    outdated_dependencies: int
    vulnerable_dependencies: int
    ecosystems: List[str]
    dependency_health_score: int
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "counts": {
                "total": self.total_dependencies,
                "direct": self.direct_dependencies,
                "transitive": self.transitive_dependencies,
                "outdated": self.outdated_dependencies,
                "vulnerable": self.vulnerable_dependencies
            },
            "ecosystems": self.ecosystems,
            "health_score": self.dependency_health_score
        }


@dataclass
class SecurityMetrics:
    """Security metrics and statistics"""
    vulnerability_density: float  # vulns per 1000 dependencies
    mean_cvss_score: float
    median_cvss_score: float
    time_to_patch: Optional[float] = None  # days
    exposure_window: Optional[float] = None  # days
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "vulnerability_density": self.vulnerability_density,
            "cvss_statistics": {
                "mean": self.mean_cvss_score,
                "median": self.median_cvss_score
            },
            "response_metrics": {
                "mean_time_to_patch_days": self.time_to_patch,
                "exposure_window_days": self.exposure_window
            }
        }


@dataclass
class ComplianceInfo:
    """Compliance and regulatory information"""
    compliance_status: str
    applicable_standards: List[str]
    compliance_score: int
    findings: List[str]
    recommendations: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "status": self.compliance_status,
            "applicable_standards": self.applicable_standards,
            "score": self.compliance_score,
            "findings": self.findings,
            "recommendations": self.recommendations
        }


@dataclass
class DetailedAnalysisReport:
    """Comprehensive analysis report structure"""
    
    # Report metadata
    report_id: str
    generated_at: datetime
    repository_info: RepositoryMetadata
    security_score: SecurityScoreBreakdown
    
    # Optional fields with defaults
    report_version: str = "1.0"
    analysis_scope: Dict[str, Any] = field(default_factory=dict)
    vulnerabilities: List[VulnerabilityDetail] = field(default_factory=list)
    dependency_analysis: Optional[DependencyAnalysis] = None
    security_metrics: Optional[SecurityMetrics] = None
    
    # Compliance and governance
    compliance_info: Optional[ComplianceInfo] = None
    
    # Executive summary
    executive_summary: Dict[str, Any] = field(default_factory=dict)
    
    # Additional metadata
    analysis_duration: Optional[float] = None
    api_calls_made: int = 0
    cache_hit_rate: float = 0.0
    
    def get_critical_vulnerabilities(self) -> List[VulnerabilityDetail]:
        """Get only critical severity vulnerabilities"""
        return [v for v in self.vulnerabilities if v.severity == SeverityLevel.CRITICAL]
    
    def get_high_vulnerabilities(self) -> List[VulnerabilityDetail]:
        """Get only high severity vulnerabilities"""
        return [v for v in self.vulnerabilities if v.severity == SeverityLevel.HIGH]
    
    def get_patchable_vulnerabilities(self) -> List[VulnerabilityDetail]:
        """Get vulnerabilities with available patches"""
        return [v for v in self.vulnerabilities if v.patch_available]
    
    def get_exploitable_vulnerabilities(self) -> List[VulnerabilityDetail]:
        """Get vulnerabilities with known exploits"""
        exploitable_keywords = ["High", "Functional", "Proof of Concept"]
        return [v for v in self.vulnerabilities 
                if any(keyword in v.exploitability for keyword in exploitable_keywords)]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert complete report to dictionary"""
        return {
            "metadata": {
                "report_id": self.report_id,
                "generated_at": self.generated_at.isoformat(),
                "report_version": self.report_version,
                "analysis_performance": {
                    "duration_seconds": self.analysis_duration,
                    "api_calls": self.api_calls_made,
                    "cache_hit_rate": self.cache_hit_rate
                }
            },
            "repository": {
                "basic_info": {
                    "full_name": self.repository_info.full_name,
                    "description": self.repository_info.description,
                    "language": self.repository_info.language,
                    "stars": self.repository_info.stars,
                    "forks": self.repository_info.forks
                },
                "activity": {
                    "last_commit": self.repository_info.last_commit_date.isoformat() if self.repository_info.last_commit_date else None,
                    "contributors": self.repository_info.contributor_count,
                    "open_issues": self.repository_info.open_issues_count
                },
                "analysis_scope": self.analysis_scope
            },
            "security_assessment": {
                "summary": {
                    "overall_score": self.security_score.overall_score,
                    "grade": self.security_score.grade,
                    "status": "PASS" if self.security_score.overall_score >= 70 else "FAIL"
                },
                "vulnerability_analysis": self.security_score.vulnerability_score.to_dict(),
                "maintenance_analysis": self.security_score.maintenance_score.to_dict(),
                "comparative_context": {
                    "percentile": self.security_score.percentile,
                    "comparison_text": self.security_score.comparison_text
                }
            },
            "vulnerabilities": {
                "summary": {
                    "total_count": len(self.vulnerabilities),
                    "by_severity": {
                        "critical": len(self.get_critical_vulnerabilities()),
                        "high": len(self.get_high_vulnerabilities()),
                        "medium": len([v for v in self.vulnerabilities if v.severity == SeverityLevel.MEDIUM]),
                        "low": len([v for v in self.vulnerabilities if v.severity == SeverityLevel.LOW])
                    },
                    "patchable_count": len(self.get_patchable_vulnerabilities()),
                    "exploitable_count": len(self.get_exploitable_vulnerabilities())
                },
                "details": [v.to_dict() for v in self.vulnerabilities]
            },
            "dependencies": self.dependency_analysis.to_dict() if self.dependency_analysis else None,
            "security_metrics": self.security_metrics.to_dict() if self.security_metrics else None,
            "compliance": self.compliance_info.to_dict() if self.compliance_info else None,
            "recommendations": {
                "critical": [r.to_dict() for r in self.security_score.get_critical_recommendations()],
                "high": [r.to_dict() for r in self.security_score.get_high_recommendations()],
                "all": [r.to_dict() for r in self.security_score.recommendations]
            },
            "executive_summary": self.executive_summary,
            "security_badge": self.security_score.security_badge.to_dict() if self.security_score.security_badge else None
        }


class ReportGenerator:
    """
    Comprehensive analysis report generator
    
    Generates detailed security analysis reports in multiple formats
    for different audiences with customizable content and presentation.
    """
    
    def __init__(self):
        """Initialize report generator"""
        self.stats = {
            "reports_generated": 0,
            "formats_exported": 0,
            "executive_summaries_created": 0
        }
    
    def generate_detailed_report(
        self,
        security_score: SecurityScoreBreakdown,
        vulnerabilities: List[EnrichedVulnerabilityData],
        repository_metadata: RepositoryMetadata,
        dependency_count: int = 0,
        analysis_duration: Optional[float] = None,
        api_calls_made: int = 0,
        cache_hit_rate: float = 0.0
    ) -> DetailedAnalysisReport:
        """
        Generate comprehensive detailed analysis report
        
        Args:
            security_score: Complete security score breakdown
            vulnerabilities: List of enriched vulnerability data
            repository_metadata: Repository metadata
            dependency_count: Total dependencies analyzed
            analysis_duration: Time taken for analysis
            api_calls_made: Number of API calls during analysis
            cache_hit_rate: Cache effectiveness rate
            
        Returns:
            Detailed analysis report
        """
        self.stats["reports_generated"] += 1
        
        # Generate unique report ID
        report_id = f"caponier-{repository_metadata.full_name.replace('/', '-')}-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        
        # Convert vulnerabilities to detailed format
        detailed_vulns = [VulnerabilityDetail.from_enriched_vulnerability(v) for v in vulnerabilities]
        
        # Create dependency analysis
        dependency_analysis = self._create_dependency_analysis(
            dependency_count, detailed_vulns, repository_metadata
        )
        
        # Calculate security metrics
        security_metrics = self._calculate_security_metrics(detailed_vulns, dependency_count)
        
        # Generate compliance information
        compliance_info = self._generate_compliance_info(security_score, detailed_vulns)
        
        # Create executive summary
        executive_summary = self._create_executive_summary(
            security_score, detailed_vulns, dependency_analysis, repository_metadata
        )
        
        # Create analysis scope information
        analysis_scope = {
            "dependencies_analyzed": dependency_count,
            "vulnerability_sources": ["NVD", "GitHub Security Advisory"],
            "scan_depth": "complete",
            "ecosystems_covered": self._detect_ecosystems(repository_metadata)
        }
        
        report = DetailedAnalysisReport(
            report_id=report_id,
            generated_at=datetime.now(),
            repository_info=repository_metadata,
            analysis_scope=analysis_scope,
            security_score=security_score,
            vulnerabilities=detailed_vulns,
            dependency_analysis=dependency_analysis,
            security_metrics=security_metrics,
            compliance_info=compliance_info,
            executive_summary=executive_summary,
            analysis_duration=analysis_duration,
            api_calls_made=api_calls_made,
            cache_hit_rate=cache_hit_rate
        )
        
        return report
    
    def _create_dependency_analysis(
        self, 
        total_deps: int, 
        vulnerabilities: List[VulnerabilityDetail],
        repo_metadata: RepositoryMetadata
    ) -> DependencyAnalysis:
        """Create dependency analysis summary"""
        
        vulnerable_deps = len(set(v.package_name for v in vulnerabilities))
        ecosystems = self._detect_ecosystems(repo_metadata)
        
        # Simple dependency health scoring
        if total_deps == 0:
            health_score = 100
        else:
            vuln_ratio = vulnerable_deps / total_deps
            if vuln_ratio <= 0.05:  # <= 5% vulnerable
                health_score = 90
            elif vuln_ratio <= 0.10:  # <= 10% vulnerable
                health_score = 75
            elif vuln_ratio <= 0.20:  # <= 20% vulnerable
                health_score = 60
            elif vuln_ratio <= 0.30:  # <= 30% vulnerable
                health_score = 40
            else:
                health_score = 20
        
        return DependencyAnalysis(
            total_dependencies=total_deps,
            direct_dependencies=int(total_deps * 0.3),  # Estimate
            transitive_dependencies=int(total_deps * 0.7),  # Estimate
            outdated_dependencies=int(total_deps * 0.15),  # Estimate
            vulnerable_dependencies=vulnerable_deps,
            ecosystems=ecosystems,
            dependency_health_score=health_score
        )
    
    def _calculate_security_metrics(
        self, 
        vulnerabilities: List[VulnerabilityDetail],
        dependency_count: int
    ) -> SecurityMetrics:
        """Calculate security metrics"""
        
        if not vulnerabilities:
            return SecurityMetrics(
                vulnerability_density=0.0,
                mean_cvss_score=0.0,
                median_cvss_score=0.0
            )
        
        # Calculate vulnerability density per 1000 dependencies
        density = (len(vulnerabilities) / max(dependency_count, 1)) * 1000
        
        # Calculate CVSS statistics
        cvss_scores = [v.cvss_score for v in vulnerabilities if v.cvss_score > 0]
        mean_cvss = sum(cvss_scores) / len(cvss_scores) if cvss_scores else 0.0
        
        # Calculate median
        sorted_scores = sorted(cvss_scores)
        if sorted_scores:
            n = len(sorted_scores)
            median_cvss = (sorted_scores[n//2] if n % 2 == 1 
                          else (sorted_scores[n//2-1] + sorted_scores[n//2]) / 2)
        else:
            median_cvss = 0.0
        
        return SecurityMetrics(
            vulnerability_density=density,
            mean_cvss_score=mean_cvss,
            median_cvss_score=median_cvss,
            time_to_patch=None,  # Would require historical data
            exposure_window=None  # Would require historical data
        )
    
    def _generate_compliance_info(
        self,
        security_score: SecurityScoreBreakdown,
        vulnerabilities: List[VulnerabilityDetail]
    ) -> ComplianceInfo:
        """Generate compliance information"""
        
        critical_vulns = [v for v in vulnerabilities if v.severity == SeverityLevel.CRITICAL]
        high_vulns = [v for v in vulnerabilities if v.severity == SeverityLevel.HIGH]
        
        # Determine compliance status
        if critical_vulns:
            status = "NON_COMPLIANT"
            score = 0
        elif high_vulns and len(high_vulns) > 5:
            status = "PARTIAL_COMPLIANCE"
            score = 60
        elif security_score.overall_score < 70:
            status = "NEEDS_IMPROVEMENT"
            score = 70
        else:
            status = "COMPLIANT"
            score = 90
        
        # Applicable standards (simplified)
        standards = ["OWASP Top 10", "NIST Cybersecurity Framework"]
        if critical_vulns or high_vulns:
            standards.extend(["SOC 2", "ISO 27001"])
        
        findings = []
        recommendations = []
        
        if critical_vulns:
            findings.append(f"Found {len(critical_vulns)} critical vulnerabilities requiring immediate attention")
            recommendations.append("Patch all critical vulnerabilities within 24-48 hours")
        
        if high_vulns:
            findings.append(f"Found {len(high_vulns)} high-severity vulnerabilities")
            recommendations.append("Address high-severity vulnerabilities within 7 days")
        
        if security_score.maintenance_score.maintenance_score < 60:
            findings.append("Repository maintenance practices need improvement")
            recommendations.append("Establish regular maintenance schedule and dependency updates")
        
        return ComplianceInfo(
            compliance_status=status,
            applicable_standards=standards,
            compliance_score=score,
            findings=findings,
            recommendations=recommendations
        )
    
    def _create_executive_summary(
        self,
        security_score: SecurityScoreBreakdown,
        vulnerabilities: List[VulnerabilityDetail],
        dependency_analysis: DependencyAnalysis,
        repo_metadata: RepositoryMetadata
    ) -> Dict[str, Any]:
        """Create executive summary for business stakeholders"""
        self.stats["executive_summaries_created"] += 1
        
        critical_vulns = [v for v in vulnerabilities if v.severity == SeverityLevel.CRITICAL]
        high_vulns = [v for v in vulnerabilities if v.severity == SeverityLevel.HIGH]
        patchable = [v for v in vulnerabilities if v.patch_available]
        
        # Risk assessment
        if critical_vulns:
            risk_level = "HIGH"
            risk_description = f"Immediate action required: {len(critical_vulns)} critical vulnerabilities found"
        elif high_vulns and len(high_vulns) > 3:
            risk_level = "MEDIUM"
            risk_description = f"Multiple high-severity issues require attention: {len(high_vulns)} vulnerabilities"
        elif len(vulnerabilities) > 10:
            risk_level = "MEDIUM"
            risk_description = f"Moderate security concerns: {len(vulnerabilities)} total vulnerabilities"
        else:
            risk_level = "LOW"
            risk_description = "Minimal security concerns identified"
        
        # Business impact
        if critical_vulns or len(high_vulns) > 5:
            business_impact = "High - Potential for data breaches or service disruption"
        elif high_vulns:
            business_impact = "Medium - Elevated security risk requiring attention"
        else:
            business_impact = "Low - Routine security maintenance recommended"
        
        # Recommendations priority
        if critical_vulns:
            priority_action = "Immediate patching of critical vulnerabilities required"
            timeline = "24-48 hours"
        elif high_vulns:
            priority_action = "Address high-severity vulnerabilities"
            timeline = "7 days"
        else:
            priority_action = "Continue regular security maintenance"
            timeline = "30 days"
        
        return {
            "overall_assessment": {
                "security_grade": security_score.grade,
                "security_score": security_score.overall_score,
                "risk_level": risk_level,
                "risk_description": risk_description
            },
            "key_findings": {
                "total_vulnerabilities": len(vulnerabilities),
                "critical_issues": len(critical_vulns),
                "high_priority_issues": len(high_vulns),
                "patchable_issues": len(patchable),
                "dependency_health": dependency_analysis.dependency_health_score
            },
            "business_impact": {
                "assessment": business_impact,
                "potential_consequences": self._assess_business_consequences(critical_vulns, high_vulns),
                "compliance_status": "Compliant" if security_score.overall_score >= 70 else "Non-Compliant"
            },
            "recommended_actions": {
                "priority_action": priority_action,
                "timeline": timeline,
                "estimated_effort": self._estimate_remediation_effort(vulnerabilities),
                "next_review": (datetime.now() + timedelta(days=30)).strftime("%Y-%m-%d")
            },
            "comparative_performance": {
                "percentile": security_score.percentile,
                "comparison": security_score.comparison_text,
                "industry_benchmark": "Above average" if security_score.overall_score > 75 else "Below average"
            }
        }
    
    def _detect_ecosystems(self, repo_metadata: RepositoryMetadata) -> List[str]:
        """Detect package ecosystems from repository metadata"""
        ecosystems = []
        
        language = repo_metadata.language.lower() if repo_metadata.language else ""
        
        if "javascript" in language or "typescript" in language:
            ecosystems.extend(["npm", "yarn"])
        elif "python" in language:
            ecosystems.extend(["pypi", "pip"])
        elif "java" in language:
            ecosystems.extend(["maven", "gradle"])
        elif "rust" in language:
            ecosystems.append("cargo")
        elif "go" in language:
            ecosystems.append("go")
        elif "ruby" in language:
            ecosystems.append("rubygems")
        elif "php" in language:
            ecosystems.append("composer")
        
        return ecosystems if ecosystems else ["unknown"]
    
    def _assess_business_consequences(
        self, 
        critical_vulns: List[VulnerabilityDetail],
        high_vulns: List[VulnerabilityDetail]
    ) -> List[str]:
        """Assess potential business consequences"""
        consequences = []
        
        if critical_vulns:
            consequences.extend([
                "Data breaches and unauthorized access",
                "Service disruption and downtime",
                "Regulatory compliance violations",
                "Reputation damage and customer trust loss"
            ])
        elif high_vulns:
            consequences.extend([
                "Elevated security risk",
                "Potential for targeted attacks",
                "Compliance audit findings"
            ])
        else:
            consequences.append("Minimal immediate business impact")
        
        return consequences
    
    def _estimate_remediation_effort(self, vulnerabilities: List[VulnerabilityDetail]) -> str:
        """Estimate effort required for remediation"""
        patchable = [v for v in vulnerabilities if v.patch_available]
        
        if not vulnerabilities:
            return "Minimal - routine maintenance"
        elif len(patchable) == len(vulnerabilities):
            return "Low - patches available for all issues"
        elif len(patchable) >= len(vulnerabilities) * 0.8:
            return "Low-Medium - most issues have patches"
        elif len(patchable) >= len(vulnerabilities) * 0.5:
            return "Medium - some issues require custom fixes"
        else:
            return "High - many issues require development effort"
    
    def export_report(
        self, 
        report: DetailedAnalysisReport, 
        format_type: ReportFormat,
        audience: ReportAudience = ReportAudience.TECHNICAL
    ) -> str:
        """
        Export report in specified format
        
        Args:
            report: Detailed analysis report
            format_type: Desired export format
            audience: Target audience for customization
            
        Returns:
            Formatted report content
        """
        self.stats["formats_exported"] += 1
        
        if format_type == ReportFormat.JSON:
            return self._export_json(report)
        elif format_type == ReportFormat.MARKDOWN:
            return self._export_markdown(report, audience)
        elif format_type == ReportFormat.EXECUTIVE:
            return self._export_executive_summary(report)
        else:
            # Default to JSON for unsupported formats
            return self._export_json(report)
    
    def _export_json(self, report: DetailedAnalysisReport) -> str:
        """Export report as JSON"""
        import json
        return json.dumps(report.to_dict(), indent=2, default=str)
    
    def _export_markdown(self, report: DetailedAnalysisReport, audience: ReportAudience) -> str:
        """Export report as Markdown"""
        md_lines = []
        
        # Header
        md_lines.extend([
            f"# Security Analysis Report",
            f"**Repository:** {report.repository_info.full_name}",
            f"**Generated:** {report.generated_at.strftime('%Y-%m-%d %H:%M:%S')}",
            f"**Report ID:** {report.report_id}",
            "",
            "## Executive Summary",
            f"**Security Grade:** {report.security_score.grade}",
            f"**Overall Score:** {report.security_score.overall_score}/100",
            f"**Risk Level:** {report.executive_summary['overall_assessment']['risk_level']}",
            "",
            f"{report.executive_summary['overall_assessment']['risk_description']}",
            ""
        ])
        
        # Vulnerability Summary
        critical_count = len(report.get_critical_vulnerabilities())
        high_count = len(report.get_high_vulnerabilities())
        
        md_lines.extend([
            "## Vulnerability Summary",
            f"- **Critical:** {critical_count}",
            f"- **High:** {high_count}",
            f"- **Total:** {len(report.vulnerabilities)}",
            f"- **Patchable:** {len(report.get_patchable_vulnerabilities())}",
            ""
        ])
        
        # Critical Vulnerabilities (if any)
        if critical_count > 0:
            md_lines.extend([
                "## 🚨 Critical Vulnerabilities",
                ""
            ])
            
            for vuln in report.get_critical_vulnerabilities():
                md_lines.extend([
                    f"### {vuln.cve_id} - {vuln.package_name}",
                    f"**CVSS Score:** {vuln.cvss_score}",
                    f"**Package:** {vuln.package_name} v{vuln.package_version}",
                    f"**Patch Available:** {'✅ Yes' if vuln.patch_available else '❌ No'}",
                    "",
                    f"{vuln.description}",
                    ""
                ])
        
        # Recommendations
        if report.security_score.recommendations:
            md_lines.extend([
                "## Recommendations",
                ""
            ])
            
            for i, rec in enumerate(report.security_score.recommendations[:5], 1):
                md_lines.extend([
                    f"### {i}. {rec.title}",
                    f"**Priority:** {rec.priority.value.title()}",
                    f"**Impact:** {rec.impact}",
                    f"**Effort:** {rec.effort}",
                    "",
                    rec.description,
                    ""
                ])
        
        return "\n".join(md_lines)
    
    def _export_executive_summary(self, report: DetailedAnalysisReport) -> str:
        """Export executive summary as formatted text"""
        lines = []
        
        exec_summary = report.executive_summary
        
        lines.extend([
            "SECURITY ANALYSIS EXECUTIVE SUMMARY",
            "=" * 50,
            "",
            f"Repository: {report.repository_info.full_name}",
            f"Analysis Date: {report.generated_at.strftime('%B %d, %Y')}",
            "",
            "OVERALL ASSESSMENT",
            "-" * 20,
            f"Security Grade: {exec_summary['overall_assessment']['security_grade']}",
            f"Security Score: {exec_summary['overall_assessment']['security_score']}/100",
            f"Risk Level: {exec_summary['overall_assessment']['risk_level']}",
            "",
            f"{exec_summary['overall_assessment']['risk_description']}",
            "",
            "KEY FINDINGS",
            "-" * 20,
            f"• Total Vulnerabilities: {exec_summary['key_findings']['total_vulnerabilities']}",
            f"• Critical Issues: {exec_summary['key_findings']['critical_issues']}",
            f"• High Priority Issues: {exec_summary['key_findings']['high_priority_issues']}",
            f"• Patchable Issues: {exec_summary['key_findings']['patchable_issues']}",
            "",
            "BUSINESS IMPACT",
            "-" * 20,
            f"Assessment: {exec_summary['business_impact']['assessment']}",
            "",
            "Potential Consequences:",
        ])
        
        for consequence in exec_summary['business_impact']['potential_consequences']:
            lines.append(f"• {consequence}")
        
        lines.extend([
            "",
            "RECOMMENDED ACTIONS",
            "-" * 20,
            f"Priority Action: {exec_summary['recommended_actions']['priority_action']}",
            f"Timeline: {exec_summary['recommended_actions']['timeline']}",
            f"Estimated Effort: {exec_summary['recommended_actions']['estimated_effort']}",
            f"Next Review: {exec_summary['recommended_actions']['next_review']}",
            ""
        ])
        
        return "\n".join(lines)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get report generation statistics"""
        return dict(self.stats)


# Convenience functions

def generate_comprehensive_report(
    security_score: SecurityScoreBreakdown,
    vulnerabilities: List[EnrichedVulnerabilityData],
    repository_metadata: RepositoryMetadata,
    dependency_count: int = 0,
    analysis_duration: Optional[float] = None
) -> DetailedAnalysisReport:
    """
    Convenience function to generate comprehensive analysis report
    
    Args:
        security_score: Security score breakdown
        vulnerabilities: List of enriched vulnerabilities
        repository_metadata: Repository metadata
        dependency_count: Total dependencies analyzed
        analysis_duration: Analysis execution time
        
    Returns:
        Detailed analysis report
    """
    generator = ReportGenerator()
    return generator.generate_detailed_report(
        security_score=security_score,
        vulnerabilities=vulnerabilities,
        repository_metadata=repository_metadata,
        dependency_count=dependency_count,
        analysis_duration=analysis_duration
    )


def export_analysis_report(
    report: DetailedAnalysisReport,
    format_type: ReportFormat = ReportFormat.JSON,
    audience: ReportAudience = ReportAudience.TECHNICAL
) -> str:
    """
    Convenience function to export analysis report
    
    Args:
        report: Detailed analysis report
        format_type: Export format
        audience: Target audience
        
    Returns:
        Formatted report content
    """
    generator = ReportGenerator()
    return generator.export_report(report, format_type, audience)
