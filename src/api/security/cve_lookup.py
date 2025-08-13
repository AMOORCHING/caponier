"""
Advanced CVE Lookup Service with Enhanced Caching and Version Matching

This module provides sophisticated CVE lookup capabilities with:
- Multi-tier caching strategy (memory + persistent)
- Advanced package-to-CVE mapping
- Semantic version comparison and range matching
- CPE (Common Platform Enumeration) integration
- Batch lookup optimization
- Version-specific vulnerability assessment
"""

import asyncio
import logging
import hashlib
import json
import os
from typing import Dict, List, Any, Optional, Tuple, Set, Union
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from enum import Enum
import pickle
import aiofiles
from pathlib import Path
import re

from ..models import VulnerabilityData, SeverityLevel
from ..utils.exceptions import VulnerabilityServiceError, CacheError
from .vulnerability_scanner import NVDAPIClient, VulnerabilitySeverity
from .dependency_parser import ParsedDependency, PackageEcosystem

logger = logging.getLogger(__name__)


class CacheLevel(str, Enum):
    """Cache storage levels"""
    MEMORY = "memory"        # In-memory TTL cache
    PERSISTENT = "persistent" # File-based persistent cache
    DISTRIBUTED = "distributed" # Redis/distributed cache (future)


@dataclass
class PackageIdentifier:
    """Standardized package identifier for CVE lookup"""
    name: str
    version: str
    ecosystem: PackageEcosystem
    vendor: Optional[str] = None
    namespace: Optional[str] = None
    
    def __post_init__(self):
        """Normalize package identifier components"""
        self.name = self.name.lower().strip()
        self.version = self.version.strip() if self.version else "unknown"
        
        # Set default vendor based on ecosystem
        if not self.vendor:
            self.vendor = self._get_default_vendor()
    
    def _get_default_vendor(self) -> str:
        """Get default vendor based on ecosystem"""
        ecosystem_vendors = {
            PackageEcosystem.NPM: "nodejs",
            PackageEcosystem.YARN: "nodejs", 
            PackageEcosystem.PIP: "python",
            PackageEcosystem.PIPENV: "python",
            PackageEcosystem.POETRY: "python",
            PackageEcosystem.CARGO: "rust-lang",
            PackageEcosystem.MAVEN: "apache",
            PackageEcosystem.GRADLE: "gradle"
        }
        return ecosystem_vendors.get(self.ecosystem, "unknown")
    
    def to_cpe(self) -> str:
        """Convert to CPE (Common Platform Enumeration) format"""
        # CPE format: cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
        return f"cpe:2.3:a:{self.vendor}:{self.name}:{self.version}:*:*:*:*:*:*:*"
    
    def get_cache_key(self) -> str:
        """Generate cache key for this package"""
        components = [self.name, self.version, self.ecosystem.value]
        if self.vendor and self.vendor != "unknown":
            components.append(self.vendor)
        return hashlib.md5("|".join(components).encode()).hexdigest()


@dataclass 
class CVELookupResult:
    """Result of CVE lookup for a specific package"""
    package_id: PackageIdentifier
    vulnerabilities: List[VulnerabilityData]
    lookup_timestamp: datetime
    cache_hit: bool
    confidence_scores: Dict[str, float]  # CVE_ID -> confidence
    version_affected: Dict[str, bool]    # CVE_ID -> is_version_affected
    lookup_method: str
    api_calls_used: int
    
    def get_critical_high_vulnerabilities(self) -> List[VulnerabilityData]:
        """Get only critical and high severity vulnerabilities"""
        return [
            vuln for vuln in self.vulnerabilities 
            if vuln.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]
        ]
    
    def get_vulnerability_count_by_severity(self) -> Dict[SeverityLevel, int]:
        """Get count of vulnerabilities by severity level"""
        counts = {severity: 0 for severity in SeverityLevel}
        for vuln in self.vulnerabilities:
            counts[vuln.severity] += 1
        return counts


class PersistentCache:
    """File-based persistent cache for CVE data"""
    
    def __init__(self, cache_dir: str = ".cache/cve", max_age_hours: int = 24):
        """
        Initialize persistent cache
        
        Args:
            cache_dir: Directory for cache files
            max_age_hours: Maximum age of cache entries in hours
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.max_age = timedelta(hours=max_age_hours)
        
        # Index file for cache metadata
        self.index_file = self.cache_dir / "index.json"
        self.index = self._load_index()
    
    def _load_index(self) -> Dict[str, Dict[str, Any]]:
        """Load cache index from disk"""
        try:
            if self.index_file.exists():
                with open(self.index_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.warning(f"Failed to load cache index: {str(e)}")
        return {}
    
    def _save_index(self):
        """Save cache index to disk"""
        try:
            with open(self.index_file, 'w') as f:
                json.dump(self.index, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Failed to save cache index: {str(e)}")
    
    async def get(self, cache_key: str) -> Optional[CVELookupResult]:
        """Get cached result"""
        try:
            # Check index first
            if cache_key not in self.index:
                return None
            
            entry = self.index[cache_key]
            cache_time = datetime.fromisoformat(entry['timestamp'])
            
            # Check if expired
            if datetime.now() - cache_time > self.max_age:
                await self.delete(cache_key)
                return None
            
            # Load from file
            cache_file = self.cache_dir / f"{cache_key}.pkl"
            if not cache_file.exists():
                # Cleanup orphaned index entry
                del self.index[cache_key]
                self._save_index()
                return None
            
            async with aiofiles.open(cache_file, 'rb') as f:
                data = await f.read()
                result = pickle.loads(data)
                result.cache_hit = True
                return result
                
        except Exception as e:
            logger.error(f"Failed to get cached result for {cache_key}: {str(e)}")
            return None
    
    async def set(self, cache_key: str, result: CVELookupResult):
        """Cache result to disk"""
        try:
            cache_file = self.cache_dir / f"{cache_key}.pkl"
            
            # Serialize result
            async with aiofiles.open(cache_file, 'wb') as f:
                data = pickle.dumps(result)
                await f.write(data)
            
            # Update index
            self.index[cache_key] = {
                'timestamp': datetime.now().isoformat(),
                'package_name': result.package_id.name,
                'package_version': result.package_id.version,
                'ecosystem': result.package_id.ecosystem.value,
                'vulnerability_count': len(result.vulnerabilities)
            }
            self._save_index()
            
        except Exception as e:
            logger.error(f"Failed to cache result for {cache_key}: {str(e)}")
    
    async def delete(self, cache_key: str):
        """Delete cached entry"""
        try:
            cache_file = self.cache_dir / f"{cache_key}.pkl"
            if cache_file.exists():
                cache_file.unlink()
            
            if cache_key in self.index:
                del self.index[cache_key]
                self._save_index()
                
        except Exception as e:
            logger.error(f"Failed to delete cache entry {cache_key}: {str(e)}")
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        total_entries = len(self.index)
        total_size = 0
        
        for cache_file in self.cache_dir.glob("*.pkl"):
            try:
                total_size += cache_file.stat().st_size
            except:
                pass
        
        return {
            "total_entries": total_entries,
            "total_size_bytes": total_size,
            "cache_directory": str(self.cache_dir),
            "index_entries": list(self.index.keys())[:10]  # Sample entries
        }


class VersionMatcher:
    """Advanced semantic version matching and range checking"""
    
    @staticmethod
    def normalize_version(version: str) -> Tuple[List[int], str]:
        """
        Normalize version string to comparable format
        
        Returns:
            Tuple of (numeric_parts, original_string)
        """
        if not version or version == "unknown":
            return ([0], version)
        
        # Remove common prefixes
        clean_version = re.sub(r'^[v=~^<>]+', '', version.strip())
        
        # Extract numeric parts
        numeric_parts = []
        for part in re.split(r'[.-]', clean_version):
            try:
                # Extract first number from part (handles "1rc1" -> 1)
                number_match = re.match(r'(\d+)', part)
                if number_match:
                    numeric_parts.append(int(number_match.group(1)))
            except ValueError:
                continue
        
        return (numeric_parts if numeric_parts else [0], clean_version)
    
    @staticmethod
    def version_in_range(target_version: str, vulnerable_ranges: List[str]) -> bool:
        """
        Check if target version falls within vulnerable version ranges
        
        Args:
            target_version: Version to check
            vulnerable_ranges: List of version ranges (e.g., ["<2.15.0", ">=2.0.0"])
            
        Returns:
            True if version is vulnerable
        """
        if not vulnerable_ranges:
            return False
        
        target_parts, _ = VersionMatcher.normalize_version(target_version)
        
        for range_spec in vulnerable_ranges:
            if VersionMatcher._version_matches_range(target_parts, range_spec):
                return True
        
        return False
    
    @staticmethod
    def _version_matches_range(target_parts: List[int], range_spec: str) -> bool:
        """Check if version matches a specific range specification"""
        range_spec = range_spec.strip()
        
        # Parse range operators
        if range_spec.startswith('>='):
            range_parts, _ = VersionMatcher.normalize_version(range_spec[2:])
            return VersionMatcher._compare_versions(target_parts, range_parts) >= 0
        elif range_spec.startswith('<='):
            range_parts, _ = VersionMatcher.normalize_version(range_spec[2:])
            return VersionMatcher._compare_versions(target_parts, range_parts) <= 0
        elif range_spec.startswith('>'):
            range_parts, _ = VersionMatcher.normalize_version(range_spec[1:])
            return VersionMatcher._compare_versions(target_parts, range_parts) > 0
        elif range_spec.startswith('<'):
            range_parts, _ = VersionMatcher.normalize_version(range_spec[1:])
            return VersionMatcher._compare_versions(target_parts, range_parts) < 0
        elif range_spec.startswith('='):
            range_parts, _ = VersionMatcher.normalize_version(range_spec[1:])
            return VersionMatcher._compare_versions(target_parts, range_parts) == 0
        else:
            # Exact match
            range_parts, _ = VersionMatcher.normalize_version(range_spec)
            return VersionMatcher._compare_versions(target_parts, range_parts) == 0
    
    @staticmethod
    def _compare_versions(v1_parts: List[int], v2_parts: List[int]) -> int:
        """
        Compare two version part lists
        
        Returns:
            -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
        """
        # Pad shorter version with zeros
        max_len = max(len(v1_parts), len(v2_parts))
        v1_padded = v1_parts + [0] * (max_len - len(v1_parts))
        v2_padded = v2_parts + [0] * (max_len - len(v2_parts))
        
        for i in range(max_len):
            if v1_padded[i] < v2_padded[i]:
                return -1
            elif v1_padded[i] > v2_padded[i]:
                return 1
        
        return 0


class AdvancedCVELookup:
    """
    Advanced CVE lookup service with multi-tier caching and version matching
    """
    
    def __init__(
        self,
        nvd_client: Optional[NVDAPIClient] = None,
        enable_persistent_cache: bool = True,
        cache_dir: str = ".cache/cve",
        memory_cache_ttl: int = 3600,  # 1 hour
        persistent_cache_ttl: int = 24,  # 24 hours
        batch_size: int = 5
    ):
        """
        Initialize advanced CVE lookup service
        
        Args:
            nvd_client: NVD API client
            enable_persistent_cache: Enable file-based caching
            cache_dir: Directory for persistent cache
            memory_cache_ttl: Memory cache TTL in seconds
            persistent_cache_ttl: Persistent cache TTL in hours
            batch_size: Batch size for parallel lookups
        """
        self.nvd_client = nvd_client
        self.batch_size = batch_size
        
        # Multi-tier caching
        self.memory_cache = {}  # Simple dict cache for this session
        self.memory_cache_ttl = memory_cache_ttl
        self.memory_timestamps = {}
        
        self.persistent_cache = None
        if enable_persistent_cache:
            self.persistent_cache = PersistentCache(cache_dir, persistent_cache_ttl)
        
        # Version matcher
        self.version_matcher = VersionMatcher()
        
        # Statistics
        self.stats = {
            "total_lookups": 0,
            "memory_cache_hits": 0,
            "persistent_cache_hits": 0,
            "api_calls": 0,
            "batch_operations": 0
        }
    
    async def __aenter__(self):
        """Async context manager entry"""
        if not self.nvd_client:
            self.nvd_client = NVDAPIClient()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.nvd_client:
            await self.nvd_client.close()
    
    async def lookup_package_vulnerabilities(
        self,
        package_id: PackageIdentifier,
        include_low_severity: bool = False,
        force_refresh: bool = False
    ) -> CVELookupResult:
        """
        Lookup vulnerabilities for a specific package
        
        Args:
            package_id: Package identifier
            include_low_severity: Include low/medium severity vulnerabilities
            force_refresh: Force refresh from API (bypass cache)
            
        Returns:
            CVE lookup result with vulnerabilities
        """
        self.stats["total_lookups"] += 1
        cache_key = package_id.get_cache_key()
        
        # Check caches unless forcing refresh
        if not force_refresh:
            # 1. Check memory cache
            cached_result = await self._get_from_memory_cache(cache_key)
            if cached_result:
                self.stats["memory_cache_hits"] += 1
                return cached_result
            
            # 2. Check persistent cache
            if self.persistent_cache:
                cached_result = await self.persistent_cache.get(cache_key)
                if cached_result:
                    self.stats["persistent_cache_hits"] += 1
                    # Also store in memory cache
                    await self._store_in_memory_cache(cache_key, cached_result)
                    return cached_result
        
        # 3. Fetch from API
        result = await self._fetch_from_api(package_id, include_low_severity)
        
        # 4. Store in caches
        await self._store_in_memory_cache(cache_key, result)
        if self.persistent_cache:
            await self.persistent_cache.set(cache_key, result)
        
        return result
    
    async def batch_lookup_vulnerabilities(
        self,
        package_ids: List[PackageIdentifier],
        include_low_severity: bool = False
    ) -> List[CVELookupResult]:
        """
        Batch lookup vulnerabilities for multiple packages
        
        Args:
            package_ids: List of package identifiers
            include_low_severity: Include low/medium severity vulnerabilities
            
        Returns:
            List of CVE lookup results
        """
        self.stats["batch_operations"] += 1
        
        # Process in batches to avoid overwhelming the API
        results = []
        for i in range(0, len(package_ids), self.batch_size):
            batch = package_ids[i:i + self.batch_size]
            
            # Process batch concurrently
            tasks = [
                self.lookup_package_vulnerabilities(pkg_id, include_low_severity)
                for pkg_id in batch
            ]
            
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in batch_results:
                if isinstance(result, Exception):
                    logger.error(f"Error in batch lookup: {str(result)}")
                    continue
                results.append(result)
            
            # Small delay between batches
            if i + self.batch_size < len(package_ids):
                await asyncio.sleep(0.5)
        
        return results
    
    async def _get_from_memory_cache(self, cache_key: str) -> Optional[CVELookupResult]:
        """Get result from memory cache"""
        if cache_key not in self.memory_cache:
            return None
        
        # Check TTL
        timestamp = self.memory_timestamps.get(cache_key, datetime.min)
        if datetime.now() - timestamp > timedelta(seconds=self.memory_cache_ttl):
            # Expired
            del self.memory_cache[cache_key]
            del self.memory_timestamps[cache_key]
            return None
        
        result = self.memory_cache[cache_key]
        result.cache_hit = True
        return result
    
    async def _store_in_memory_cache(self, cache_key: str, result: CVELookupResult):
        """Store result in memory cache"""
        self.memory_cache[cache_key] = result
        self.memory_timestamps[cache_key] = datetime.now()
    
    async def _fetch_from_api(
        self,
        package_id: PackageIdentifier,
        include_low_severity: bool
    ) -> CVELookupResult:
        """Fetch vulnerabilities from NVD API"""
        self.stats["api_calls"] += 1
        api_calls_used = 0
        
        try:
            # Search by package name
            nvd_response = await self.nvd_client.search_cves_by_keyword(
                keyword=package_id.name,
                results_per_page=50
            )
            api_calls_used += 1
            
            vulnerabilities = []
            confidence_scores = {}
            version_affected = {}
            
            for cve_data in nvd_response.cves:
                cve = cve_data.get("cve", {})
                cve_id = cve.get("id", "")
                
                # Parse vulnerability data
                vuln_data = self._parse_cve_to_vulnerability_data(
                    cve_data, package_id.name, package_id.version
                )
                
                # Calculate confidence and version matching
                confidence = self._calculate_confidence(cve_data, package_id)
                is_version_affected = self._check_version_affected(cve_data, package_id)
                
                # Apply severity filter
                if not include_low_severity:
                    if vuln_data.severity not in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]:
                        continue
                
                # Apply confidence filter (only high confidence matches)
                if confidence >= 0.5:  # Threshold for inclusion
                    vulnerabilities.append(vuln_data)
                    confidence_scores[cve_id] = confidence
                    version_affected[cve_id] = is_version_affected
            
            return CVELookupResult(
                package_id=package_id,
                vulnerabilities=vulnerabilities,
                lookup_timestamp=datetime.now(),
                cache_hit=False,
                confidence_scores=confidence_scores,
                version_affected=version_affected,
                lookup_method="nvd_api_keyword_search",
                api_calls_used=api_calls_used
            )
            
        except Exception as e:
            logger.error(f"Failed to fetch CVE data for {package_id.name}: {str(e)}")
            raise VulnerabilityServiceError(
                f"CVE lookup failed for package {package_id.name}",
                service="NVD API"
            )
    
    def _parse_cve_to_vulnerability_data(
        self,
        cve_data: Dict[str, Any],
        package_name: str,
        package_version: str
    ) -> VulnerabilityData:
        """Parse CVE data to VulnerabilityData model"""
        cve = cve_data.get("cve", {})
        cve_id = cve.get("id", "")
        
        # Extract description
        descriptions = cve.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break
        
        # Extract CVSS score
        metrics = cve.get("metrics", {})
        cvss_score = 0.0
        
        for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if version in metrics and metrics[version]:
                metric = metrics[version][0]
                cvss_data = metric.get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", 0.0)
                break
        
        # Map severity
        severity = self._map_cvss_to_severity(cvss_score)
        
        # Parse dates
        published_date = None
        modified_date = None
        try:
            if cve.get("published"):
                published_date = datetime.fromisoformat(cve["published"].replace('Z', '+00:00'))
            if cve.get("lastModified"):
                modified_date = datetime.fromisoformat(cve["lastModified"].replace('Z', '+00:00'))
        except Exception:
            pass
        
        return VulnerabilityData(
            cve_id=cve_id,
            package_name=package_name,
            package_version=package_version,
            severity=severity,
            cvss_score=cvss_score,
            description=description,
            cve_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            published_date=published_date,
            last_modified=modified_date
        )
    
    def _map_cvss_to_severity(self, cvss_score: float) -> SeverityLevel:
        """Map CVSS score to severity level"""
        if cvss_score >= 9.0:
            return SeverityLevel.CRITICAL
        elif cvss_score >= 7.0:
            return SeverityLevel.HIGH
        elif cvss_score >= 4.0:
            return SeverityLevel.MEDIUM
        else:
            return SeverityLevel.LOW
    
    def _calculate_confidence(self, cve_data: Dict[str, Any], package_id: PackageIdentifier) -> float:
        """Calculate confidence score for CVE-package match"""
        confidence = 0.0
        cve = cve_data.get("cve", {})
        
        # Extract description for analysis
        descriptions = cve.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "").lower()
                break
        
        package_name_lower = package_id.name.lower()
        
        # Exact package name in description
        if f" {package_name_lower} " in description or description.startswith(package_name_lower):
            confidence += 0.7
        elif package_name_lower in description:
            confidence += 0.5
        
        # Version mentioned
        if package_id.version != "unknown" and package_id.version in description:
            confidence += 0.2
        
        # Ecosystem/vendor context
        ecosystem_keywords = {
            PackageEcosystem.NPM: ["node", "npm", "javascript"],
            PackageEcosystem.PIP: ["python", "pip", "pypi"],
            PackageEcosystem.CARGO: ["rust", "cargo", "crates"],
            PackageEcosystem.MAVEN: ["java", "maven", "apache"]
        }
        
        keywords = ecosystem_keywords.get(package_id.ecosystem, [])
        for keyword in keywords:
            if keyword in description:
                confidence += 0.1
                break
        
        return min(confidence, 1.0)
    
    def _check_version_affected(self, cve_data: Dict[str, Any], package_id: PackageIdentifier) -> bool:
        """Check if specific package version is affected"""
        # This is a simplified implementation
        # In production, you would parse CPE data and version ranges from the CVE
        
        if package_id.version == "unknown":
            return True  # Assume vulnerable if version unknown
        
        # For now, use heuristic based on description
        cve = cve_data.get("cve", {})
        descriptions = cve.get("descriptions", [])
        
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                
                # Look for version patterns in description
                if package_id.version in description:
                    return True
                
                # Look for version range patterns (this is simplified)
                version_patterns = [
                    r"versions?\s+([<>=!]+)\s*([0-9.]+)",
                    r"before\s+([0-9.]+)",
                    r"prior\s+to\s+([0-9.]+)"
                ]
                
                for pattern in version_patterns:
                    matches = re.findall(pattern, description, re.IGNORECASE)
                    if matches:
                        # Simple heuristic - in production, use proper semantic version comparison
                        return True
        
        return False  # Default to not affected if we can't determine
    
    def get_stats(self) -> Dict[str, Any]:
        """Get lookup service statistics"""
        cache_stats = {}
        if self.persistent_cache:
            cache_stats = self.persistent_cache.get_cache_stats()
        
        return {
            **self.stats,
            "memory_cache_size": len(self.memory_cache),
            "persistent_cache": cache_stats,
            "cache_hit_rate": (
                (self.stats["memory_cache_hits"] + self.stats["persistent_cache_hits"]) / 
                max(self.stats["total_lookups"], 1)
            )
        }


# Convenience functions for easy integration

async def lookup_vulnerabilities_for_dependency(
    dependency: ParsedDependency,
    include_low_severity: bool = False,
    nvd_client: Optional[NVDAPIClient] = None
) -> CVELookupResult:
    """
    Convenience function to lookup vulnerabilities for a single dependency
    
    Args:
        dependency: Parsed dependency to check
        include_low_severity: Include low/medium severity vulnerabilities
        nvd_client: Optional NVD API client
        
    Returns:
        CVE lookup result
    """
    package_id = PackageIdentifier(
        name=dependency.name,
        version=dependency.version,
        ecosystem=dependency.ecosystem
    )
    
    async with AdvancedCVELookup(nvd_client) as lookup_service:
        return await lookup_service.lookup_package_vulnerabilities(
            package_id, include_low_severity
        )


async def batch_lookup_vulnerabilities_for_dependencies(
    dependencies: List[ParsedDependency],
    include_low_severity: bool = False,
    nvd_client: Optional[NVDAPIClient] = None
) -> List[CVELookupResult]:
    """
    Convenience function to lookup vulnerabilities for multiple dependencies
    
    Args:
        dependencies: List of parsed dependencies to check
        include_low_severity: Include low/medium severity vulnerabilities
        nvd_client: Optional NVD API client
        
    Returns:
        List of CVE lookup results
    """
    package_ids = [
        PackageIdentifier(
            name=dep.name,
            version=dep.version,
            ecosystem=dep.ecosystem
        )
        for dep in dependencies
    ]
    
    async with AdvancedCVELookup(nvd_client) as lookup_service:
        return await lookup_service.batch_lookup_vulnerabilities(
            package_ids, include_low_severity
        )
