"""
NPM dependency parser for package.json and package-lock.json files.

This module provides robust JSON parsing for NPM dependency files using
proper JSON parsing with validation instead of regex-based approaches.
"""

import json
import logging
from typing import Dict, List, Any, Optional
from .base import DependencyParser, ParsedDependency, DependencyParseResult, PackageEcosystem

logger = logging.getLogger(__name__)


class NpmParser(DependencyParser):
    """
    Parser for NPM package.json and package-lock.json files.
    
    Uses proper JSON parsing with validation for reliable dependency extraction
    and support for NPM's dependency management features.
    """
    
    def __init__(self):
        """Initialize the NPM parser."""
        self.ecosystem = PackageEcosystem.NPM
    
    def parse(self, file_content: str, manifest_file: str) -> DependencyParseResult:
        """
        Parse NPM package.json or package-lock.json file content.
        
        Args:
            file_content: Raw JSON content of the file
            manifest_file: Name/path of the file being parsed
            
        Returns:
            DependencyParseResult containing parsed dependencies
            
        Raises:
            DependencyParsingError: If JSON is malformed or parsing fails
        """
        dependencies = []
        parsing_errors = []
        metadata = {}
        
        try:
            # Parse JSON
            data = json.loads(file_content)
            
            if manifest_file == "package.json":
                result = self._parse_package_json(data, manifest_file)
            elif manifest_file == "package-lock.json":
                result = self._parse_package_lock_json(data, manifest_file)
            else:
                error_msg = f"Unsupported NPM file: {manifest_file}"
                logger.error(error_msg)
                parsing_errors.append(error_msg)
                return DependencyParseResult(
                    dependencies=[],
                    ecosystem=self.ecosystem,
                    manifest_file=manifest_file,
                    total_dependencies=0,
                    dev_dependencies=0,
                    production_dependencies=0,
                    parsing_errors=parsing_errors,
                    metadata={}
                )
            
            dependencies = result["dependencies"]
            metadata = result["metadata"]
            
        except json.JSONDecodeError as e:
            error_msg = f"Invalid JSON in {manifest_file}: {e}"
            logger.error(error_msg)
            parsing_errors.append(error_msg)
        except Exception as e:
            error_msg = f"Error parsing {manifest_file}: {e}"
            logger.error(error_msg)
            parsing_errors.append(error_msg)
        
        # Calculate statistics
        total_deps = len(dependencies)
        dev_deps = len([d for d in dependencies if d.is_dev_dependency])
        prod_deps = total_deps - dev_deps
        
        return DependencyParseResult(
            dependencies=dependencies,
            ecosystem=self.ecosystem,
            manifest_file=manifest_file,
            total_dependencies=total_deps,
            dev_dependencies=dev_deps,
            production_dependencies=prod_deps,
            parsing_errors=parsing_errors,
            metadata=metadata
        )
    
    def supported_files(self) -> List[str]:
        """Get list of supported NPM files."""
        return ["package.json", "package-lock.json"]
    
    def get_ecosystem(self) -> PackageEcosystem:
        """Get the NPM ecosystem."""
        return self.ecosystem
    
    def _parse_package_json(self, data: Dict[str, Any], manifest_file: str) -> Dict[str, Any]:
        """Parse package.json file."""
        dependencies = []
        metadata = {}
        
        # Extract package metadata
        metadata["name"] = data.get("name", "")
        metadata["version"] = data.get("version", "")
        metadata["description"] = data.get("description", "")
        
        # Parse production dependencies
        deps = data.get("dependencies", {})
        for name, version in deps.items():
            dep = ParsedDependency(
                name=name,
                version=version,
                version_constraint=version,
                ecosystem=self.ecosystem,
                manifest_file=manifest_file,
                is_dev_dependency=False
            )
            dependencies.append(dep)
        
        # Parse development dependencies
        dev_deps = data.get("devDependencies", {})
        for name, version in dev_deps.items():
            dep = ParsedDependency(
                name=name,
                version=version,
                version_constraint=version,
                ecosystem=self.ecosystem,
                manifest_file=manifest_file,
                is_dev_dependency=True
            )
            dependencies.append(dep)
        
        # Parse peer dependencies
        peer_deps = data.get("peerDependencies", {})
        for name, version in peer_deps.items():
            dep = ParsedDependency(
                name=name,
                version=version,
                version_constraint=version,
                ecosystem=self.ecosystem,
                manifest_file=manifest_file,
                is_dev_dependency=False,
                scope="peer"
            )
            dependencies.append(dep)
        
        # Parse optional dependencies
        optional_deps = data.get("optionalDependencies", {})
        for name, version in optional_deps.items():
            dep = ParsedDependency(
                name=name,
                version=version,
                version_constraint=version,
                ecosystem=self.ecosystem,
                manifest_file=manifest_file,
                is_dev_dependency=False,
                is_optional=True
            )
            dependencies.append(dep)
        
        return {
            "dependencies": dependencies,
            "metadata": metadata
        }
    
    def _parse_package_lock_json(self, data: Dict[str, Any], manifest_file: str) -> Dict[str, Any]:
        """Parse package-lock.json file."""
        dependencies = []
        metadata = {}
        
        # Extract lock file metadata
        metadata["lockfileVersion"] = data.get("lockfileVersion", "")
        metadata["name"] = data.get("name", "")
        metadata["version"] = data.get("version", "")
        
        # Parse dependencies
        deps = data.get("dependencies", {})
        for name, dep_info in deps.items():
            if isinstance(dep_info, dict):
                version = dep_info.get("version", "")
                resolved = dep_info.get("resolved", "")
                integrity = dep_info.get("integrity", "")
                
                # Check if it's a dev dependency (inferred from devDependencies in package.json)
                is_dev = False  # This would need to be determined from package.json context
                
                dep = ParsedDependency(
                    name=name,
                    version=version,
                    version_constraint=version,
                    ecosystem=self.ecosystem,
                    manifest_file=manifest_file,
                    is_dev_dependency=is_dev
                )
                dependencies.append(dep)
                
                # Parse nested dependencies
                nested_deps = dep_info.get("dependencies", {})
                for nested_name, nested_info in nested_deps.items():
                    if isinstance(nested_info, dict):
                        nested_version = nested_info.get("version", "")
                        nested_dep = ParsedDependency(
                            name=nested_name,
                            version=nested_version,
                            version_constraint=nested_version,
                            ecosystem=self.ecosystem,
                            manifest_file=manifest_file,
                            is_dev_dependency=is_dev
                        )
                        dependencies.append(nested_dep)
        
        return {
            "dependencies": dependencies,
            "metadata": metadata
        }
