"""
Maven dependency parser for pom.xml files.

This module provides robust XML parsing for Maven pom.xml files using lxml
for better performance and error handling compared to regex-based parsing.
"""

import logging
from typing import Dict, List, Any, Optional
from lxml import etree
from .base import DependencyParser, ParsedDependency, DependencyParseResult, PackageEcosystem

logger = logging.getLogger(__name__)


class MavenParser(DependencyParser):
    """
    Parser for Maven pom.xml files.
    
    Uses lxml for robust XML parsing with proper error handling and
    support for Maven's dependency management features.
    """
    
    def __init__(self):
        """Initialize the Maven parser."""
        self.ecosystem = PackageEcosystem.MAVEN
    
    def parse(self, file_content: str, manifest_file: str) -> DependencyParseResult:
        """
        Parse Maven pom.xml file content.
        
        Args:
            file_content: Raw XML content of pom.xml
            manifest_file: Name/path of the pom.xml file
            
        Returns:
            DependencyParseResult containing parsed dependencies
            
        Raises:
            DependencyParsingError: If XML is malformed or parsing fails
        """
        dependencies = []
        parsing_errors = []
        metadata = {}
        
        try:
            # Parse XML with lxml
            root = etree.fromstring(file_content.encode('utf-8'))
            
            # Extract project metadata
            metadata = self._extract_project_metadata(root)
            
            # Parse dependencies
            dependencies.extend(self._parse_dependencies(root, "dependencies/dependency"))
            dependencies.extend(self._parse_dependencies(root, "build/plugins/plugin"))
            dependencies.extend(self._parse_dependencies(root, "build/pluginManagement/plugins/plugin"))
            
            # Parse dependency management
            managed_deps = self._parse_dependency_management(root)
            
            # Apply version management
            dependencies = self._apply_dependency_management(dependencies, managed_deps)
            
        except etree.XMLSyntaxError as e:
            error_msg = f"Invalid XML in {manifest_file}: {e}"
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
        """Get list of supported Maven files."""
        return ["pom.xml"]
    
    def get_ecosystem(self) -> PackageEcosystem:
        """Get the Maven ecosystem."""
        return self.ecosystem
    
    def _extract_project_metadata(self, root: etree._Element) -> Dict[str, Any]:
        """Extract project metadata from pom.xml."""
        metadata = {}
        
        # Extract basic project info
        group_id = root.find("groupId")
        artifact_id = root.find("artifactId")
        version = root.find("version")
        
        if group_id is not None:
            metadata["groupId"] = group_id.text
        if artifact_id is not None:
            metadata["artifactId"] = artifact_id.text
        if version is not None:
            metadata["version"] = version.text
        
        # Extract parent info
        parent = root.find("parent")
        if parent is not None:
            parent_metadata = {}
            for field in ["groupId", "artifactId", "version"]:
                elem = parent.find(field)
                if elem is not None:
                    parent_metadata[field] = elem.text
            metadata["parent"] = parent_metadata
        
        return metadata
    
    def _parse_dependencies(self, root: etree._Element, xpath: str) -> List[ParsedDependency]:
        """Parse dependencies using XPath."""
        dependencies = []
        
        for dep_elem in root.xpath(xpath):
            try:
                dep = self._parse_single_dependency(dep_elem)
                if dep:
                    dependencies.append(dep)
            except Exception as e:
                logger.warning(f"Error parsing dependency: {e}")
                continue
        
        return dependencies
    
    def _parse_single_dependency(self, dep_elem: etree._Element) -> Optional[ParsedDependency]:
        """Parse a single dependency element."""
        try:
            # Extract basic dependency info
            group_id = dep_elem.find("groupId")
            artifact_id = dep_elem.find("artifactId")
            version = dep_elem.find("version")
            scope = dep_elem.find("scope")
            optional = dep_elem.find("optional")
            
            if group_id is None or artifact_id is None:
                return None
            
            # Determine if it's a dev dependency
            is_dev = False
            if scope is not None and scope.text in ["test", "provided"]:
                is_dev = True
            
            # Handle optional dependencies
            is_optional = False
            if optional is not None and optional.text == "true":
                is_optional = True
            
            # Create dependency name (groupId:artifactId)
            name = f"{group_id.text}:{artifact_id.text}"
            
            # Handle version
            version_text = version.text if version is not None else ""
            version_constraint = version_text
            
            return ParsedDependency(
                name=name,
                version=version_text,
                version_constraint=version_constraint,
                ecosystem=self.ecosystem,
                manifest_file="pom.xml",
                is_dev_dependency=is_dev,
                is_optional=is_optional,
                scope=scope.text if scope is not None else None
            )
            
        except Exception as e:
            logger.warning(f"Error parsing dependency element: {e}")
            return None
    
    def _parse_dependency_management(self, root: etree._Element) -> Dict[str, str]:
        """Parse dependency management section for version resolution."""
        managed_versions = {}
        
        management = root.find("dependencyManagement")
        if management is not None:
            for dep in management.xpath("dependencies/dependency"):
                try:
                    group_id = dep.find("groupId")
                    artifact_id = dep.find("artifactId")
                    version = dep.find("version")
                    
                    if group_id is not None and artifact_id is not None and version is not None:
                        key = f"{group_id.text}:{artifact_id.text}"
                        managed_versions[key] = version.text
                except Exception as e:
                    logger.warning(f"Error parsing managed dependency: {e}")
                    continue
        
        return managed_versions
    
    def _apply_dependency_management(self, dependencies: List[ParsedDependency], 
                                   managed_versions: Dict[str, str]) -> List[ParsedDependency]:
        """Apply dependency management versions to dependencies without explicit versions."""
        for dep in dependencies:
            if not dep.version and dep.name in managed_versions:
                dep.version = managed_versions[dep.name]
                dep.version_constraint = managed_versions[dep.name]
        
        return dependencies
