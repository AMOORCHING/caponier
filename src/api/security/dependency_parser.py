"""
Dependency parser for multiple package ecosystems

This module provides comprehensive dependency parsing for various package management systems:
- Node.js/npm (package.json, package-lock.json, yarn.lock)
- Python/pip (requirements.txt, Pipfile, poetry.lock)
- Rust/Cargo (Cargo.toml, Cargo.lock)
- Java/Maven & Gradle (pom.xml, build.gradle)
- Go modules (go.mod)
- PHP/Composer (composer.json)
- Ruby/Bundler (Gemfile)
"""

import json
import re
import logging
from typing import Dict, List, Any, Optional, Tuple, Union
from dataclasses import dataclass
from enum import Enum
# Import toml and yaml with fallback
try:
    import toml
except ImportError:
    toml = None

try:
    import yaml
except ImportError:
    yaml = None

try:
    import xml.etree.ElementTree as ET
except ImportError:
    ET = None

from ..models import DependencyInfo
from ..utils.exceptions import DependencyParsingError
from .github_client import GitHubAPIClient

logger = logging.getLogger(__name__)


class PackageEcosystem(str, Enum):
    """Supported package ecosystems"""
    NPM = "npm"
    YARN = "yarn"
    PIP = "pip"
    PIPENV = "pipenv"
    POETRY = "poetry"
    CARGO = "cargo"
    MAVEN = "maven"
    GRADLE = "gradle"
    GO_MOD = "go"
    COMPOSER = "composer"
    BUNDLER = "bundler"


@dataclass
class ParsedDependency:
    """Parsed dependency information"""
    name: str
    version: str
    version_constraint: str
    ecosystem: PackageEcosystem
    manifest_file: str
    is_dev_dependency: bool = False
    is_optional: bool = False
    scope: Optional[str] = None


@dataclass
class DependencyParseResult:
    """Result of dependency parsing operation"""
    dependencies: List[ParsedDependency]
    ecosystem: PackageEcosystem
    manifest_file: str
    total_dependencies: int
    dev_dependencies: int
    production_dependencies: int
    parsing_errors: List[str]
    metadata: Dict[str, Any]


class PythonDependencyParser:
    """
    Parser for Python/pip ecosystem dependency files
    
    Supports:
    - requirements.txt (pip)
    - Pipfile (pipenv)
    - poetry.lock (poetry)
    - setup.py (setuptools)
    """
    
    @staticmethod
    def parse_requirements_txt(content: str, manifest_file: str = "requirements.txt") -> DependencyParseResult:
        """
        Parse requirements.txt file for dependencies
        
        Args:
            content: File content as string
            manifest_file: Name of the manifest file
            
        Returns:
            Dependency parse result
        """
        try:
            dependencies = []
            errors = []
            
            lines = content.strip().split('\n')
            
            for line_num, line in enumerate(lines, 1):
                # Skip empty lines and comments
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # Handle pip options/flags
                if line.startswith('-'):
                    # Skip pip flags like -r, -e, --index-url, etc.
                    continue
                
                try:
                    parsed_dep = PythonDependencyParser._parse_requirement_line(line)
                    if parsed_dep:
                        dependencies.append(ParsedDependency(
                            name=parsed_dep['name'],
                            version=parsed_dep['version'],
                            version_constraint=parsed_dep['constraint'],
                            ecosystem=PackageEcosystem.PIP,
                            manifest_file=manifest_file,
                            is_dev_dependency=False  # requirements.txt doesn't distinguish
                        ))
                except Exception as e:
                    errors.append(f"Line {line_num}: Failed to parse '{line}': {str(e)}")
            
            # Extract metadata (limited for requirements.txt)
            metadata = {
                "total_lines": len(lines),
                "comment_lines": len([l for l in lines if l.strip().startswith('#')]),
                "empty_lines": len([l for l in lines if not l.strip()]),
                "pip_options": len([l for l in lines if l.strip().startswith('-')])
            }
            
            return DependencyParseResult(
                dependencies=dependencies,
                ecosystem=PackageEcosystem.PIP,
                manifest_file=manifest_file,
                total_dependencies=len(dependencies),
                dev_dependencies=0,  # Can't distinguish in requirements.txt
                production_dependencies=len(dependencies),
                parsing_errors=errors,
                metadata=metadata
            )
            
        except Exception as e:
            raise DependencyParsingError(
                manifest_file,
                f"Failed to parse requirements.txt: {str(e)}",
                PackageEcosystem.PIP
            )
    
    @staticmethod
    def parse_pipfile(content: str, manifest_file: str = "Pipfile") -> DependencyParseResult:
        """
        Parse Pipfile for dependencies
        
        Args:
            content: File content as string
            manifest_file: Name of the manifest file
            
        Returns:
            Dependency parse result
        """
        try:
            if toml is None:
                raise DependencyParsingError(
                    manifest_file,
                    "TOML library not available for Pipfile parsing",
                    PackageEcosystem.PIPENV
                )
            
            data = toml.loads(content)
            dependencies = []
            errors = []
            
            # Parse production packages
            packages = data.get("packages", {})
            for name, spec in packages.items():
                try:
                    version_info = PythonDependencyParser._parse_pipfile_spec(spec)
                    dependencies.append(ParsedDependency(
                        name=name,
                        version=version_info['version'],
                        version_constraint=version_info['constraint'],
                        ecosystem=PackageEcosystem.PIPENV,
                        manifest_file=manifest_file,
                        is_dev_dependency=False
                    ))
                except Exception as e:
                    errors.append(f"Failed to parse package {name}: {str(e)}")
            
            # Parse dev packages
            dev_packages = data.get("dev-packages", {})
            for name, spec in dev_packages.items():
                try:
                    version_info = PythonDependencyParser._parse_pipfile_spec(spec)
                    dependencies.append(ParsedDependency(
                        name=name,
                        version=version_info['version'],
                        version_constraint=version_info['constraint'],
                        ecosystem=PackageEcosystem.PIPENV,
                        manifest_file=manifest_file,
                        is_dev_dependency=True
                    ))
                except Exception as e:
                    errors.append(f"Failed to parse dev package {name}: {str(e)}")
            
            # Extract metadata
            metadata = {
                "python_version": data.get("requires", {}).get("python_version"),
                "source": data.get("source", []),
                "scripts": data.get("scripts", {}),
                "pipenv_version": data.get("pipenv", {}).get("version")
            }
            
            prod_count = len([d for d in dependencies if not d.is_dev_dependency])
            dev_count = len([d for d in dependencies if d.is_dev_dependency])
            
            return DependencyParseResult(
                dependencies=dependencies,
                ecosystem=PackageEcosystem.PIPENV,
                manifest_file=manifest_file,
                total_dependencies=len(dependencies),
                dev_dependencies=dev_count,
                production_dependencies=prod_count,
                parsing_errors=errors,
                metadata=metadata
            )
            
        except Exception as e:
            raise DependencyParsingError(
                manifest_file,
                f"Failed to parse Pipfile: {str(e)}",
                PackageEcosystem.PIPENV
            )
    
    @staticmethod
    def parse_poetry_lock(content: str, manifest_file: str = "poetry.lock") -> DependencyParseResult:
        """
        Parse poetry.lock file for exact dependency versions
        
        Args:
            content: File content as string
            manifest_file: Name of the manifest file
            
        Returns:
            Dependency parse result
        """
        try:
            if toml is None:
                raise DependencyParsingError(
                    manifest_file,
                    "TOML library not available for poetry.lock parsing",
                    PackageEcosystem.POETRY
                )
            
            data = toml.loads(content)
            dependencies = []
            errors = []
            
            # Parse package entries
            packages = data.get("package", [])
            for package in packages:
                try:
                    name = package.get("name")
                    version = package.get("version")
                    category = package.get("category", "main")
                    
                    if name and version:
                        dependencies.append(ParsedDependency(
                            name=name,
                            version=version,
                            version_constraint=version,  # Lock file has exact versions
                            ecosystem=PackageEcosystem.POETRY,
                            manifest_file=manifest_file,
                            is_dev_dependency=(category == "dev")
                        ))
                except Exception as e:
                    errors.append(f"Failed to parse package {package}: {str(e)}")
            
            # Extract metadata
            metadata_section = data.get("metadata", {})
            metadata = {
                "lock_version": metadata_section.get("lock-version"),
                "python_versions": metadata_section.get("python-versions"),
                "content_hash": metadata_section.get("content-hash"),
                "total_packages": len(packages)
            }
            
            prod_count = len([d for d in dependencies if not d.is_dev_dependency])
            dev_count = len([d for d in dependencies if d.is_dev_dependency])
            
            return DependencyParseResult(
                dependencies=dependencies,
                ecosystem=PackageEcosystem.POETRY,
                manifest_file=manifest_file,
                total_dependencies=len(dependencies),
                dev_dependencies=dev_count,
                production_dependencies=prod_count,
                parsing_errors=errors,
                metadata=metadata
            )
            
        except Exception as e:
            raise DependencyParsingError(
                manifest_file,
                f"Failed to parse poetry.lock: {str(e)}",
                PackageEcosystem.POETRY
            )
    
    @staticmethod
    def _parse_requirement_line(line: str) -> Optional[Dict[str, str]]:
        """
        Parse a single requirements.txt line
        
        Args:
            line: Requirement line (e.g., "Django>=3.2,<4.0")
            
        Returns:
            Dictionary with name, version, and constraint
        """
        # Handle Git URLs, file paths, and other special cases
        if any(prefix in line for prefix in ['git+', 'http://', 'https://', 'file://', './']):
            # For now, skip VCS and file dependencies
            return None
        
        # Remove inline comments
        if '#' in line:
            line = line.split('#')[0].strip()
        
        # Parse the requirement using regex
        # Pattern matches: package_name[extras]version_spec
        pattern = r'^([a-zA-Z0-9][a-zA-Z0-9._-]*[a-zA-Z0-9]|\b[a-zA-Z0-9]\b)(\[[^\]]*\])?(.*)'
        match = re.match(pattern, line.strip())
        
        if not match:
            return None
        
        name = match.group(1)
        extras = match.group(2) or ""
        version_spec = match.group(3).strip()
        
        # Parse version constraint
        if version_spec:
            # Extract version from constraint
            version = PythonDependencyParser._extract_version_from_constraint(version_spec)
        else:
            version_spec = "*"
            version = "latest"
        
        return {
            'name': name,
            'version': version,
            'constraint': version_spec,
            'extras': extras
        }
    
    @staticmethod
    def _parse_pipfile_spec(spec: Union[str, Dict[str, Any]]) -> Dict[str, str]:
        """
        Parse Pipfile package specification
        
        Args:
            spec: Package specification (string or dict)
            
        Returns:
            Dictionary with version and constraint
        """
        if isinstance(spec, str):
            # Simple version string
            version = PythonDependencyParser._extract_version_from_constraint(spec)
            return {
                'version': version,
                'constraint': spec
            }
        elif isinstance(spec, dict):
            # Complex specification
            version_spec = spec.get('version', '*')
            if version_spec:
                version = PythonDependencyParser._extract_version_from_constraint(version_spec)
                return {
                    'version': version,
                    'constraint': version_spec
                }
            else:
                # VCS or file dependency
                return {
                    'version': 'vcs',
                    'constraint': str(spec)
                }
        
        return {
            'version': 'unknown',
            'constraint': str(spec)
        }
    
    @staticmethod
    def _extract_version_from_constraint(constraint: str) -> str:
        """
        Extract version number from Python version constraint
        
        Args:
            constraint: Version constraint (e.g., ">=3.2,<4.0", "~=1.4.2")
            
        Returns:
            Extracted version
        """
        if not constraint or constraint == "*":
            return "latest"
        
        # Remove whitespace
        constraint = constraint.strip()
        
        # Handle multiple constraints separated by commas
        if ',' in constraint:
            # Take the first constraint
            constraint = constraint.split(',')[0].strip()
        
        # Remove operators and extract version
        version = re.sub(r'^[~!<>=\s]+', '', constraint)
        version = re.sub(r'[<>=\s].*$', '', version)
        
        # Clean up the version
        version = version.strip()
        
        return version if version else "unknown"


class RustDependencyParser:
    """
    Parser for Rust/Cargo ecosystem dependency files
    
    Supports:
    - Cargo.toml (cargo dependencies)
    - Cargo.lock (cargo lockfile)
    """
    
    @staticmethod
    def parse_cargo_toml(content: str, manifest_file: str = "Cargo.toml") -> DependencyParseResult:
        """
        Parse Cargo.toml file for dependencies
        
        Args:
            content: File content as string
            manifest_file: Name of the manifest file
            
        Returns:
            Dependency parse result
        """
        try:
            if toml is None:
                raise DependencyParsingError(
                    manifest_file,
                    "TOML library not available for Cargo.toml parsing",
                    PackageEcosystem.CARGO
                )
            
            data = toml.loads(content)
            dependencies = []
            errors = []
            
            # Parse regular dependencies
            deps = data.get("dependencies", {})
            for name, spec in deps.items():
                try:
                    version_info = RustDependencyParser._parse_cargo_dependency(name, spec)
                    dependencies.append(ParsedDependency(
                        name=name,
                        version=version_info['version'],
                        version_constraint=version_info['constraint'],
                        ecosystem=PackageEcosystem.CARGO,
                        manifest_file=manifest_file,
                        is_dev_dependency=False,
                        is_optional=version_info.get('optional', False)
                    ))
                except Exception as e:
                    errors.append(f"Failed to parse dependency {name}: {str(e)}")
            
            # Parse dev dependencies
            dev_deps = data.get("dev-dependencies", {})
            for name, spec in dev_deps.items():
                try:
                    version_info = RustDependencyParser._parse_cargo_dependency(name, spec)
                    dependencies.append(ParsedDependency(
                        name=name,
                        version=version_info['version'],
                        version_constraint=version_info['constraint'],
                        ecosystem=PackageEcosystem.CARGO,
                        manifest_file=manifest_file,
                        is_dev_dependency=True,
                        is_optional=version_info.get('optional', False)
                    ))
                except Exception as e:
                    errors.append(f"Failed to parse dev dependency {name}: {str(e)}")
            
            # Parse build dependencies
            build_deps = data.get("build-dependencies", {})
            for name, spec in build_deps.items():
                try:
                    version_info = RustDependencyParser._parse_cargo_dependency(name, spec)
                    dependencies.append(ParsedDependency(
                        name=name,
                        version=version_info['version'],
                        version_constraint=version_info['constraint'],
                        ecosystem=PackageEcosystem.CARGO,
                        manifest_file=manifest_file,
                        is_dev_dependency=False,  # Build deps are production
                        scope="build"
                    ))
                except Exception as e:
                    errors.append(f"Failed to parse build dependency {name}: {str(e)}")
            
            # Extract package metadata
            package_info = data.get("package", {})
            metadata = {
                "package_name": package_info.get("name"),
                "package_version": package_info.get("version"),
                "description": package_info.get("description"),
                "license": package_info.get("license"),
                "authors": package_info.get("authors", []),
                "edition": package_info.get("edition"),
                "rust_version": package_info.get("rust-version"),
                "repository": package_info.get("repository"),
                "homepage": package_info.get("homepage"),
                "documentation": package_info.get("documentation"),
                "keywords": package_info.get("keywords", []),
                "categories": package_info.get("categories", []),
                "workspace": data.get("workspace") is not None
            }
            
            prod_count = len([d for d in dependencies if not d.is_dev_dependency])
            dev_count = len([d for d in dependencies if d.is_dev_dependency])
            
            return DependencyParseResult(
                dependencies=dependencies,
                ecosystem=PackageEcosystem.CARGO,
                manifest_file=manifest_file,
                total_dependencies=len(dependencies),
                dev_dependencies=dev_count,
                production_dependencies=prod_count,
                parsing_errors=errors,
                metadata=metadata
            )
            
        except Exception as e:
            raise DependencyParsingError(
                manifest_file,
                f"Failed to parse Cargo.toml: {str(e)}",
                PackageEcosystem.CARGO
            )
    
    @staticmethod
    def parse_cargo_lock(content: str, manifest_file: str = "Cargo.lock") -> DependencyParseResult:
        """
        Parse Cargo.lock file for exact dependency versions
        
        Args:
            content: File content as string
            manifest_file: Name of the manifest file
            
        Returns:
            Dependency parse result
        """
        try:
            if toml is None:
                raise DependencyParsingError(
                    manifest_file,
                    "TOML library not available for Cargo.lock parsing",
                    PackageEcosystem.CARGO
                )
            
            data = toml.loads(content)
            dependencies = []
            errors = []
            
            # Parse package entries from lock file
            packages = data.get("package", [])
            for package in packages:
                try:
                    name = package.get("name")
                    version = package.get("version")
                    source = package.get("source")
                    
                    if name and version:
                        # Determine if it's from crates.io or other source
                        is_external = source is not None and "registry" in str(source)
                        
                        dependencies.append(ParsedDependency(
                            name=name,
                            version=version,
                            version_constraint=version,  # Lock file has exact versions
                            ecosystem=PackageEcosystem.CARGO,
                            manifest_file=manifest_file,
                            is_dev_dependency=False,  # Can't distinguish in lock file
                            is_optional=not is_external  # Local packages might be optional
                        ))
                except Exception as e:
                    errors.append(f"Failed to parse package {package}: {str(e)}")
            
            # Extract metadata
            metadata = {
                "version": data.get("version"),
                "total_packages": len(packages),
                "registry_packages": len([p for p in packages if p.get("source") and "registry" in str(p.get("source"))]),
                "local_packages": len([p for p in packages if not p.get("source")])
            }
            
            return DependencyParseResult(
                dependencies=dependencies,
                ecosystem=PackageEcosystem.CARGO,
                manifest_file=manifest_file,
                total_dependencies=len(dependencies),
                dev_dependencies=0,  # Can't distinguish in lock file
                production_dependencies=len(dependencies),
                parsing_errors=errors,
                metadata=metadata
            )
            
        except Exception as e:
            raise DependencyParsingError(
                manifest_file,
                f"Failed to parse Cargo.lock: {str(e)}",
                PackageEcosystem.CARGO
            )
    
    @staticmethod
    def _parse_cargo_dependency(name: str, spec: Union[str, Dict[str, Any]]) -> Dict[str, Any]:
        """
        Parse Cargo dependency specification
        
        Args:
            name: Package name
            spec: Package specification (string or dict)
            
        Returns:
            Dictionary with version, constraint, and metadata
        """
        if isinstance(spec, str):
            # Simple version string
            version = RustDependencyParser._extract_cargo_version(spec)
            return {
                'version': version,
                'constraint': spec,
                'optional': False
            }
        elif isinstance(spec, dict):
            # Complex specification
            version_spec = spec.get('version', '*')
            version = RustDependencyParser._extract_cargo_version(version_spec)
            
            return {
                'version': version,
                'constraint': version_spec,
                'optional': spec.get('optional', False),
                'features': spec.get('features', []),
                'default_features': spec.get('default-features', True),
                'git': spec.get('git'),
                'branch': spec.get('branch'),
                'tag': spec.get('tag'),
                'rev': spec.get('rev'),
                'path': spec.get('path')
            }
        
        return {
            'version': 'unknown',
            'constraint': str(spec),
            'optional': False
        }
    
    @staticmethod
    def _extract_cargo_version(constraint: str) -> str:
        """
        Extract version number from Cargo version constraint
        
        Args:
            constraint: Version constraint (e.g., "^1.0", "~1.2.3", ">=1.0.0")
            
        Returns:
            Extracted version
        """
        if not constraint or constraint == "*":
            return "latest"
        
        # Remove whitespace
        constraint = constraint.strip()
        
        # Handle Cargo version operators
        # ^ means compatible version (allows newer patch/minor)
        # ~ means tilde requirements (allows newer patch only)
        # >= means greater than or equal
        version = re.sub(r'^[~^>=<\s]+', '', constraint)
        
        # Handle version ranges
        if ',' in version:
            # Take the first version in range
            version = version.split(',')[0].strip()
        
        # Clean up the version
        version = re.sub(r'[<>=\s].*$', '', version)
        version = version.strip()
        
        return version if version else "unknown"


class JavaDependencyParser:
    """
    Parser for Java ecosystem dependency files
    
    Supports:
    - pom.xml (Maven)
    - build.gradle (Gradle)
    - build.gradle.kts (Gradle Kotlin DSL)
    """
    
    @staticmethod
    def parse_pom_xml(content: str, manifest_file: str = "pom.xml") -> DependencyParseResult:
        """
        Parse Maven pom.xml file for dependencies
        
        Args:
            content: File content as string
            manifest_file: Name of the manifest file
            
        Returns:
            Dependency parse result
        """
        try:
            if ET is None:
                raise DependencyParsingError(
                    manifest_file,
                    "XML library not available for pom.xml parsing",
                    PackageEcosystem.MAVEN
                )
            
            # Parse XML content
            root = ET.fromstring(content)
            
            # Define Maven namespace
            namespace = {'maven': 'http://maven.apache.org/POM/4.0.0'}
            
            # Try to get namespace from root element
            if root.tag.startswith('{'):
                ns_end = root.tag.find('}')
                if ns_end > 0:
                    ns_uri = root.tag[1:ns_end]
                    namespace = {'maven': ns_uri}
            
            dependencies = []
            errors = []
            
            # Parse regular dependencies
            deps_section = root.find('.//maven:dependencies', namespace)
            if deps_section is None:
                deps_section = root.find('.//dependencies')  # Try without namespace
            
            if deps_section is not None:
                for dep in deps_section.findall('maven:dependency', namespace):
                    if dep is None:
                        dep = deps_section.findall('dependency')  # Try without namespace
                        if not dep:
                            continue
                        dep = dep[0] if isinstance(dep, list) else dep
                    
                    try:
                        parsed_dep = JavaDependencyParser._parse_maven_dependency(dep, namespace)
                        if parsed_dep:
                            dependencies.append(ParsedDependency(
                                name=f"{parsed_dep['groupId']}:{parsed_dep['artifactId']}",
                                version=parsed_dep['version'],
                                version_constraint=parsed_dep['version'],
                                ecosystem=PackageEcosystem.MAVEN,
                                manifest_file=manifest_file,
                                is_dev_dependency=parsed_dep.get('scope') in ['test', 'provided'],
                                scope=parsed_dep.get('scope', 'compile')
                            ))
                    except Exception as e:
                        errors.append(f"Failed to parse dependency: {str(e)}")
            
            # Extract project metadata
            project_metadata = JavaDependencyParser._extract_maven_metadata(root, namespace)
            
            dev_count = len([d for d in dependencies if d.is_dev_dependency])
            prod_count = len([d for d in dependencies if not d.is_dev_dependency])
            
            return DependencyParseResult(
                dependencies=dependencies,
                ecosystem=PackageEcosystem.MAVEN,
                manifest_file=manifest_file,
                total_dependencies=len(dependencies),
                dev_dependencies=dev_count,
                production_dependencies=prod_count,
                parsing_errors=errors,
                metadata=project_metadata
            )
            
        except ET.ParseError as e:
            raise DependencyParsingError(
                manifest_file,
                f"Failed to parse XML: {str(e)}",
                PackageEcosystem.MAVEN
            )
        except Exception as e:
            raise DependencyParsingError(
                manifest_file,
                f"Failed to parse pom.xml: {str(e)}",
                PackageEcosystem.MAVEN
            )
    
    @staticmethod
    def parse_build_gradle(content: str, manifest_file: str = "build.gradle") -> DependencyParseResult:
        """
        Parse Gradle build.gradle file for dependencies
        
        Args:
            content: File content as string
            manifest_file: Name of the manifest file
            
        Returns:
            Dependency parse result
        """
        try:
            dependencies = []
            errors = []
            
            lines = content.split('\n')
            in_dependencies_block = False
            brace_count = 0
            
            # Simple state machine to parse Gradle dependencies
            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                
                # Skip comments and empty lines
                if not line or line.startswith('//') or line.startswith('/*'):
                    continue
                
                # Track dependencies block
                if 'dependencies' in line and '{' in line:
                    in_dependencies_block = True
                    brace_count = line.count('{') - line.count('}')
                    continue
                elif in_dependencies_block:
                    brace_count += line.count('{') - line.count('}')
                    if brace_count <= 0:
                        in_dependencies_block = False
                        continue
                
                # Parse dependency declarations in dependencies block
                if in_dependencies_block:
                    try:
                        parsed_dep = JavaDependencyParser._parse_gradle_dependency_line(line)
                        if parsed_dep:
                            dependencies.append(ParsedDependency(
                                name=parsed_dep['name'],
                                version=parsed_dep['version'],
                                version_constraint=parsed_dep['version'],
                                ecosystem=PackageEcosystem.GRADLE,
                                manifest_file=manifest_file,
                                is_dev_dependency=parsed_dep['configuration'] in ['testImplementation', 'testCompile', 'androidTestImplementation'],
                                scope=parsed_dep['configuration']
                            ))
                    except Exception as e:
                        errors.append(f"Line {line_num}: Failed to parse '{line}': {str(e)}")
            
            # Extract basic metadata (limited for Gradle)
            metadata = JavaDependencyParser._extract_gradle_metadata(content)
            
            dev_count = len([d for d in dependencies if d.is_dev_dependency])
            prod_count = len([d for d in dependencies if not d.is_dev_dependency])
            
            return DependencyParseResult(
                dependencies=dependencies,
                ecosystem=PackageEcosystem.GRADLE,
                manifest_file=manifest_file,
                total_dependencies=len(dependencies),
                dev_dependencies=dev_count,
                production_dependencies=prod_count,
                parsing_errors=errors,
                metadata=metadata
            )
            
        except Exception as e:
            raise DependencyParsingError(
                manifest_file,
                f"Failed to parse build.gradle: {str(e)}",
                PackageEcosystem.GRADLE
            )
    
    @staticmethod
    def _parse_maven_dependency(dep_element, namespace: Dict[str, str]) -> Optional[Dict[str, str]]:
        """
        Parse a single Maven dependency element
        
        Args:
            dep_element: XML element for dependency
            namespace: XML namespace mapping
            
        Returns:
            Dictionary with dependency information
        """
        try:
            def get_text(element, tag_name):
                """Helper to get text with or without namespace"""
                elem = element.find(f'maven:{tag_name}', namespace)
                if elem is None:
                    elem = element.find(tag_name)
                return elem.text if elem is not None else None
            
            group_id = get_text(dep_element, 'groupId')
            artifact_id = get_text(dep_element, 'artifactId')
            version = get_text(dep_element, 'version')
            scope = get_text(dep_element, 'scope')
            optional = get_text(dep_element, 'optional')
            
            if not group_id or not artifact_id:
                return None
            
            return {
                'groupId': group_id,
                'artifactId': artifact_id,
                'version': version or 'unknown',
                'scope': scope or 'compile',
                'optional': optional == 'true'
            }
            
        except Exception:
            return None
    
    @staticmethod
    def _parse_gradle_dependency_line(line: str) -> Optional[Dict[str, str]]:
        """
        Parse a single Gradle dependency line
        
        Args:
            line: Gradle dependency line
            
        Returns:
            Dictionary with dependency information
        """
        # Common Gradle dependency patterns
        patterns = [
            # implementation 'group:artifact:version'
            r"(\w+)\s+['\"]([^:]+):([^:]+):([^'\"]*)['\"]",
            # implementation group: 'group', name: 'artifact', version: 'version'
            r"(\w+)\s+group:\s*['\"]([^'\"]+)['\"],\s*name:\s*['\"]([^'\"]+)['\"],\s*version:\s*['\"]([^'\"]+)['\"]",
            # implementation('group:artifact:version')
            r"(\w+)\(['\"]([^:]+):([^:]+):([^'\"]*)['\"]\)",
            # implementation 'group:artifact' (no version)
            r"(\w+)\s+['\"]([^:]+):([^:]+)['\"]",
        ]
        
        for pattern in patterns:
            match = re.search(pattern, line)
            if match:
                groups = match.groups()
                if len(groups) == 4:
                    config, group, artifact, version = groups
                    return {
                        'name': f"{group}:{artifact}",
                        'version': version if version else 'unknown',
                        'configuration': config,
                        'group': group,
                        'artifact': artifact
                    }
                elif len(groups) == 3:
                    # No version specified (e.g., Spring Boot managed dependencies)
                    config, group, artifact = groups
                    return {
                        'name': f"{group}:{artifact}",
                        'version': 'managed',
                        'configuration': config,
                        'group': group,
                        'artifact': artifact
                    }
        
        return None
    
    @staticmethod
    def _extract_maven_metadata(root, namespace: Dict[str, str]) -> Dict[str, Any]:
        """Extract metadata from Maven pom.xml"""
        def get_text(tag_name):
            elem = root.find(f'maven:{tag_name}', namespace)
            if elem is None:
                elem = root.find(tag_name)
            return elem.text if elem is not None else None
        
        return {
            'groupId': get_text('groupId'),
            'artifactId': get_text('artifactId'),
            'version': get_text('version'),
            'name': get_text('name'),
            'description': get_text('description'),
            'packaging': get_text('packaging'),
            'java_version': None,  # Could be extracted from properties
            'maven_version': None,  # Could be extracted from model version
        }
    
    @staticmethod
    def _extract_gradle_metadata(content: str) -> Dict[str, Any]:
        """Extract metadata from Gradle build file"""
        metadata = {
            'project_name': None,
            'version': None,
            'group': None,
            'java_version': None,
            'gradle_version': None,
            'plugins': []
        }
        
        lines = content.split('\n')
        for line in lines:
            line = line.strip()
            
            # Extract version
            version_match = re.search(r"version\s*=\s*['\"]([^'\"]+)['\"]", line)
            if version_match:
                metadata['version'] = version_match.group(1)
            
            # Extract group
            group_match = re.search(r"group\s*=\s*['\"]([^'\"]+)['\"]", line)
            if group_match:
                metadata['group'] = group_match.group(1)
            
            # Extract Java version
            java_match = re.search(r"sourceCompatibility\s*=\s*['\"]?([^'\"]+)['\"]?", line)
            if java_match:
                metadata['java_version'] = java_match.group(1)
            
            # Extract plugins
            plugin_match = re.search(r"id\s+['\"]([^'\"]+)['\"]", line)
            if plugin_match:
                metadata['plugins'].append(plugin_match.group(1))
        
        return metadata


class NodeJSDependencyParser:
    """
    Parser for Node.js/npm ecosystem dependency files
    
    Supports:
    - package.json (npm/yarn)
    - package-lock.json (npm)
    - yarn.lock (yarn)
    """
    
    @staticmethod
    def parse_package_json(content: str, manifest_file: str = "package.json") -> DependencyParseResult:
        """
        Parse package.json file for dependencies
        
        Args:
            content: File content as string
            manifest_file: Name of the manifest file
            
        Returns:
            Dependency parse result
        """
        try:
            data = json.loads(content)
            dependencies = []
            errors = []
            
            # Parse production dependencies
            prod_deps = data.get("dependencies", {})
            for name, version in prod_deps.items():
                try:
                    parsed_version = NodeJSDependencyParser._parse_npm_version(version)
                    dependencies.append(ParsedDependency(
                        name=name,
                        version=parsed_version,
                        version_constraint=version,
                        ecosystem=PackageEcosystem.NPM,
                        manifest_file=manifest_file,
                        is_dev_dependency=False
                    ))
                except Exception as e:
                    errors.append(f"Failed to parse dependency {name}@{version}: {str(e)}")
            
            # Parse development dependencies
            dev_deps = data.get("devDependencies", {})
            for name, version in dev_deps.items():
                try:
                    parsed_version = NodeJSDependencyParser._parse_npm_version(version)
                    dependencies.append(ParsedDependency(
                        name=name,
                        version=parsed_version,
                        version_constraint=version,
                        ecosystem=PackageEcosystem.NPM,
                        manifest_file=manifest_file,
                        is_dev_dependency=True
                    ))
                except Exception as e:
                    errors.append(f"Failed to parse dev dependency {name}@{version}: {str(e)}")
            
            # Parse optional dependencies
            optional_deps = data.get("optionalDependencies", {})
            for name, version in optional_deps.items():
                try:
                    parsed_version = NodeJSDependencyParser._parse_npm_version(version)
                    dependencies.append(ParsedDependency(
                        name=name,
                        version=parsed_version,
                        version_constraint=version,
                        ecosystem=PackageEcosystem.NPM,
                        manifest_file=manifest_file,
                        is_dev_dependency=False,
                        is_optional=True
                    ))
                except Exception as e:
                    errors.append(f"Failed to parse optional dependency {name}@{version}: {str(e)}")
            
            # Parse peer dependencies (treated as production dependencies)
            peer_deps = data.get("peerDependencies", {})
            for name, version in peer_deps.items():
                try:
                    parsed_version = NodeJSDependencyParser._parse_npm_version(version)
                    dependencies.append(ParsedDependency(
                        name=name,
                        version=parsed_version,
                        version_constraint=version,
                        ecosystem=PackageEcosystem.NPM,
                        manifest_file=manifest_file,
                        is_dev_dependency=False,
                        scope="peer"
                    ))
                except Exception as e:
                    errors.append(f"Failed to parse peer dependency {name}@{version}: {str(e)}")
            
            # Extract metadata
            metadata = {
                "package_name": data.get("name"),
                "package_version": data.get("version"),
                "description": data.get("description"),
                "license": data.get("license"),
                "engines": data.get("engines", {}),
                "scripts": list(data.get("scripts", {}).keys()),
                "keywords": data.get("keywords", []),
                "repository": data.get("repository"),
                "homepage": data.get("homepage"),
                "bugs": data.get("bugs")
            }
            
            prod_count = len([d for d in dependencies if not d.is_dev_dependency and not d.is_optional])
            dev_count = len([d for d in dependencies if d.is_dev_dependency])
            
            return DependencyParseResult(
                dependencies=dependencies,
                ecosystem=PackageEcosystem.NPM,
                manifest_file=manifest_file,
                total_dependencies=len(dependencies),
                dev_dependencies=dev_count,
                production_dependencies=prod_count,
                parsing_errors=errors,
                metadata=metadata
            )
            
        except json.JSONDecodeError as e:
            raise DependencyParsingError(
                manifest_file, 
                f"Invalid JSON: {str(e)}", 
                PackageEcosystem.NPM
            )
        except Exception as e:
            raise DependencyParsingError(
                manifest_file, 
                f"Failed to parse package.json: {str(e)}", 
                PackageEcosystem.NPM
            )
    
    @staticmethod
    def parse_package_lock_json(content: str, manifest_file: str = "package-lock.json") -> DependencyParseResult:
        """
        Parse package-lock.json file for exact dependency versions
        
        Args:
            content: File content as string
            manifest_file: Name of the manifest file
            
        Returns:
            Dependency parse result
        """
        try:
            data = json.loads(content)
            dependencies = []
            errors = []
            
            # Parse locked dependencies from the dependencies object
            deps = data.get("dependencies", {})
            
            def extract_dependencies(deps_dict: Dict[str, Any], is_dev: bool = False):
                for name, info in deps_dict.items():
                    try:
                        version = info.get("version", "unknown")
                        dependencies.append(ParsedDependency(
                            name=name,
                            version=version,
                            version_constraint=version,  # Lock files have exact versions
                            ecosystem=PackageEcosystem.NPM,
                            manifest_file=manifest_file,
                            is_dev_dependency=is_dev
                        ))
                        
                        # Recursively parse nested dependencies
                        if "dependencies" in info:
                            extract_dependencies(info["dependencies"], is_dev)
                            
                    except Exception as e:
                        errors.append(f"Failed to parse locked dependency {name}: {str(e)}")
            
            extract_dependencies(deps)
            
            # Extract metadata
            metadata = {
                "package_name": data.get("name"),
                "package_version": data.get("version"),
                "lockfile_version": data.get("lockfileVersion"),
                "requires": data.get("requires", True),
                "total_locked_packages": len(deps)
            }
            
            return DependencyParseResult(
                dependencies=dependencies,
                ecosystem=PackageEcosystem.NPM,
                manifest_file=manifest_file,
                total_dependencies=len(dependencies),
                dev_dependencies=0,  # Lock file doesn't distinguish dev deps easily
                production_dependencies=len(dependencies),
                parsing_errors=errors,
                metadata=metadata
            )
            
        except json.JSONDecodeError as e:
            raise DependencyParsingError(
                manifest_file,
                f"Invalid JSON: {str(e)}",
                PackageEcosystem.NPM
            )
        except Exception as e:
            raise DependencyParsingError(
                manifest_file,
                f"Failed to parse package-lock.json: {str(e)}",
                PackageEcosystem.NPM
            )
    
    @staticmethod
    def parse_yarn_lock(content: str, manifest_file: str = "yarn.lock") -> DependencyParseResult:
        """
        Parse yarn.lock file for exact dependency versions
        
        Args:
            content: File content as string
            manifest_file: Name of the manifest file
            
        Returns:
            Dependency parse result
        """
        try:
            dependencies = []
            errors = []
            
            # Yarn lock file has a specific format that's not JSON
            # Parse using regex patterns
            
            # Pattern to match dependency entries
            dep_pattern = r'^"?([^@\s]+)@([^"]+)"?:\s*$'
            version_pattern = r'^\s+version\s+"([^"]+)"'
            
            lines = content.split('\n')
            current_dep = None
            
            for line in lines:
                # Try to match dependency declaration
                dep_match = re.match(dep_pattern, line)
                if dep_match:
                    current_dep = {
                        'name': dep_match.group(1),
                        'constraint': dep_match.group(2),
                        'version': None
                    }
                    continue
                
                # Try to match version
                if current_dep:
                    version_match = re.match(version_pattern, line)
                    if version_match:
                        current_dep['version'] = version_match.group(1)
                        
                        try:
                            dependencies.append(ParsedDependency(
                                name=current_dep['name'],
                                version=current_dep['version'],
                                version_constraint=current_dep['constraint'],
                                ecosystem=PackageEcosystem.YARN,
                                manifest_file=manifest_file,
                                is_dev_dependency=False  # Yarn lock doesn't distinguish
                            ))
                        except Exception as e:
                            errors.append(f"Failed to parse yarn dependency {current_dep['name']}: {str(e)}")
                        
                        current_dep = None
            
            # Extract metadata (limited for yarn.lock)
            metadata = {
                "lockfile_type": "yarn",
                "total_locked_packages": len(dependencies)
            }
            
            return DependencyParseResult(
                dependencies=dependencies,
                ecosystem=PackageEcosystem.YARN,
                manifest_file=manifest_file,
                total_dependencies=len(dependencies),
                dev_dependencies=0,  # Can't distinguish in lock file
                production_dependencies=len(dependencies),
                parsing_errors=errors,
                metadata=metadata
            )
            
        except Exception as e:
            raise DependencyParsingError(
                manifest_file,
                f"Failed to parse yarn.lock: {str(e)}",
                PackageEcosystem.YARN
            )
    
    @staticmethod
    def _parse_npm_version(version_constraint: str) -> str:
        """
        Parse npm version constraint to extract base version
        
        Args:
            version_constraint: Version constraint string (e.g., "^1.2.3", "~2.0.0")
            
        Returns:
            Base version string
        """
        # Remove common npm version prefixes and suffixes
        version = version_constraint.strip()
        
        # Remove semver operators
        version = re.sub(r'^[~^>=<]+', '', version)
        
        # Handle version ranges (take the first version)
        if ' - ' in version:
            version = version.split(' - ')[0]
        elif ' || ' in version:
            version = version.split(' || ')[0]
        elif ' ' in version:
            version = version.split(' ')[0]
        
        # Remove any remaining non-version characters
        version = re.sub(r'[^0-9.]', '', version)
        
        return version if version else "unknown"


class DependencyParser:
    """
    Main dependency parser that coordinates parsing across different ecosystems with smart file discovery
    """
    
    # Priority mapping for dependency files (higher number = higher priority)
    FILE_PRIORITIES = {
        # Lock files have highest priority (exact versions)
        "package-lock.json": 100,
        "yarn.lock": 95,
        "Cargo.lock": 90,
        "poetry.lock": 85,
        
        # Main manifest files
        "package.json": 80,
        "Cargo.toml": 75,
        "pom.xml": 70,
        "requirements.txt": 65,
        "Pipfile": 60,
        "build.gradle": 55,
        "build.gradle.kts": 54,
        
        # Other formats
        "composer.json": 50,
        "Gemfile": 45,
        "go.mod": 40,
    }
    
    # File patterns that indicate workspace/monorepo structures
    WORKSPACE_INDICATORS = {
        "lerna.json": "npm_workspace",
        "nx.json": "nx_workspace", 
        "rush.json": "rush_workspace",
        "yarn.workspaces": "yarn_workspace",
        "Cargo.toml": "cargo_workspace",  # Check for [workspace] section
        "pom.xml": "maven_multimodule",   # Check for <modules> section
        "build.gradle": "gradle_multiproject",  # Check for subprojects
        ".github/workflows": "github_actions"
    }
    
    # Maximum directory depth for recursive search (optimized for rate limits)
    MAX_SEARCH_DEPTH = 3
    
    # Maximum API calls per repository analysis
    MAX_API_CALLS_PER_REPO = 50
    
    # Smart discovery mode configurations
    DISCOVERY_MODES = {
        "fast": {"max_depth": 2, "max_calls": 20},      # Quick scan for most common patterns
        "balanced": {"max_depth": 3, "max_calls": 50},   # Default balanced approach  
        "thorough": {"max_depth": 5, "max_calls": 100},  # Deep scan for complex monorepos
    }
    
    # Directories to skip during search
    SKIP_DIRECTORIES = {
        ".git", ".svn", ".hg",  # VCS directories
        "node_modules", ".venv", "venv", "__pycache__",  # Package/build directories
        "target", "build", "dist", "out",  # Build output directories
        ".idea", ".vscode", ".vs",  # IDE directories
        "coverage", ".coverage", ".nyc_output",  # Coverage directories
        "logs", "log", "tmp", "temp"  # Temporary directories
    }
    
    def __init__(self, github_client: Optional[GitHubAPIClient] = None):
        """
        Initialize dependency parser
        
        Args:
            github_client: Optional GitHub client for file access
        """
        self.github_client = github_client
    
    async def discover_dependency_files(
        self, 
        owner: str, 
        repo: str,
        max_depth: Optional[int] = None,
        discovery_mode: str = "balanced"
    ) -> List[Dict[str, Any]]:
        """
        Recursively discover dependency files across repository structure
        
        Args:
            owner: Repository owner
            repo: Repository name  
            max_depth: Maximum search depth (uses class default if None)
            
        Returns:
            List of discovered dependency files with metadata
        """
        if self.github_client is None:
            from .github_client import get_github_client
            self.github_client = await get_github_client()
        
        # Configure discovery based on mode
        if discovery_mode in self.DISCOVERY_MODES:
            config = self.DISCOVERY_MODES[discovery_mode]
            max_depth = max_depth or config["max_depth"]
            max_calls = config["max_calls"]
        else:
            max_depth = max_depth or self.MAX_SEARCH_DEPTH
            max_calls = self.MAX_API_CALLS_PER_REPO
        
        discovered_files = []
        workspace_info = {}
        api_call_count = {"count": 0}  # Mutable counter
        
        logger.info(f"Starting {discovery_mode} dependency discovery for {owner}/{repo} (max_depth: {max_depth}, max_calls: {max_calls})")
        
        # Try optimized discovery first
        success = await self._discover_with_optimization(
            owner, repo, max_depth, max_calls, discovered_files, workspace_info, api_call_count
        )
        
        if not success:
            logger.warning(f"Optimized discovery incomplete due to rate limits. Found {len(discovered_files)} files.")
            # Fall back to root-only discovery if we hit limits
            if len(discovered_files) == 0:
                await self._discover_root_only(owner, repo, discovered_files, api_call_count)
        
        # Prioritize and deduplicate files
        prioritized_files = self._prioritize_dependency_files(discovered_files)
        
        # Detect workspace/monorepo structures
        workspace_type = self._detect_workspace_structure(discovered_files, workspace_info)
        
        logger.info(f"Discovered {len(prioritized_files)} dependency files (workspace: {workspace_type})")
        
        return prioritized_files
    
    async def _discover_with_optimization(
        self,
        owner: str,
        repo: str,
        max_depth: int,
        max_calls: int,
        discovered_files: List[Dict[str, Any]],
        workspace_info: Dict[str, Any],
        api_call_count: Dict[str, int]
    ) -> bool:
        """
        Optimized discovery that respects API call limits
        
        Returns:
            True if discovery completed, False if stopped due to limits
        """
        try:
            # Start with common paths first (most likely to contain dependencies)
            priority_paths = [
                "",  # Root directory
                "packages",  # Common monorepo structure
                "apps", 
                "services",
                "libs",
                "modules",
                "src",
                "frontend",
                "backend",
                "api",
                "web",
                "client",
                "server"
            ]
            
            # Try priority paths first
            for path in priority_paths:
                if api_call_count["count"] >= max_calls:
                    logger.warning(f"Reached API call limit ({max_calls}), stopping discovery")
                    return False
                
                depth = 0 if path == "" else 1
                
                try:
                    await self._discover_files_recursive(
                        owner, repo, path, depth, max_depth, 
                        discovered_files, workspace_info, max_calls, api_call_count
                    )
                except Exception as e:
                    logger.debug(f"Path {path} not found or accessible: {str(e)}")
                    continue
            
            # If we found files in priority paths, we're likely done
            if len(discovered_files) > 0:
                logger.info(f"Found {len(discovered_files)} files using optimized discovery")
                return True
            
            # Otherwise, fall back to full recursive discovery
            await self._discover_files_recursive(
                owner, repo, "", 0, max_depth, 
                discovered_files, workspace_info, max_calls, api_call_count
            )
            
            return True
            
        except Exception as e:
            # Re-raise repository access errors to stop discovery immediately
            from ..utils.exceptions import (
                RepositoryNotFoundError, RepositoryPrivateError, 
                RepositoryAccessDeniedError, InvalidRepositoryURLError
            )
            if isinstance(e, (
                RepositoryNotFoundError, RepositoryPrivateError, 
                RepositoryAccessDeniedError, InvalidRepositoryURLError
            )):
                raise
                
            logger.error(f"Optimized discovery failed: {str(e)}")
            return False
    
    async def _discover_root_only(
        self,
        owner: str,
        repo: str,
        discovered_files: List[Dict[str, Any]],
        api_call_count: Dict[str, int]
    ) -> None:
        """
        Fallback to root-only discovery when rate limited
        """
        try:
            files = await self.github_client.get_repository_files(owner, repo, "")
            api_call_count["count"] += 1
            
            if isinstance(files, list):
                for file_info in files:
                    file_name = file_info.get("name", "")
                    if file_name in self.FILE_PRIORITIES:
                        discovered_files.append({
                            "name": file_name,
                            "path": file_name,
                            "priority": self.FILE_PRIORITIES[file_name],
                            "depth": 0,
                            "size": file_info.get("size", 0),
                            "download_url": file_info.get("download_url")
                        })
                        logger.debug(f"Found root dependency file: {file_name}")
                        
        except Exception as e:
            # Re-raise repository access errors to stop discovery immediately
            from ..utils.exceptions import (
                RepositoryNotFoundError, RepositoryPrivateError, 
                RepositoryAccessDeniedError, InvalidRepositoryURLError
            )
            if isinstance(e, (
                RepositoryNotFoundError, RepositoryPrivateError, 
                RepositoryAccessDeniedError, InvalidRepositoryURLError
            )):
                raise
                
            logger.error(f"Root-only discovery failed: {str(e)}")
    
    async def _discover_files_recursive(
        self,
        owner: str,
        repo: str, 
        path: str,
        depth: int,
        max_depth: int,
        discovered_files: List[Dict[str, Any]],
        workspace_info: Dict[str, Any],
        max_calls: int,
        api_call_count: Dict[str, int]
    ) -> None:
        """
        Recursively discover dependency files in repository
        """
        if depth > max_depth or api_call_count["count"] >= max_calls:
            return
        
        try:
            # Get directory contents
            files = await self.github_client.get_repository_files(owner, repo, path)
            api_call_count["count"] += 1
            
            if not isinstance(files, list):
                return
            
            for file_info in files:
                file_name = file_info.get("name", "")
                file_path = file_info.get("path", "")
                file_type = file_info.get("type", "")
                
                if file_type == "file":
                    # Check if it's a dependency file we care about
                    if file_name in self.FILE_PRIORITIES:
                        discovered_files.append({
                            "name": file_name,
                            "path": file_path,
                            "priority": self.FILE_PRIORITIES[file_name],
                            "depth": depth,
                            "size": file_info.get("size", 0),
                            "download_url": file_info.get("download_url")
                        })
                        logger.debug(f"Found dependency file: {file_path}")
                    
                    # Check for workspace indicators
                    if file_name in self.WORKSPACE_INDICATORS:
                        workspace_info[file_path] = self.WORKSPACE_INDICATORS[file_name]
                
                elif file_type == "dir":
                    # Skip certain directories and check call limits
                    if file_name not in self.SKIP_DIRECTORIES and api_call_count["count"] < max_calls:
                        await self._discover_files_recursive(
                            owner, repo, file_path, depth + 1, max_depth, 
                            discovered_files, workspace_info, max_calls, api_call_count
                        )
                    else:
                        logger.debug(f"Skipping directory: {file_path}")
        
        except Exception as e:
            # Re-raise repository access errors to stop discovery immediately
            from ..utils.exceptions import (
                RepositoryNotFoundError, RepositoryPrivateError, 
                RepositoryAccessDeniedError, InvalidRepositoryURLError
            )
            if isinstance(e, (
                RepositoryNotFoundError, RepositoryPrivateError, 
                RepositoryAccessDeniedError, InvalidRepositoryURLError
            )):
                raise
                
            logger.warning(f"Error discovering files in {path}: {str(e)}")
    
    def _prioritize_dependency_files(self, discovered_files: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Prioritize discovered dependency files based on priority and location
        """
        # Group files by directory to detect conflicts
        by_directory = {}
        for file_info in discovered_files:
            dir_path = "/".join(file_info["path"].split("/")[:-1])
            if dir_path not in by_directory:
                by_directory[dir_path] = []
            by_directory[dir_path].append(file_info)
        
        prioritized = []
        
        for dir_path, files in by_directory.items():
            # Sort by priority (highest first), then by depth (shallowest first)
            files.sort(key=lambda f: (-f["priority"], f["depth"]))
            
            # Handle conflicts in same directory (e.g., package.json vs package-lock.json)
            selected_files = []
            seen_ecosystems = set()
            
            for file_info in files:
                ecosystem = self._get_file_ecosystem(file_info["name"])
                
                # For lock files, always include them
                if file_info["priority"] >= 85:  # Lock files
                    selected_files.append(file_info)
                # For manifest files, only include if we haven't seen this ecosystem
                elif ecosystem not in seen_ecosystems:
                    selected_files.append(file_info)
                    seen_ecosystems.add(ecosystem)
            
            prioritized.extend(selected_files)
        
        # Final sort by priority and depth
        prioritized.sort(key=lambda f: (-f["priority"], f["depth"]))
        
        return prioritized
    
    def _get_file_ecosystem(self, filename: str) -> str:
        """Get ecosystem for a dependency file"""
        ecosystem_map = {
            "package.json": "nodejs",
            "package-lock.json": "nodejs", 
            "yarn.lock": "nodejs",
            "requirements.txt": "python",
            "Pipfile": "python",
            "poetry.lock": "python",
            "Cargo.toml": "rust",
            "Cargo.lock": "rust",
            "pom.xml": "java",
            "build.gradle": "java",
            "build.gradle.kts": "java",
            "go.mod": "go",
            "composer.json": "php",
            "Gemfile": "ruby"
        }
        return ecosystem_map.get(filename, "unknown")
    
    def _detect_workspace_structure(
        self, 
        discovered_files: List[Dict[str, Any]], 
        workspace_info: Dict[str, Any]
    ) -> str:
        """
        Detect workspace/monorepo structure from discovered files
        """
        # Count dependency files by depth
        depth_counts = {}
        for file_info in discovered_files:
            depth = file_info["depth"]
            depth_counts[depth] = depth_counts.get(depth, 0) + 1
        
        # If most files are at depth > 0, likely a monorepo
        deep_files = sum(count for depth, count in depth_counts.items() if depth > 0)
        total_files = sum(depth_counts.values())
        
        if workspace_info:
            # Explicit workspace indicators found
            workspace_types = list(workspace_info.values())
            return workspace_types[0] if workspace_types else "unknown"
        elif deep_files > total_files * 0.6:
            # More than 60% of files are in subdirectories
            return "monorepo"
        elif len(depth_counts) > 2:
            # Files spread across multiple depths
            return "multi_level"
        else:
            return "single_project"
    
    async def parse_repository_dependencies(
        self, 
        owner: str, 
        repo: str,
        use_smart_discovery: bool = True
    ) -> List[DependencyParseResult]:
        """
        Parse all dependency files found in a repository using smart discovery
        
        Args:
            owner: Repository owner
            repo: Repository name
            use_smart_discovery: Use smart recursive file discovery (default: True)
            
        Returns:
            List of dependency parse results for all found manifest files
        """
        results = []
        
        try:
            if not self.github_client:
                from .github_client import get_github_client
                self.github_client = await get_github_client()
            
            # Define dependency file patterns and their parsers
            dependency_files = {
                "package.json": (PackageEcosystem.NPM, self._parse_package_json),
                "package-lock.json": (PackageEcosystem.NPM, self._parse_package_lock_json),
                "yarn.lock": (PackageEcosystem.YARN, self._parse_yarn_lock),
                "requirements.txt": (PackageEcosystem.PIP, self._parse_requirements_txt),
                "Pipfile": (PackageEcosystem.PIPENV, self._parse_pipfile),
                "poetry.lock": (PackageEcosystem.POETRY, self._parse_poetry_lock),
                "Cargo.toml": (PackageEcosystem.CARGO, self._parse_cargo_toml),
                "Cargo.lock": (PackageEcosystem.CARGO, self._parse_cargo_lock),
                "pom.xml": (PackageEcosystem.MAVEN, self._parse_pom_xml),
                "build.gradle": (PackageEcosystem.GRADLE, self._parse_build_gradle),
                "build.gradle.kts": (PackageEcosystem.GRADLE, self._parse_build_gradle),
            }
            
            # Get dependency files using smart discovery or basic search
            try:
                if use_smart_discovery:
                    discovered_files = await self.discover_dependency_files(owner, repo)
                    files = discovered_files
                else:
                    # Fallback to root directory search only
                    root_files = await self.github_client.get_repository_files(owner, repo)
                    files = [{"name": f.get("name", ""), "path": f.get("path", f.get("name", ""))} 
                            for f in root_files if f.get("name") in dependency_files]
            except Exception as discovery_error:
                # Re-raise repository access errors as-is for proper handling
                from ..utils.exceptions import (
                    RepositoryNotFoundError, RepositoryPrivateError, 
                    RepositoryAccessDeniedError, InvalidRepositoryURLError
                )
                if isinstance(discovery_error, (
                    RepositoryNotFoundError, RepositoryPrivateError, 
                    RepositoryAccessDeniedError, InvalidRepositoryURLError
                )):
                    raise
                
                # For other errors, wrap in analysis error
                logger.error(f"Failed to discover dependency files for {owner}/{repo}: {str(discovery_error)}")
                raise AnalysisError(
                    f"Failed to discover dependency files in repository",
                    job_id=f"{owner}/{repo}",
                    stage="file_discovery",
                    original_error=discovery_error
                )
            
            # Parse each found dependency file
            for file_info in files:
                file_name = file_info.get("name", "")
                file_path = file_info.get("path", file_name)
                
                if file_name in dependency_files:
                    ecosystem, parser_func = dependency_files[file_name]
                    
                    try:
                        logger.info(f"Parsing {file_path} from {owner}/{repo}")
                        
                        # Get file content
                        content = await self.github_client.get_file_content(owner, repo, file_path)
                        
                        # Parse the file with full path context
                        parse_result = await parser_func(content, file_path)
                        results.append(parse_result)
                        
                        logger.info(f"Successfully parsed {file_name}: {parse_result.total_dependencies} dependencies")
                        
                    except Exception as e:
                        logger.error(f"Failed to parse {file_name} from {owner}/{repo}: {str(e)}")
                        # Create error result
                        error_result = DependencyParseResult(
                            dependencies=[],
                            ecosystem=ecosystem,
                            manifest_file=file_name,
                            total_dependencies=0,
                            dev_dependencies=0,
                            production_dependencies=0,
                            parsing_errors=[str(e)],
                            metadata={"error": str(e)}
                        )
                        results.append(error_result)
            
            if not results:
                logger.info(f"No dependency files found in {owner}/{repo}")
            
            return results
            
        except Exception as e:
            # Re-raise repository access errors as-is for proper handling
            from ..utils.exceptions import (
                RepositoryNotFoundError, RepositoryPrivateError, 
                RepositoryAccessDeniedError, InvalidRepositoryURLError
            )
            if isinstance(e, (
                RepositoryNotFoundError, RepositoryPrivateError, 
                RepositoryAccessDeniedError, InvalidRepositoryURLError
            )):
                raise
                
            logger.error(f"Failed to parse repository dependencies for {owner}/{repo}: {str(e)}")
            raise DependencyParsingError(
                "repository",
                f"Failed to access repository files: {str(e)}",
                "unknown"
            )
    
    async def _parse_package_json(self, content: str, manifest_file: str) -> DependencyParseResult:
        """Parse package.json content"""
        return NodeJSDependencyParser.parse_package_json(content, manifest_file)
    
    async def _parse_package_lock_json(self, content: str, manifest_file: str) -> DependencyParseResult:
        """Parse package-lock.json content"""
        return NodeJSDependencyParser.parse_package_lock_json(content, manifest_file)
    
    async def _parse_yarn_lock(self, content: str, manifest_file: str) -> DependencyParseResult:
        """Parse yarn.lock content"""
        return NodeJSDependencyParser.parse_yarn_lock(content, manifest_file)
    
    async def _parse_requirements_txt(self, content: str, manifest_file: str) -> DependencyParseResult:
        """Parse requirements.txt content"""
        return PythonDependencyParser.parse_requirements_txt(content, manifest_file)
    
    async def _parse_pipfile(self, content: str, manifest_file: str) -> DependencyParseResult:
        """Parse Pipfile content"""
        return PythonDependencyParser.parse_pipfile(content, manifest_file)
    
    async def _parse_poetry_lock(self, content: str, manifest_file: str) -> DependencyParseResult:
        """Parse poetry.lock content"""
        return PythonDependencyParser.parse_poetry_lock(content, manifest_file)
    
    async def _parse_cargo_toml(self, content: str, manifest_file: str) -> DependencyParseResult:
        """Parse Cargo.toml content"""
        return RustDependencyParser.parse_cargo_toml(content, manifest_file)
    
    async def _parse_cargo_lock(self, content: str, manifest_file: str) -> DependencyParseResult:
        """Parse Cargo.lock content"""
        return RustDependencyParser.parse_cargo_lock(content, manifest_file)
    
    async def _parse_pom_xml(self, content: str, manifest_file: str) -> DependencyParseResult:
        """Parse pom.xml content"""
        return JavaDependencyParser.parse_pom_xml(content, manifest_file)
    
    async def _parse_build_gradle(self, content: str, manifest_file: str) -> DependencyParseResult:
        """Parse build.gradle content"""
        return JavaDependencyParser.parse_build_gradle(content, manifest_file)
    
    def convert_to_dependency_info(self, parsed_deps: List[ParsedDependency]) -> List[DependencyInfo]:
        """
        Convert parsed dependencies to DependencyInfo models
        
        Args:
            parsed_deps: List of parsed dependencies
            
        Returns:
            List of DependencyInfo models
        """
        dependency_infos = []
        
        for dep in parsed_deps:
            dependency_infos.append(DependencyInfo(
                name=dep.name,
                version=dep.version,
                ecosystem=dep.ecosystem.value,
                manifest_file=dep.manifest_file
            ))
        
        return dependency_infos


# Utility functions for external use
async def parse_package_json_content(content: str) -> DependencyParseResult:
    """
    Parse package.json content directly
    
    Args:
        content: package.json content as string
        
    Returns:
        Dependency parse result
    """
    return NodeJSDependencyParser.parse_package_json(content)


async def parse_requirements_txt_content(content: str) -> DependencyParseResult:
    """
    Parse requirements.txt content directly
    
    Args:
        content: requirements.txt content as string
        
    Returns:
        Dependency parse result
    """
    return PythonDependencyParser.parse_requirements_txt(content)


async def parse_pipfile_content(content: str) -> DependencyParseResult:
    """
    Parse Pipfile content directly
    
    Args:
        content: Pipfile content as string
        
    Returns:
        Dependency parse result
    """
    return PythonDependencyParser.parse_pipfile(content)


async def parse_cargo_toml_content(content: str) -> DependencyParseResult:
    """
    Parse Cargo.toml content directly
    
    Args:
        content: Cargo.toml content as string
        
    Returns:
        Dependency parse result
    """
    return RustDependencyParser.parse_cargo_toml(content)


async def parse_pom_xml_content(content: str) -> DependencyParseResult:
    """
    Parse pom.xml content directly
    
    Args:
        content: pom.xml content as string
        
    Returns:
        Dependency parse result
    """
    return JavaDependencyParser.parse_pom_xml(content)


async def parse_build_gradle_content(content: str) -> DependencyParseResult:
    """
    Parse build.gradle content directly
    
    Args:
        content: build.gradle content as string
        
    Returns:
        Dependency parse result
    """
    return JavaDependencyParser.parse_build_gradle(content)


async def get_repository_java_dependencies(
    owner: str, 
    repo: str, 
    github_client: Optional[GitHubAPIClient] = None
) -> List[DependencyInfo]:
    """
    Get Java dependencies from a repository
    
    Args:
        owner: Repository owner
        repo: Repository name
        github_client: Optional GitHub client
        
    Returns:
        List of Java dependencies
    """
    parser = DependencyParser(github_client)
    parse_results = await parser.parse_repository_dependencies(owner, repo)
    
    # Filter for Java ecosystems
    java_results = [
        result for result in parse_results 
        if result.ecosystem in [PackageEcosystem.MAVEN, PackageEcosystem.GRADLE]
    ]
    
    # Convert to DependencyInfo
    all_dependencies = []
    for result in java_results:
        all_dependencies.extend(parser.convert_to_dependency_info(result.dependencies))
    
    return all_dependencies


async def get_repository_rust_dependencies(
    owner: str, 
    repo: str, 
    github_client: Optional[GitHubAPIClient] = None
) -> List[DependencyInfo]:
    """
    Get Rust dependencies from a repository
    
    Args:
        owner: Repository owner
        repo: Repository name
        github_client: Optional GitHub client
        
    Returns:
        List of Rust dependencies
    """
    parser = DependencyParser(github_client)
    parse_results = await parser.parse_repository_dependencies(owner, repo)
    
    # Filter for Rust/Cargo ecosystems
    rust_results = [
        result for result in parse_results 
        if result.ecosystem == PackageEcosystem.CARGO
    ]
    
    # Convert to DependencyInfo
    all_dependencies = []
    for result in rust_results:
        all_dependencies.extend(parser.convert_to_dependency_info(result.dependencies))
    
    return all_dependencies


async def get_repository_python_dependencies(
    owner: str, 
    repo: str, 
    github_client: Optional[GitHubAPIClient] = None
) -> List[DependencyInfo]:
    """
    Get Python dependencies from a repository
    
    Args:
        owner: Repository owner
        repo: Repository name
        github_client: Optional GitHub client
        
    Returns:
        List of Python dependencies
    """
    parser = DependencyParser(github_client)
    parse_results = await parser.parse_repository_dependencies(owner, repo)
    
    # Filter for Python ecosystems
    python_results = [
        result for result in parse_results 
        if result.ecosystem in [PackageEcosystem.PIP, PackageEcosystem.PIPENV, PackageEcosystem.POETRY]
    ]
    
    # Convert to DependencyInfo
    all_dependencies = []
    for result in python_results:
        all_dependencies.extend(parser.convert_to_dependency_info(result.dependencies))
    
    return all_dependencies


async def discover_repository_structure(
    owner: str, 
    repo: str, 
    github_client: Optional[GitHubAPIClient] = None
) -> Dict[str, Any]:
    """
    Discover repository structure and dependency files using smart discovery
    
    Args:
        owner: Repository owner
        repo: Repository name
        github_client: Optional GitHub client
        
    Returns:
        Dictionary with discovery results and metadata
    """
    parser = DependencyParser(github_client)
    
    try:
        # Discover dependency files
        discovered_files = await parser.discover_dependency_files(owner, repo)
        
        # Group by ecosystem
        by_ecosystem = {}
        for file_info in discovered_files:
            ecosystem = parser._get_file_ecosystem(file_info["name"])
            if ecosystem not in by_ecosystem:
                by_ecosystem[ecosystem] = []
            by_ecosystem[ecosystem].append(file_info)
        
        # Calculate statistics
        total_files = len(discovered_files)
        ecosystems_found = list(by_ecosystem.keys())
        max_depth = max((f["depth"] for f in discovered_files), default=0)
        
        # Determine structure type
        depth_distribution = {}
        for file_info in discovered_files:
            depth = file_info["depth"]
            depth_distribution[depth] = depth_distribution.get(depth, 0) + 1
        
        return {
            "repository": f"{owner}/{repo}",
            "total_dependency_files": total_files,
            "ecosystems_detected": ecosystems_found,
            "max_search_depth": max_depth,
            "depth_distribution": depth_distribution,
            "files_by_ecosystem": by_ecosystem,
            "discovered_files": discovered_files,
            "structure_summary": {
                "is_monorepo": max_depth > 2 and total_files > 5,
                "has_multiple_ecosystems": len(ecosystems_found) > 1,
                "primary_ecosystem": max(by_ecosystem.keys(), key=lambda k: len(by_ecosystem[k])) if by_ecosystem else None
            }
        }
        
    except Exception as e:
        logger.error(f"Failed to discover repository structure for {owner}/{repo}: {str(e)}")
        return {
            "repository": f"{owner}/{repo}",
            "error": str(e),
            "total_dependency_files": 0,
            "ecosystems_detected": [],
            "discovered_files": []
        }


async def get_repository_nodejs_dependencies(
    owner: str, 
    repo: str, 
    github_client: Optional[GitHubAPIClient] = None
) -> List[DependencyInfo]:
    """
    Get Node.js dependencies from a repository
    
    Args:
        owner: Repository owner
        repo: Repository name
        github_client: Optional GitHub client
        
    Returns:
        List of Node.js dependencies
    """
    parser = DependencyParser(github_client)
    parse_results = await parser.parse_repository_dependencies(owner, repo)
    
    # Filter for Node.js/npm/yarn ecosystems
    nodejs_results = [
        result for result in parse_results 
        if result.ecosystem in [PackageEcosystem.NPM, PackageEcosystem.YARN]
    ]
    
    # Convert to DependencyInfo
    all_dependencies = []
    for result in nodejs_results:
        all_dependencies.extend(parser.convert_to_dependency_info(result.dependencies))
    
    return all_dependencies
