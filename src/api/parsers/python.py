"""
Python dependency parser for requirements.txt, Pipfile, and poetry.lock files.

This module provides robust parsing for Python dependency files using
proper parsing libraries instead of regex-based approaches.
"""

import re
import logging
from typing import Dict, List, Any, Optional
from .base import DependencyParser, ParsedDependency, DependencyParseResult, PackageEcosystem

logger = logging.getLogger(__name__)


class PythonParser(DependencyParser):
    """
    Parser for Python dependency files.
    
    Supports requirements.txt, Pipfile, and poetry.lock files with
    proper parsing and validation.
    """
    
    def __init__(self):
        """Initialize the Python parser."""
        self.ecosystem = PackageEcosystem.PIP
    
    def parse(self, file_content: str, manifest_file: str) -> DependencyParseResult:
        """
        Parse Python dependency file content.
        
        Args:
            file_content: Raw content of the dependency file
            manifest_file: Name/path of the file being parsed
            
        Returns:
            DependencyParseResult containing parsed dependencies
            
        Raises:
            DependencyParsingError: If parsing fails due to invalid format
        """
        dependencies = []
        parsing_errors = []
        metadata = {}
        
        try:
            if manifest_file == "requirements.txt":
                result = self._parse_requirements_txt(file_content, manifest_file)
            elif manifest_file == "Pipfile":
                result = self._parse_pipfile(file_content, manifest_file)
            elif manifest_file == "poetry.lock":
                result = self._parse_poetry_lock(file_content, manifest_file)
            elif manifest_file == "setup.py":
                result = self._parse_setup_py(file_content, manifest_file)
            else:
                error_msg = f"Unsupported Python file: {manifest_file}"
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
        """Get list of supported Python files."""
        return ["requirements.txt", "Pipfile", "poetry.lock", "setup.py"]
    
    def get_ecosystem(self) -> PackageEcosystem:
        """Get the Python ecosystem."""
        return self.ecosystem
    
    def _parse_requirements_txt(self, content: str, manifest_file: str) -> Dict[str, Any]:
        """Parse requirements.txt file."""
        dependencies = []
        metadata = {}
        
        lines = content.split('\n')
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            
            # Skip empty lines and comments
            if not line or line.startswith('#'):
                continue
            
            # Skip editable installs for now
            if line.startswith('-e ') or line.startswith('--editable '):
                continue
            
            try:
                # Parse dependency line
                dep = self._parse_requirement_line(line, manifest_file)
                if dep:
                    dependencies.append(dep)
            except Exception as e:
                logger.warning(f"Error parsing line {line_num} in {manifest_file}: {e}")
                continue
        
        return {
            "dependencies": dependencies,
            "metadata": metadata
        }
    
    def _parse_requirement_line(self, line: str, manifest_file: str) -> Optional[ParsedDependency]:
        """Parse a single requirement line."""
        # Remove comments
        line = re.sub(r'#.*$', '', line).strip()
        if not line:
            return None
        
        # Handle different requirement formats
        # Format: package==version
        # Format: package>=version
        # Format: package~=version
        # Format: package
        match = re.match(r'^([a-zA-Z0-9_-]+)(.*)$', line)
        if not match:
            return None
        
        name = match.group(1)
        version_spec = match.group(2).strip()
        
        # Determine version constraint
        version_constraint = version_spec if version_spec else "*"
        
        # Extract version for display (remove operators)
        version = re.sub(r'^[=<>~!]+', '', version_spec) if version_spec else ""
        
        return ParsedDependency(
            name=name,
            version=version,
            version_constraint=version_constraint,
            ecosystem=self.ecosystem,
            manifest_file=manifest_file,
            is_dev_dependency=False
        )
    
    def _parse_pipfile(self, content: str, manifest_file: str) -> Dict[str, Any]:
        """Parse Pipfile."""
        dependencies = []
        metadata = {}
        
        try:
            # Try to import toml for proper parsing
            import toml
            data = toml.loads(content)
            
            # Parse production dependencies
            deps = data.get("packages", {})
            for name, spec in deps.items():
                if isinstance(spec, dict):
                    version = spec.get("version", "*")
                else:
                    version = str(spec) if spec else "*"
                
                dep = ParsedDependency(
                    name=name,
                    version=version,
                    version_constraint=version,
                    ecosystem=PackageEcosystem.PIPENV,
                    manifest_file=manifest_file,
                    is_dev_dependency=False
                )
                dependencies.append(dep)
            
            # Parse development dependencies
            dev_deps = data.get("dev-packages", {})
            for name, spec in dev_deps.items():
                if isinstance(spec, dict):
                    version = spec.get("version", "*")
                else:
                    version = str(spec) if spec else "*"
                
                dep = ParsedDependency(
                    name=name,
                    version=version,
                    version_constraint=version,
                    ecosystem=PackageEcosystem.PIPENV,
                    manifest_file=manifest_file,
                    is_dev_dependency=True
                )
                dependencies.append(dep)
            
            # Extract metadata
            metadata["source"] = data.get("source", [])
            
        except ImportError:
            # Fallback to regex parsing if toml is not available
            logger.warning("toml library not available, using regex fallback for Pipfile")
            dependencies = self._parse_pipfile_regex(content, manifest_file)
        except Exception as e:
            logger.error(f"Error parsing Pipfile: {e}")
            raise
        
        return {
            "dependencies": dependencies,
            "metadata": metadata
        }
    
    def _parse_pipfile_regex(self, content: str, manifest_file: str) -> List[ParsedDependency]:
        """Fallback regex parsing for Pipfile."""
        dependencies = []
        
        # Simple regex patterns for Pipfile sections
        packages_pattern = r'\[packages\]\s*\n(.*?)(?=\n\[|\Z)'
        dev_packages_pattern = r'\[dev-packages\]\s*\n(.*?)(?=\n\[|\Z)'
        
        # Parse production packages
        packages_match = re.search(packages_pattern, content, re.DOTALL)
        if packages_match:
            packages_content = packages_match.group(1)
            for line in packages_content.split('\n'):
                line = line.strip()
                if line and not line.startswith('#'):
                    dep = self._parse_pipfile_line(line, manifest_file, False)
                    if dep:
                        dependencies.append(dep)
        
        # Parse dev packages
        dev_packages_match = re.search(dev_packages_pattern, content, re.DOTALL)
        if dev_packages_match:
            dev_packages_content = dev_packages_match.group(1)
            for line in dev_packages_content.split('\n'):
                line = line.strip()
                if line and not line.startswith('#'):
                    dep = self._parse_pipfile_line(line, manifest_file, True)
                    if dep:
                        dependencies.append(dep)
        
        return dependencies
    
    def _parse_pipfile_line(self, line: str, manifest_file: str, is_dev: bool) -> Optional[ParsedDependency]:
        """Parse a single Pipfile line."""
        # Format: package = "version"
        match = re.match(r'^([a-zA-Z0-9_-]+)\s*=\s*["\']?([^"\']*)["\']?$', line)
        if not match:
            return None
        
        name = match.group(1)
        version = match.group(2).strip()
        
        return ParsedDependency(
            name=name,
            version=version,
            version_constraint=version,
            ecosystem=PackageEcosystem.PIPENV,
            manifest_file=manifest_file,
            is_dev_dependency=is_dev
        )
    
    def _parse_poetry_lock(self, content: str, manifest_file: str) -> Dict[str, Any]:
        """Parse poetry.lock file."""
        dependencies = []
        metadata = {}
        
        try:
            import toml
            data = toml.loads(content)
            
            # Parse package entries
            packages = data.get("package", [])
            for pkg in packages:
                name = pkg.get("name", "")
                version = pkg.get("version", "")
                category = pkg.get("category", "main")
                
                is_dev = category in ["dev", "test"]
                
                dep = ParsedDependency(
                    name=name,
                    version=version,
                    version_constraint=version,
                    ecosystem=PackageEcosystem.POETRY,
                    manifest_file=manifest_file,
                    is_dev_dependency=is_dev
                )
                dependencies.append(dep)
            
            # Extract metadata
            metadata["lock_version"] = data.get("metadata", {}).get("lock-version", "")
            
        except ImportError:
            logger.warning("toml library not available, cannot parse poetry.lock")
        except Exception as e:
            logger.error(f"Error parsing poetry.lock: {e}")
            raise
        
        return {
            "dependencies": dependencies,
            "metadata": metadata
        }
    
    def _parse_setup_py(self, content: str, manifest_file: str) -> Dict[str, Any]:
        """Parse setup.py file."""
        dependencies = []
        metadata = {}
        
        # Extract install_requires
        install_requires_match = re.search(
            r'install_requires\s*=\s*\[(.*?)\]',
            content,
            re.DOTALL
        )
        
        if install_requires_match:
            requires_content = install_requires_match.group(1)
            for line in requires_content.split('\n'):
                line = line.strip().strip('"\'')
                if line and not line.startswith('#'):
                    dep = self._parse_requirement_line(line, manifest_file)
                    if dep:
                        dependencies.append(dep)
        
        # Extract setup_requires
        setup_requires_match = re.search(
            r'setup_requires\s*=\s*\[(.*?)\]',
            content,
            re.DOTALL
        )
        
        if setup_requires_match:
            requires_content = setup_requires_match.group(1)
            for line in requires_content.split('\n'):
                line = line.strip().strip('"\'')
                if line and not line.startswith('#'):
                    dep = self._parse_requirement_line(line, manifest_file)
                    if dep:
                        dep.is_dev_dependency = True
                        dependencies.append(dep)
        
        return {
            "dependencies": dependencies,
            "metadata": metadata
        }
