"""
Synchronous dependency parser for Celery tasks

This module provides a synchronous version of the dependency parser specifically
designed for use in Celery tasks to avoid asyncio.run() performance issues.
"""

import logging
from typing import Dict, List, Any, Optional
import base64

from .github_client_sync import SyncGitHubClient
from .dependency_parser import (
    PythonDependencyParser, 
    RustDependencyParser, 
    JavaDependencyParser, 
    NodeJSDependencyParser,
    DependencyParseResult,
    PackageEcosystem
)
from .secure_parser import (
    secure_decode_base64_content,
    validate_file_size,
    SecurityError,
    FileSizeError,
    ParseTimeoutError,
    SecureFileParser
)
from ..utils.exceptions import DependencyParsingError

logger = logging.getLogger(__name__)


class SyncDependencyParser:
    """
    Synchronous dependency parser that coordinates parsing across different ecosystems
    """
    
    def __init__(self, github_client: SyncGitHubClient):
        """
        Initialize synchronous dependency parser
        
        Args:
            github_client: Synchronous GitHub API client
        """
        self.github_client = github_client
    
    def parse_repository_dependencies(
        self, 
        owner: str, 
        repo: str,
        use_smart_discovery: bool = True
    ) -> List[DependencyParseResult]:
        """
        Parse all dependency files found in a repository
        
        Args:
            owner: Repository owner
            repo: Repository name
            use_smart_discovery: Use smart recursive file discovery (default: True)
            
        Returns:
            List of dependency parse results for all found manifest files
        """
        results = []
        
        try:
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
            discovered_files = []
            if use_smart_discovery:
                discovered_files = self._smart_discovery(owner, repo, dependency_files.keys())
            else:
                discovered_files = self._basic_discovery(owner, repo, dependency_files.keys())
            
            logger.info(f"Discovered {len(discovered_files)} dependency files in {owner}/{repo}")
            
            # Parse each discovered file
            for file_info in discovered_files:
                file_path = file_info['path']
                file_name = file_info['name']
                
                if file_name in dependency_files:
                    ecosystem, parser_func = dependency_files[file_name]
                    
                    try:
                        logger.debug(f"Parsing {file_path} as {ecosystem.value}")
                        
                        # Get file content
                        content = self._get_file_content(owner, repo, file_path)
                        
                        if content:
                            # Parse the content
                            result = parser_func(content, file_path)
                            if result:
                                results.append(result)
                                logger.info(
                                    f"Successfully parsed {file_path}: "
                                    f"{result.total_dependencies} dependencies found"
                                )
                        
                    except Exception as e:
                        logger.warning(f"Failed to parse {file_path}: {e}")
                        # Create error result
                        error_result = DependencyParseResult(
                            dependencies=[],
                            ecosystem=ecosystem,
                            manifest_file=file_path,
                            total_dependencies=0,
                            dev_dependencies=0,
                            production_dependencies=0,
                            parsing_errors=[str(e)],
                            metadata={'error': str(e)}
                        )
                        results.append(error_result)
            
            logger.info(f"Completed dependency parsing for {owner}/{repo}: {len(results)} files processed")
            return results
            
        except Exception as e:
            logger.error(f"Failed to parse repository dependencies for {owner}/{repo}: {e}")
            raise DependencyParsingError("repository", str(e), PackageEcosystem.NPM)
    
    def _smart_discovery(self, owner: str, repo: str, target_files: List[str]) -> List[Dict[str, Any]]:
        """
        Smart recursive discovery of dependency files
        
        Args:
            owner: Repository owner
            repo: Repository name
            target_files: List of target file names to find
            
        Returns:
            List of discovered file information
        """
        discovered = []
        visited_paths = set()
        
        def search_directory(path: str = "", depth: int = 0, max_depth: int = 5):
            """Recursively search directory for dependency files"""
            if depth > max_depth or path in visited_paths:
                return
            
            visited_paths.add(path)
            
            try:
                files = self.github_client.get_repository_files(owner, repo, path)
                
                for file_info in files:
                    file_name = file_info.get('name', '')
                    file_path = file_info.get('path', '')
                    file_type = file_info.get('type', '')
                    
                    if file_name in target_files:
                        discovered.append({
                            'name': file_name,
                            'path': file_path,
                            'type': file_type,
                            'depth': depth
                        })
                        logger.debug(f"Found dependency file: {file_path}")
                    
                    # Recursively search subdirectories
                    elif file_type == 'dir' and not self._should_skip_directory(file_name):
                        search_directory(file_path, depth + 1, max_depth)
                        
            except Exception as e:
                logger.debug(f"Could not search directory {path}: {e}")
        
        # Start discovery from root
        search_directory()
        
        return discovered
    
    def _basic_discovery(self, owner: str, repo: str, target_files: List[str]) -> List[Dict[str, Any]]:
        """
        Basic discovery of dependency files in root directory
        
        Args:
            owner: Repository owner
            repo: Repository name
            target_files: List of target file names to find
            
        Returns:
            List of discovered file information
        """
        discovered = []
        
        try:
            files = self.github_client.get_repository_files(owner, repo)
            
            for file_info in files:
                file_name = file_info.get('name', '')
                if file_name in target_files:
                    discovered.append({
                        'name': file_name,
                        'path': file_info.get('path', ''),
                        'type': file_info.get('type', ''),
                        'depth': 0
                    })
                    logger.debug(f"Found dependency file: {file_info.get('path', '')}")
            
        except Exception as e:
            logger.warning(f"Failed basic discovery for {owner}/{repo}: {e}")
        
        return discovered
    
    def _should_skip_directory(self, dir_name: str) -> bool:
        """
        Check if directory should be skipped during discovery
        
        Args:
            dir_name: Directory name
            
        Returns:
            True if directory should be skipped
        """
        skip_dirs = {
            '.git', '.github', '.vscode', '.idea',
            'node_modules', 'target', 'build', 'dist',
            '__pycache__', '.pytest_cache', '.mypy_cache',
            'vendor', 'deps', 'tmp', 'temp'
        }
        
        return dir_name.lower() in skip_dirs or dir_name.startswith('.')
    
    def _get_file_content(self, owner: str, repo: str, file_path: str) -> Optional[str]:
        """
        Get file content from repository with security validation
        
        Args:
            owner: Repository owner
            repo: Repository name
            file_path: Path to file
            
        Returns:
            File content as string or None if not found
            
        Raises:
            FileSizeError: If file exceeds size limits
            SecurityError: If content cannot be safely decoded
        """
        try:
            file_data = self.github_client.get_file_content(owner, repo, file_path)
            
            # Check file size from GitHub API metadata
            file_size = file_data.get('size', 0)
            if file_size > 10 * 1024 * 1024:  # 10MB limit
                raise FileSizeError(
                    f"File {file_path} size {file_size} bytes exceeds 10MB limit"
                )
            
            # GitHub API returns base64 encoded content
            if file_data.get('encoding') == 'base64':
                # Use secure base64 decoding with size validation
                content = secure_decode_base64_content(file_data['content'])
                
                # Additional validation after decoding
                validate_file_size(content)
                
                logger.debug(f"Successfully retrieved and validated content for {file_path}")
                return content
            
            # Handle direct content
            elif 'content' in file_data:
                content = file_data['content']
                validate_file_size(content)
                return content
            
            return None
            
        except (FileSizeError, SecurityError) as e:
            logger.error(f"Security validation failed for {file_path}: {e}")
            raise DependencyParsingError(file_path, str(e), PackageEcosystem.NPM)
        except Exception as e:
            logger.warning(f"Could not get content for {file_path}: {e}")
            return None
    
    # Parser method delegates with security hardening
    def _parse_package_json(self, content: str, manifest_file: str) -> DependencyParseResult:
        """Parse package.json content with security validation"""
        try:
            with SecureFileParser(content, 'json') as parser:
                # Validate JSON structure first
                parser.parse()  # This validates the JSON
                # Then use the original parser
                return NodeJSDependencyParser.parse_package_json(content, manifest_file)
        except (SecurityError, FileSizeError, ParseTimeoutError) as e:
            logger.error(f"Security validation failed for {manifest_file}: {e}")
            raise DependencyParsingError(manifest_file, str(e), PackageEcosystem.NPM)
    
    def _parse_package_lock_json(self, content: str, manifest_file: str) -> DependencyParseResult:
        """Parse package-lock.json content with security validation"""
        try:
            with SecureFileParser(content, 'json') as parser:
                parser.parse()  # Validate JSON structure
                return NodeJSDependencyParser.parse_package_lock_json(content, manifest_file)
        except (SecurityError, FileSizeError, ParseTimeoutError) as e:
            logger.error(f"Security validation failed for {manifest_file}: {e}")
            raise DependencyParsingError(manifest_file, str(e), PackageEcosystem.NPM)
    
    def _parse_yarn_lock(self, content: str, manifest_file: str) -> DependencyParseResult:
        """Parse yarn.lock content with security validation"""
        try:
            with SecureFileParser(content, 'text') as parser:
                # yarn.lock is a custom format, validate as text
                return NodeJSDependencyParser.parse_yarn_lock(content, manifest_file)
        except (SecurityError, FileSizeError, ParseTimeoutError) as e:
            logger.error(f"Security validation failed for {manifest_file}: {e}")
            raise DependencyParsingError(manifest_file, str(e), PackageEcosystem.YARN)
    
    def _parse_requirements_txt(self, content: str, manifest_file: str) -> DependencyParseResult:
        """Parse requirements.txt content with security validation"""
        try:
            with SecureFileParser(content, 'text') as parser:
                return PythonDependencyParser.parse_requirements_txt(content, manifest_file)
        except (SecurityError, FileSizeError, ParseTimeoutError) as e:
            logger.error(f"Security validation failed for {manifest_file}: {e}")
            raise DependencyParsingError(manifest_file, str(e), PackageEcosystem.PIP)
    
    def _parse_pipfile(self, content: str, manifest_file: str) -> DependencyParseResult:
        """Parse Pipfile content with security validation"""
        try:
            with SecureFileParser(content, 'toml') as parser:
                parser.parse()  # Validate TOML structure
                return PythonDependencyParser.parse_pipfile(content, manifest_file)
        except (SecurityError, FileSizeError, ParseTimeoutError) as e:
            logger.error(f"Security validation failed for {manifest_file}: {e}")
            raise DependencyParsingError(manifest_file, str(e), PackageEcosystem.PIPENV)
    
    def _parse_poetry_lock(self, content: str, manifest_file: str) -> DependencyParseResult:
        """Parse poetry.lock content with security validation"""
        try:
            with SecureFileParser(content, 'toml') as parser:
                parser.parse()  # Validate TOML structure
                return PythonDependencyParser.parse_poetry_lock(content, manifest_file)
        except (SecurityError, FileSizeError, ParseTimeoutError) as e:
            logger.error(f"Security validation failed for {manifest_file}: {e}")
            raise DependencyParsingError(manifest_file, str(e), PackageEcosystem.POETRY)
    
    def _parse_cargo_toml(self, content: str, manifest_file: str) -> DependencyParseResult:
        """Parse Cargo.toml content with security validation"""
        try:
            with SecureFileParser(content, 'toml') as parser:
                parser.parse()  # Validate TOML structure
                return RustDependencyParser.parse_cargo_toml(content, manifest_file)
        except (SecurityError, FileSizeError, ParseTimeoutError) as e:
            logger.error(f"Security validation failed for {manifest_file}: {e}")
            raise DependencyParsingError(manifest_file, str(e), PackageEcosystem.CARGO)
    
    def _parse_cargo_lock(self, content: str, manifest_file: str) -> DependencyParseResult:
        """Parse Cargo.lock content with security validation"""
        try:
            with SecureFileParser(content, 'toml') as parser:
                parser.parse()  # Validate TOML structure
                return RustDependencyParser.parse_cargo_lock(content, manifest_file)
        except (SecurityError, FileSizeError, ParseTimeoutError) as e:
            logger.error(f"Security validation failed for {manifest_file}: {e}")
            raise DependencyParsingError(manifest_file, str(e), PackageEcosystem.CARGO)
    
    def _parse_pom_xml(self, content: str, manifest_file: str) -> DependencyParseResult:
        """Parse pom.xml content with security validation"""
        try:
            with SecureFileParser(content, 'xml') as parser:
                parser.parse()  # Validate XML structure with defusedxml
                return JavaDependencyParser.parse_pom_xml(content, manifest_file)
        except (SecurityError, FileSizeError, ParseTimeoutError) as e:
            logger.error(f"Security validation failed for {manifest_file}: {e}")
            raise DependencyParsingError(manifest_file, str(e), PackageEcosystem.MAVEN)
    
    def _parse_build_gradle(self, content: str, manifest_file: str) -> DependencyParseResult:
        """Parse build.gradle content with security validation"""
        try:
            with SecureFileParser(content, 'text') as parser:
                # Gradle files are Groovy/Kotlin, validate as text
                return JavaDependencyParser.parse_build_gradle(content, manifest_file)
        except (SecurityError, FileSizeError, ParseTimeoutError) as e:
            logger.error(f"Security validation failed for {manifest_file}: {e}")
            raise DependencyParsingError(manifest_file, str(e), PackageEcosystem.GRADLE)
