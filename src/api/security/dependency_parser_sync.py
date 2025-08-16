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
        Get file content from repository
        
        Args:
            owner: Repository owner
            repo: Repository name
            file_path: Path to file
            
        Returns:
            File content as string or None if not found
        """
        try:
            file_data = self.github_client.get_file_content(owner, repo, file_path)
            
            # GitHub API returns base64 encoded content
            if file_data.get('encoding') == 'base64':
                content = base64.b64decode(file_data['content']).decode('utf-8')
                return content
            
            # Handle direct content
            elif 'content' in file_data:
                return file_data['content']
            
            return None
            
        except Exception as e:
            logger.warning(f"Could not get content for {file_path}: {e}")
            return None
    
    # Parser method delegates - these call the existing static parser methods
    def _parse_package_json(self, content: str, manifest_file: str) -> DependencyParseResult:
        """Parse package.json content"""
        return NodeJSDependencyParser.parse_package_json(content, manifest_file)
    
    def _parse_package_lock_json(self, content: str, manifest_file: str) -> DependencyParseResult:
        """Parse package-lock.json content"""
        return NodeJSDependencyParser.parse_package_lock_json(content, manifest_file)
    
    def _parse_yarn_lock(self, content: str, manifest_file: str) -> DependencyParseResult:
        """Parse yarn.lock content"""
        return NodeJSDependencyParser.parse_yarn_lock(content, manifest_file)
    
    def _parse_requirements_txt(self, content: str, manifest_file: str) -> DependencyParseResult:
        """Parse requirements.txt content"""
        return PythonDependencyParser.parse_requirements_txt(content, manifest_file)
    
    def _parse_pipfile(self, content: str, manifest_file: str) -> DependencyParseResult:
        """Parse Pipfile content"""
        return PythonDependencyParser.parse_pipfile(content, manifest_file)
    
    def _parse_poetry_lock(self, content: str, manifest_file: str) -> DependencyParseResult:
        """Parse poetry.lock content"""
        return PythonDependencyParser.parse_poetry_lock(content, manifest_file)
    
    def _parse_cargo_toml(self, content: str, manifest_file: str) -> DependencyParseResult:
        """Parse Cargo.toml content"""
        return RustDependencyParser.parse_cargo_toml(content, manifest_file)
    
    def _parse_cargo_lock(self, content: str, manifest_file: str) -> DependencyParseResult:
        """Parse Cargo.lock content"""
        return RustDependencyParser.parse_cargo_lock(content, manifest_file)
    
    def _parse_pom_xml(self, content: str, manifest_file: str) -> DependencyParseResult:
        """Parse pom.xml content"""
        return JavaDependencyParser.parse_pom_xml(content, manifest_file)
    
    def _parse_build_gradle(self, content: str, manifest_file: str) -> DependencyParseResult:
        """Parse build.gradle content"""
        return JavaDependencyParser.parse_build_gradle(content, manifest_file)
