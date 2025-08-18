"""
Base parser interface for dependency file parsing.

This module defines the abstract base class and data structures that all
dependency parsers must implement for consistent behavior across the system.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Any, Optional


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


class DependencyParser(ABC):
    """
    Abstract base class for dependency parsers.
    
    All dependency parsers must implement this interface to ensure
    consistent behavior and integration with the parser factory.
    """
    
    @abstractmethod
    def parse(self, file_content: str, manifest_file: str) -> DependencyParseResult:
        """
        Parse dependency file content and extract dependency information.
        
        Args:
            file_content: Raw content of the dependency file
            manifest_file: Name/path of the manifest file being parsed
            
        Returns:
            DependencyParseResult containing parsed dependencies and metadata
            
        Raises:
            DependencyParsingError: If parsing fails due to invalid format
        """
        pass
    
    @abstractmethod
    def supported_files(self) -> List[str]:
        """
        Get list of file names this parser can handle.
        
        Returns:
            List of supported file names (e.g., ["package.json", "package-lock.json"])
        """
        pass
    
    @abstractmethod
    def get_ecosystem(self) -> PackageEcosystem:
        """
        Get the package ecosystem this parser handles.
        
        Returns:
            PackageEcosystem enum value
        """
        pass
    
    def can_parse(self, filename: str) -> bool:
        """
        Check if this parser can handle the given filename.
        
        Args:
            filename: Name of the file to check
            
        Returns:
            True if parser can handle this file, False otherwise
        """
        return filename in self.supported_files()
