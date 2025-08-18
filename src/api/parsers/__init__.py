"""
Dependency parsers package.

This package contains specialized parsers for different dependency file formats.
Each parser implements a common interface for consistent dependency extraction.
"""

from .base import DependencyParser, ParsedDependency, DependencyParseResult
from .factory import ParserFactory

__all__ = [
    "DependencyParser",
    "ParsedDependency", 
    "DependencyParseResult",
    "ParserFactory"
]
