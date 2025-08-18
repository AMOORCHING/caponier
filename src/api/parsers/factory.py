"""
Parser factory for managing dependency parser implementations.

This module provides a factory pattern for selecting and instantiating
the appropriate parser for different dependency file types.
"""

import logging
from typing import Dict, List, Optional, Type
from .base import DependencyParser, DependencyParseResult, PackageEcosystem

logger = logging.getLogger(__name__)


class ParserFactory:
    """
    Factory for creating and managing dependency parsers.
    
    This class maintains a registry of available parsers and provides
    methods to select the appropriate parser for a given file.
    """
    
    def __init__(self):
        """Initialize the parser factory with an empty registry."""
        self._parsers: Dict[str, Type[DependencyParser]] = {}
        self._file_to_parser: Dict[str, Type[DependencyParser]] = {}
    
    def register_parser(self, parser_class: Type[DependencyParser]) -> None:
        """
        Register a parser class with the factory.
        
        Args:
            parser_class: The parser class to register
        """
        parser_instance = parser_class()
        ecosystem = parser_instance.get_ecosystem()
        
        # Register by ecosystem
        self._parsers[ecosystem.value] = parser_class
        
        # Register by supported files
        for filename in parser_instance.supported_files():
            self._file_to_parser[filename] = parser_class
            
        logger.debug(f"Registered parser {parser_class.__name__} for ecosystem {ecosystem.value}")
    
    def get_parser_for_file(self, filename: str) -> Optional[DependencyParser]:
        """
        Get the appropriate parser for a given filename.
        
        Args:
            filename: Name of the file to parse
            
        Returns:
            Parser instance if available, None otherwise
        """
        parser_class = self._file_to_parser.get(filename)
        if parser_class:
            return parser_class()
        
        logger.warning(f"No parser found for file: {filename}")
        return None
    
    def get_parser_for_ecosystem(self, ecosystem: PackageEcosystem) -> Optional[DependencyParser]:
        """
        Get the parser for a specific ecosystem.
        
        Args:
            ecosystem: The package ecosystem
            
        Returns:
            Parser instance if available, None otherwise
        """
        parser_class = self._parsers.get(ecosystem.value)
        if parser_class:
            return parser_class()
        
        logger.warning(f"No parser found for ecosystem: {ecosystem.value}")
        return None
    
    def get_supported_files(self) -> List[str]:
        """
        Get list of all supported file types.
        
        Returns:
            List of supported filenames
        """
        return list(self._file_to_parser.keys())
    
    def get_supported_ecosystems(self) -> List[PackageEcosystem]:
        """
        Get list of all supported ecosystems.
        
        Returns:
            List of supported ecosystems
        """
        return [PackageEcosystem(ecosystem) for ecosystem in self._parsers.keys()]
    
    def parse_file(self, filename: str, content: str) -> Optional[DependencyParseResult]:
        """
        Parse a file using the appropriate parser.
        
        Args:
            filename: Name of the file to parse
            content: File content to parse
            
        Returns:
            Parse result if successful, None if no parser available
        """
        parser = self.get_parser_for_file(filename)
        if parser:
            try:
                return parser.parse(content, filename)
            except Exception as e:
                logger.error(f"Error parsing {filename}: {e}")
                return None
        
        return None


# Global factory instance
parser_factory = ParserFactory()
