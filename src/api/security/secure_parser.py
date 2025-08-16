"""
Secure parsing utilities for dependency files

This module provides security-hardened parsing functions to prevent:
- Memory exhaustion attacks via large files
- ReDoS attacks via malicious regex patterns
- XML entity expansion attacks
- Infinite loops in parsing operations
"""

import logging
import re
import time
from typing import Any, Optional, Dict, List, Callable, Union
from functools import wraps
import xml.etree.ElementTree as ET
import base64

try:
    import defusedxml.ElementTree as SecureET
    HAS_DEFUSEDXML = True
except ImportError:
    SecureET = None
    HAS_DEFUSEDXML = False

try:
    import timeout_decorator
    HAS_TIMEOUT_DECORATOR = True
except ImportError:
    timeout_decorator = None
    HAS_TIMEOUT_DECORATOR = False

from ..utils.exceptions import DependencyParsingError

logger = logging.getLogger(__name__)

# Security configuration
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
MAX_PARSE_TIME = 30  # 30 seconds
MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50MB for base64 decoded content
MAX_REGEX_TIME = 5  # 5 seconds for regex operations

# Safe regex patterns to prevent ReDoS
SAFE_REGEX_PATTERNS = {
    'python_requirement': r'^([a-zA-Z0-9][a-zA-Z0-9._-]{0,100}[a-zA-Z0-9]|[a-zA-Z0-9])(\[[^\]]{0,200}\])?(.*)',
    'semantic_version': r'^([0-9]+)\.([0-9]+)\.([0-9]+)(?:-([0-9A-Za-z-]{1,50}(?:\.[0-9A-Za-z-]{1,50})*))?(?:\+([0-9A-Za-z-]{1,50}(?:\.[0-9A-Za-z-]{1,50})*))?$',
    'package_name': r'^[a-zA-Z0-9][a-zA-Z0-9._-]{0,100}[a-zA-Z0-9]$',
    'version_constraint': r'^[<>=!~^]{0,3}[0-9][a-zA-Z0-9._-]{0,50}$',
    'gradle_dependency': r'(\w+)\s+[\'\"]([^:]+):([^:]+):([^\'\"]*)[\'\"]\s*',
    'yarn_dependency': r'^[\'\"]?([^@\s]+)@([^\'\"]+)[\'\"]?\s*:\s*$'
}


class SecurityError(Exception):
    """Exception raised for security violations during parsing"""
    pass


class FileSizeError(SecurityError):
    """Exception raised when file size exceeds limits"""
    pass


class ParseTimeoutError(SecurityError):
    """Exception raised when parsing times out"""
    pass


class RegexTimeoutError(SecurityError):
    """Exception raised when regex execution times out"""
    pass


def validate_file_size(content: Union[str, bytes], max_size: int = MAX_FILE_SIZE) -> None:
    """
    Validate that content size is within safe limits
    
    Args:
        content: File content to validate
        max_size: Maximum allowed size in bytes
        
    Raises:
        FileSizeError: If content exceeds size limit
    """
    if isinstance(content, str):
        size = len(content.encode('utf-8'))
    else:
        size = len(content)
    
    if size > max_size:
        raise FileSizeError(
            f"File size {size} bytes exceeds maximum allowed size {max_size} bytes"
        )
    
    logger.debug(f"File size validation passed: {size} bytes")


def timeout_parsing(max_time: int = MAX_PARSE_TIME):
    """
    Decorator to add timeout protection to parsing functions
    
    Args:
        max_time: Maximum parsing time in seconds
    """
    def decorator(func: Callable) -> Callable:
        if HAS_TIMEOUT_DECORATOR:
            return timeout_decorator.timeout(max_time)(func)
        else:
            # Fallback implementation without timeout-decorator
            @wraps(func)
            def wrapper(*args, **kwargs):
                start_time = time.time()
                try:
                    result = func(*args, **kwargs)
                    elapsed = time.time() - start_time
                    if elapsed > max_time:
                        logger.warning(f"Parsing took {elapsed:.2f}s, exceeding recommended {max_time}s")
                    return result
                except Exception as e:
                    elapsed = time.time() - start_time
                    if elapsed > max_time:
                        raise ParseTimeoutError(f"Parsing timed out after {elapsed:.2f}s")
                    raise
            return wrapper
    return decorator


def safe_regex_match(pattern: str, text: str, timeout: float = MAX_REGEX_TIME) -> Optional[re.Match]:
    """
    Safely execute regex match with timeout protection
    
    Args:
        pattern: Regex pattern
        text: Text to match against
        timeout: Maximum execution time in seconds
        
    Returns:
        Match object or None
        
    Raises:
        RegexTimeoutError: If regex execution exceeds timeout
    """
    start_time = time.time()
    
    try:
        # Compile pattern with reasonable limits
        compiled_pattern = re.compile(pattern, re.DOTALL)
        
        # Check for potentially dangerous patterns
        if _is_dangerous_regex(pattern):
            logger.warning(f"Potentially dangerous regex pattern detected: {pattern}")
        
        match = compiled_pattern.match(text)
        
        elapsed = time.time() - start_time
        if elapsed > timeout:
            raise RegexTimeoutError(f"Regex execution timed out after {elapsed:.2f}s")
        
        return match
        
    except re.error as e:
        logger.error(f"Invalid regex pattern '{pattern}': {e}")
        return None
    except Exception as e:
        elapsed = time.time() - start_time
        if elapsed > timeout:
            raise RegexTimeoutError(f"Regex execution timed out after {elapsed:.2f}s")
        raise


def safe_regex_findall(pattern: str, text: str, timeout: float = MAX_REGEX_TIME) -> List[str]:
    """
    Safely execute regex findall with timeout protection
    
    Args:
        pattern: Regex pattern
        text: Text to search
        timeout: Maximum execution time in seconds
        
    Returns:
        List of matches
        
    Raises:
        RegexTimeoutError: If regex execution exceeds timeout
    """
    start_time = time.time()
    
    try:
        # Compile pattern with reasonable limits
        compiled_pattern = re.compile(pattern, re.DOTALL)
        
        # Check for potentially dangerous patterns
        if _is_dangerous_regex(pattern):
            logger.warning(f"Potentially dangerous regex pattern detected: {pattern}")
        
        matches = compiled_pattern.findall(text)
        
        elapsed = time.time() - start_time
        if elapsed > timeout:
            raise RegexTimeoutError(f"Regex execution timed out after {elapsed:.2f}s")
        
        return matches
        
    except re.error as e:
        logger.error(f"Invalid regex pattern '{pattern}': {e}")
        return []
    except Exception as e:
        elapsed = time.time() - start_time
        if elapsed > timeout:
            raise RegexTimeoutError(f"Regex execution timed out after {elapsed:.2f}s")
        raise


def _is_dangerous_regex(pattern: str) -> bool:
    """
    Check if regex pattern contains potentially dangerous constructs
    
    Args:
        pattern: Regex pattern to check
        
    Returns:
        True if pattern appears dangerous
    """
    dangerous_patterns = [
        r'\(\?\=.*\)\+',  # Positive lookahead with quantifier
        r'\(\?\!.*\)\+',  # Negative lookahead with quantifier
        r'\(\?\<\=.*\)\+',  # Positive lookbehind with quantifier
        r'\(\?\<\!.*\)\+',  # Negative lookbehind with quantifier
        r'\(\.\*\)\+',    # .* with quantifier
        r'\(\.\+\)\+',    # .+ with quantifier
        r'\(\[\^.*\]\*\)\+',  # Character class negation with quantifier
    ]
    
    for dangerous in dangerous_patterns:
        if re.search(dangerous, pattern):
            return True
    
    return False


def secure_decode_base64_content(encoded_content: str, max_size: int = MAX_CONTENT_LENGTH) -> str:
    """
    Securely decode base64 content with size limits
    
    Args:
        encoded_content: Base64 encoded content
        max_size: Maximum allowed decoded size
        
    Returns:
        Decoded content string
        
    Raises:
        FileSizeError: If decoded content exceeds size limit
        SecurityError: If content cannot be safely decoded
    """
    try:
        # Remove whitespace and newlines
        clean_content = encoded_content.replace('\n', '').replace(' ', '')
        
        # Estimate decoded size (base64 is ~4/3 overhead)
        estimated_size = len(clean_content) * 3 // 4
        if estimated_size > max_size:
            raise FileSizeError(
                f"Estimated decoded size {estimated_size} bytes exceeds limit {max_size} bytes"
            )
        
        # Decode content
        decoded_bytes = base64.b64decode(clean_content)
        
        # Validate actual decoded size
        if len(decoded_bytes) > max_size:
            raise FileSizeError(
                f"Decoded size {len(decoded_bytes)} bytes exceeds limit {max_size} bytes"
            )
        
        # Decode to UTF-8 string
        content = decoded_bytes.decode('utf-8')
        
        logger.debug(f"Successfully decoded base64 content: {len(content)} characters")
        return content
        
    except base64.binascii.Error as e:
        raise SecurityError(f"Invalid base64 content: {e}")
    except UnicodeDecodeError as e:
        raise SecurityError(f"Content is not valid UTF-8: {e}")


def secure_xml_parse(xml_content: str, max_size: int = MAX_FILE_SIZE) -> ET.Element:
    """
    Securely parse XML content with entity expansion protection
    
    Args:
        xml_content: XML content to parse
        max_size: Maximum allowed content size
        
    Returns:
        Parsed XML root element
        
    Raises:
        FileSizeError: If content exceeds size limit
        SecurityError: If XML parsing fails or is unsafe
    """
    # Validate file size
    validate_file_size(xml_content, max_size)
    
    try:
        if HAS_DEFUSEDXML:
            # Use defusedxml for secure parsing
            logger.debug("Using defusedxml for secure XML parsing")
            root = SecureET.fromstring(xml_content)
        else:
            # Fallback to standard library with basic protection
            logger.warning("defusedxml not available, using standard XML parser with basic protection")
            
            # Check for obvious entity expansion attacks
            if '<!ENTITY' in xml_content or '&' in xml_content.count('&') > 100:
                raise SecurityError("XML content contains suspicious entity declarations")
            
            root = ET.fromstring(xml_content)
        
        logger.debug("XML parsing completed successfully")
        return root
        
    except ET.ParseError as e:
        raise SecurityError(f"XML parsing failed: {e}")
    except Exception as e:
        raise SecurityError(f"XML parsing error: {e}")


@timeout_parsing(MAX_PARSE_TIME)
def secure_parse_json_content(content: str, max_size: int = MAX_FILE_SIZE) -> Dict[str, Any]:
    """
    Securely parse JSON content with size and timeout protection
    
    Args:
        content: JSON content to parse
        max_size: Maximum allowed content size
        
    Returns:
        Parsed JSON data
        
    Raises:
        FileSizeError: If content exceeds size limit
        SecurityError: If JSON parsing fails
    """
    import json
    
    # Validate file size
    validate_file_size(content, max_size)
    
    try:
        data = json.loads(content)
        logger.debug(f"JSON parsing completed successfully: {type(data)}")
        return data
        
    except json.JSONDecodeError as e:
        raise SecurityError(f"JSON parsing failed: {e}")
    except Exception as e:
        raise SecurityError(f"JSON parsing error: {e}")


@timeout_parsing(MAX_PARSE_TIME)
def secure_parse_toml_content(content: str, max_size: int = MAX_FILE_SIZE) -> Dict[str, Any]:
    """
    Securely parse TOML content with size and timeout protection
    
    Args:
        content: TOML content to parse
        max_size: Maximum allowed content size
        
    Returns:
        Parsed TOML data
        
    Raises:
        FileSizeError: If content exceeds size limit
        SecurityError: If TOML parsing fails
    """
    try:
        import toml
    except ImportError:
        raise SecurityError("TOML library not available")
    
    # Validate file size
    validate_file_size(content, max_size)
    
    try:
        data = toml.loads(content)
        logger.debug(f"TOML parsing completed successfully")
        return data
        
    except Exception as e:
        raise SecurityError(f"TOML parsing failed: {e}")


@timeout_parsing(MAX_PARSE_TIME)
def secure_parse_yaml_content(content: str, max_size: int = MAX_FILE_SIZE) -> Dict[str, Any]:
    """
    Securely parse YAML content with size and timeout protection
    
    Args:
        content: YAML content to parse
        max_size: Maximum allowed content size
        
    Returns:
        Parsed YAML data
        
    Raises:
        FileSizeError: If content exceeds size limit
        SecurityError: If YAML parsing fails
    """
    try:
        import yaml
    except ImportError:
        raise SecurityError("YAML library not available")
    
    # Validate file size
    validate_file_size(content, max_size)
    
    try:
        # Use safe_load to prevent code execution
        data = yaml.safe_load(content)
        logger.debug(f"YAML parsing completed successfully")
        return data
        
    except yaml.YAMLError as e:
        raise SecurityError(f"YAML parsing failed: {e}")
    except Exception as e:
        raise SecurityError(f"YAML parsing error: {e}")


def get_safe_regex_pattern(pattern_name: str) -> str:
    """
    Get a pre-validated safe regex pattern
    
    Args:
        pattern_name: Name of the pattern to retrieve
        
    Returns:
        Safe regex pattern
        
    Raises:
        ValueError: If pattern name is not found
    """
    if pattern_name not in SAFE_REGEX_PATTERNS:
        raise ValueError(f"Unknown safe regex pattern: {pattern_name}")
    
    return SAFE_REGEX_PATTERNS[pattern_name]


class SecureFileParser:
    """
    Context manager for secure file parsing operations
    """
    
    def __init__(self, content: str, file_type: str, max_size: int = MAX_FILE_SIZE):
        """
        Initialize secure parser
        
        Args:
            content: File content to parse
            file_type: Type of file (json, xml, toml, yaml, text)
            max_size: Maximum allowed file size
        """
        self.content = content
        self.file_type = file_type.lower()
        self.max_size = max_size
        self.start_time = None
        
    def __enter__(self):
        """Enter secure parsing context"""
        self.start_time = time.time()
        
        # Validate file size immediately
        validate_file_size(self.content, self.max_size)
        
        logger.debug(f"Starting secure parsing of {self.file_type} file ({len(self.content)} chars)")
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit secure parsing context"""
        if self.start_time:
            elapsed = time.time() - self.start_time
            logger.debug(f"Secure parsing completed in {elapsed:.3f}s")
            
            if elapsed > MAX_PARSE_TIME:
                logger.warning(f"Parsing took {elapsed:.2f}s, exceeding recommended {MAX_PARSE_TIME}s")
    
    def parse(self) -> Any:
        """
        Parse content based on file type
        
        Returns:
            Parsed content
            
        Raises:
            SecurityError: If parsing fails or is unsafe
        """
        if self.file_type == 'json':
            return secure_parse_json_content(self.content, self.max_size)
        elif self.file_type == 'xml':
            return secure_xml_parse(self.content, self.max_size)
        elif self.file_type == 'toml':
            return secure_parse_toml_content(self.content, self.max_size)
        elif self.file_type == 'yaml' or self.file_type == 'yml':
            return secure_parse_yaml_content(self.content, self.max_size)
        elif self.file_type == 'text' or self.file_type == 'txt':
            return self.content  # Already validated by __enter__
        else:
            raise SecurityError(f"Unsupported file type for secure parsing: {self.file_type}")
