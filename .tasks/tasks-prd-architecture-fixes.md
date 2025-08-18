# Product Requirements Document: Code Quality & Architecture Refactoring

## Introduction/Overview

This PRD addresses code quality issues, architectural anti-patterns, and technical debt identified in the codebase review. The focus is on refactoring monolithic modules, eliminating custom implementations where mature libraries exist, and establishing consistent coding conventions throughout the project.

The goal is to create a maintainable, testable codebase that follows Python best practices and reduces cognitive load for contributors.

## Goals

1. **Eliminate Technical Debt**: Refactor monolithic modules and replace custom implementations with proven libraries.
2. **Improve Code Maintainability**: Break down large modules into focused, single-responsibility components.
3. **Standardize Dependencies**: Consolidate HTTP client usage and establish consistent library choices.
4. **Enhance Parser Robustness**: Replace fragile regex-based parsing with proper structured file parsers.
5. **Reduce Cognitive Load**: Create clear separation of concerns and improve code readability for contributors.

## Task List

### 1. Module Decomposition and Organization
- [ ] **1.1 Refactor dependency_parser.py into separate parser modules**
  - [x] Create `src/api/parsers/` directory structure
  - [x] Create base parser interface (`base.py`)
  - [x] Extract Maven parser (`maven.py`)
  - [ ] Extract Gradle parser (`gradle.py`)
  - [x] Extract NPM parser (`npm.py`)
  - [x] Extract Python parser (`python.py`)
  - [ ] Extract Rust parser (`rust.py`)
  - [ ] Extract Go parser (`go.py`)
  - [ ] Extract PHP parser (`php.py`)
  - [ ] Extract Ruby parser (`ruby.py`)
  - [x] Create parser factory (`factory.py`)
  - [ ] Update imports and references

- [ ] **1.2 Split main.py into focused modules**
  - [ ] Create `src/api/routes/` directory
  - [ ] Extract analysis routes (`analysis.py`)
  - [ ] Extract health check routes (`health.py`)
  - [ ] Create `src/api/services/` directory
  - [ ] Extract business logic (`analysis_service.py`)
  - [ ] Extract GitHub integration (`github_service.py`)
  - [ ] Update main.py to use new structure

- [ ] **1.3 Implement dependency injection**
  - [ ] Create configuration management module
  - [ ] Implement service container pattern
  - [ ] Update route handlers to use dependency injection

### 2. Custom Implementation Replacement
- [ ] **2.1 Replace custom timeout manager**
  - [ ] Remove custom timeout manager implementation
  - [ ] Integrate Celery's built-in time limits
  - [ ] Update task configurations
  - [ ] Test timeout behavior

- [ ] **2.2 Replace custom circuit breaker**
  - [ ] Install `pybreaker` library
  - [ ] Remove custom circuit breaker implementation
  - [ ] Implement pybreaker-based circuit breaker
  - [ ] Update service integrations
  - [ ] Test circuit breaker behavior

- [ ] **2.3 Standardize HTTP client usage**
  - [ ] Remove `requests` library dependency
  - [ ] Migrate all HTTP calls to `httpx`
  - [ ] Implement consistent connection pooling
  - [ ] Update timeout configurations
  - [ ] Test HTTP client behavior

### 3. Dependency File Parsing Improvements
- [ ] **3.1 Implement proper XML parsing**
  - [ ] Install `lxml` library
  - [ ] Replace regex-based pom.xml parsing
  - [ ] Implement proper XML parsing with error handling
  - [ ] Test Maven dependency detection accuracy

- [ ] **3.2 Implement proper JSON parsing**
  - [ ] Replace regex-based package.json parsing
  - [ ] Implement proper JSON parsing with validation
  - [ ] Handle package-lock.json parsing
  - [ ] Test NPM dependency detection accuracy

- [ ] **3.3 Implement YAML parsing**
  - [ ] Install `PyYAML` library
  - [ ] Implement GitHub Actions workflow parsing
  - [ ] Implement other YAML-based configuration parsing
  - [ ] Test YAML parsing accuracy

- [ ] **3.4 Implement lock file parsing**
  - [ ] Install specialized parsing libraries
  - [ ] Implement Pipfile.lock parsing
  - [ ] Implement other lock file formats
  - [ ] Test lock file parsing accuracy

### 4. Error Handling and Logging Improvements
- [ ] **4.1 Implement structured error handling**
  - [ ] Create custom exception hierarchy
  - [ ] Implement parser-specific exceptions
  - [ ] Add error boundaries for parsing failures
  - [ ] Test error handling behavior

- [ ] **4.2 Implement consistent logging**
  - [ ] Standardize logging patterns across modules
  - [ ] Implement structured logging
  - [ ] Add logging configuration
  - [ ] Test logging behavior

### 5. Code Quality Standards
- [ ] **5.1 Implement code formatting**
  - [ ] Install and configure `black` with line length 88
  - [ ] Format all Python files
  - [ ] Add pre-commit hooks
  - [ ] Test formatting consistency

- [ ] **5.2 Implement import organization**
  - [ ] Install and configure `isort` with black profile
  - [ ] Organize imports across all files
  - [ ] Add import sorting to pre-commit hooks
  - [ ] Test import organization

- [ ] **5.3 Implement type hints**
  - [ ] Install and configure `mypy` in strict mode
  - [ ] Add type hints to all functions and classes
  - [ ] Fix type checking errors
  - [ ] Test type checking compliance

- [ ] **5.4 Implement comprehensive docstrings**
  - [ ] Choose docstring style (Google or NumPy)
  - [ ] Add docstrings to all public functions and classes
  - [ ] Validate docstring completeness
  - [ ] Test documentation generation

### 6. Testing and Validation
- [ ] **6.1 Create comprehensive test suite**
  - [ ] Write unit tests for all parser modules
  - [ ] Write integration tests for refactored components
  - [ ] Achieve >90% test coverage
  - [ ] Test backward compatibility

- [ ] **6.2 Performance validation**
  - [ ] Benchmark parsing performance
  - [ ] Validate no performance regression
  - [ ] Test with real repository data
  - [ ] Document performance metrics

## Relevant Files
- `src/api/parsers/__init__.py` - Package initialization and exports
- `src/api/parsers/base.py` - Abstract base class and data structures for dependency parsers
- `src/api/parsers/factory.py` - Factory pattern for managing parser implementations
- `src/api/parsers/maven.py` - Maven pom.xml parser using lxml
- `src/api/parsers/npm.py` - NPM package.json and package-lock.json parser
- `src/api/parsers/python.py` - Python dependency files parser (requirements.txt, Pipfile, etc.)

## User Stories

1. **As a developer**, I want focused, single-purpose modules so that I can understand and modify code without navigating complex, multi-responsibility files.

2. **As a contributor**, I want consistent coding patterns so that I can apply the same mental models across the entire codebase.

3. **As a maintainer**, I want reliable parsing logic so that minor changes in dependency file formats don't break the analysis functionality.

4. **As a code reviewer**, I want clear module boundaries so that I can review changes with confidence about their impact scope.

5. **As a new team member**, I want well-structured code so that I can become productive quickly without extensive codebase archaeology.

6. **As a system integrator**, I want robust dependency parsing so that the analysis results are reliable across different project types and configurations.

## Functional Requirements

### Module Decomposition and Organization
1. The system must refactor `src/api/security/dependency_parser.py` into separate parser modules for each file type (Maven, Gradle, NPM, etc.).
2. Each parser module must implement a common interface with standardized input/output contracts.
3. The system must create a parser factory or registry pattern to manage different parser implementations.
4. The main API module (`src/api/main.py`) must be split into separate route handlers, business logic, and configuration modules.
5. The system must implement proper dependency injection for configuration and external services.

### Custom Implementation Replacement
6. The system must replace the custom timeout manager with Celery's built-in time limits and monitoring.
7. The system must replace the custom circuit breaker with the `pybreaker` library or similar proven implementation.
8. The system must implement proper error handling and retry logic using established patterns.
9. The system must remove duplicate HTTP client implementations and standardize on a single library.

### Dependency File Parsing Improvements
10. The system must implement proper XML parsing for `pom.xml` files using `lxml` or `xml.etree.ElementTree`.
11. The system must implement proper JSON parsing for `package.json` and `package-lock.json` files.
12. The system must implement YAML parsing for GitHub Actions and other YAML-based configuration files.
13. The system must implement lock file parsing using specialized libraries where available (e.g., `pipfile-parse` for Pipfile.lock).
14. The system must maintain backward compatibility with existing dependency detection while improving accuracy.

### HTTP Client Standardization
15. The system must standardize on `httpx` for all HTTP requests throughout the application.
16. The system must remove the `requests` library dependency and migrate all usage to `httpx`.
17. The system must implement consistent connection pooling and timeout configuration.
18. The system must implement proper async/sync patterns based on the calling context (FastAPI vs Celery).

### Error Handling and Logging Improvements
19. The system must implement structured error handling with custom exception types for different failure modes.
20. The system must implement consistent logging patterns across all modules.
21. The system must implement proper error boundaries that prevent parsing failures from affecting other analyses.
22. The system must implement graceful degradation when specific parsers fail.

### Code Quality Standards
23. The system must implement consistent code formatting using `black` with line length 88.
24. The system must implement import organization using `isort` with profile "black".
25. The system must implement type hints throughout the codebase with `mypy` strict mode compliance.
26. The system must implement comprehensive docstrings following Google or NumPy style conventions.

## Non-Goals (Out of Scope)

- Complete rewrite of the analysis logic (incremental improvement focus)
- Implementation of new parser types (focus on improving existing parsers)
- Performance optimization (functionality and maintainability focus)
- Database schema changes (no database in current architecture)
- Frontend refactoring (no frontend currently exists)

## Technical Considerations

- Use `lxml` for XML parsing with proper error handling and security configurations
- Implement parser interface using ABC (Abstract Base Classes) for clear contracts
- Consider `pydantic` for configuration management and validation
- Use dependency injection pattern for testability and modularity
- Implement parser caching to avoid re-parsing the same files
- Consider factory pattern for parser selection based on file types

## Design Considerations

### Parser Architecture
```python
class DependencyParser(ABC):
    @abstractmethod
    def parse(self, file_content: str) -> List[Dependency]:
        pass
    
    @abstractmethod
    def supported_files(self) -> List[str]:
        pass
```

### Module Structure
```
src/api/
├── parsers/
│   ├── __init__.py
│   ├── base.py          # Parser interface
│   ├── maven.py         # Maven pom.xml parser
│   ├── gradle.py        # Gradle build files
│   ├── npm.py           # NPM package.json
│   └── factory.py       # Parser selection logic
├── routes/
│   ├── __init__.py
│   ├── analysis.py      # Analysis endpoints
│   └── health.py        # Health check endpoints
├── services/
│   ├── __init__.py
│   ├── github.py        # GitHub API integration
│   └── analysis.py      # Business logic
└── config.py            # Configuration management
```

### Error Handling Strategy
- Parser-specific exceptions for different failure modes
- Graceful degradation when individual parsers fail
- Structured error reporting for debugging and monitoring
- Clear separation between user errors and system errors

## Success Metrics

1. **Code Complexity**: Reduce cyclomatic complexity of main modules by >50%
2. **Test Coverage**: Achieve >90% test coverage on refactored modules
3. **Parsing Accuracy**: Improve dependency detection accuracy by >20% across test repositories
4. **Maintainability**: Reduce time to implement new parser from 2 days to 4 hours
5. **Code Quality**: Achieve 100% mypy type checking compliance and zero linting errors

## Open Questions

1. **Parser Selection**: Should parser selection be automatic based on file detection or explicit based on repository type analysis?
2. **Backwards Compatibility**: How should we handle edge cases where the new parsers detect different dependencies than the regex-based approach?
3. **Performance Impact**: Should we implement parser result caching to avoid performance regression from more thorough parsing?
4. **Configuration Strategy**: Should parser configuration (timeouts, limits) be global or per-parser-type?
5. **Migration Strategy**: Should this refactoring be done incrementally (parser by parser) or as a complete replacement?

---

**Document Version**: 1.0  
**Priority**: Medium (Improves maintainability and reliability)  
**Estimated Implementation Time**: 6-8 development sessions  
**Dependencies**: Should be implemented after testing infrastructure and critical security fixes