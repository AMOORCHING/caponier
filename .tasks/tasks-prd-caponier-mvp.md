# Tasks: Caponier MVP - GitHub Repository Security Analysis Platform

Based on PRD: `prd-caponier-mvp.md`

## Relevant Files

- `src/api/main.py` - Extend existing FastAPI application with security analysis endpoints and CORS configuration (UPDATED)
- `src/api/models.py` - Pydantic models for API requests, responses, and vulnerability data structures (CREATED)
- `src/api/security/` - Security analysis module directory
- `src/api/security/repository_analyzer.py` - Repository validation and metadata extraction service (CREATED)
- `src/api/security/analyzer.py` - Core security analysis engine and orchestration logic
- `src/api/security/vulnerability_scanner.py` - Vulnerability detection using NVD API integration (CREATED)
- `src/api/security/cve_lookup.py` - Advanced CVE lookup with multi-tier caching and version matching (CREATED)
- `src/api/security/circuit_breaker.py` - Circuit breaker pattern for external service resilience (CREATED)
- `src/api/security/vulnerability_enrichment.py` - Advanced vulnerability data enrichment with CVSS analysis (CREATED)
- `src/api/security/dependency_parser.py` - Package manifest file parsing for different ecosystems (UPDATED - Node.js + Python + Rust + Java + Smart Discovery)
- `src/api/security/scoring.py` - Security scoring algorithm implementation
- `src/api/security/github_client.py` - GitHub API client for repository access and metadata (CREATED)
- `src/api/jobs/` - Background job processing directory
- `src/api/jobs/worker.py` - Celery/RQ worker configuration and task definitions
- `src/api/jobs/tasks.py` - Background task implementations for analysis processing
- `src/api/websocket/` - WebSocket handlers directory
- `src/api/websocket/progress.py` - Real-time progress update handlers
- `src/api/utils/` - Utility functions directory
- `src/api/utils/validators.py` - URL validation and comprehensive repository analysis (UPDATED)
- `src/api/utils/exceptions.py` - Custom exception classes for error handling (CREATED)
- `src/frontend/` - React/Next.js frontend application directory
- `src/frontend/components/` - React components for analysis interface
- `src/frontend/pages/` - Next.js pages for single-page application
- `src/frontend/hooks/` - Custom React hooks for WebSocket and API integration
- `docker-compose.yml` - Local development environment with Redis and worker services
- `requirements.txt` - Updated Python dependencies including security analysis libraries (UPDATED - added TOML/YAML support)
- `requirements-dev.txt` - Development-only dependencies for testing and code quality (CREATED)
- `.dockerignore` - Docker build optimization and security (CREATED)
- `.env.example` - Environment configuration template (CREATED)
- `helm/astrid/values.yaml` - Updated Helm values for Redis and worker deployment
- `helm/astrid/templates/redis-deployment.yaml` - Redis deployment for job queue
- `helm/astrid/templates/worker-deployment.yaml` - Background worker deployment

### Notes

- Build upon existing FastAPI application structure at `src/api/main.py`
- Leverage existing Docker and Helm deployment infrastructure
- Use Redis for job queue management and temporary result storage
- Implement WebSocket connections for real-time progress updates
- Design API endpoints to be RESTful and easily extensible
- Target analysis completion time of under 2 minutes for typical repositories

## Tasks

- [x] 1.0 Extend FastAPI Application with Security Analysis Infrastructure
  - [x] 1.1 Create Pydantic models for analysis requests, responses, and vulnerability data structures
  - [x] 1.2 Add new API endpoints: POST /analyze, GET /analysis/{job_id}, GET /analysis/{job_id}/progress
  - [x] 1.3 Implement URL validation middleware for GitHub repository URLs
  - [x] 1.4 Create custom exception classes for analysis errors and API responses
  - [x] 1.5 Add CORS configuration for frontend integration
  - [x] 1.6 Update requirements.txt with security analysis dependencies (requests, redis, celery, websockets)

- [x] 2.0 Implement GitHub Repository Analysis and Dependency Parsing
  - [x] 2.1 Create GitHub API client with rate limiting and authentication handling
  - [x] 2.2 Implement repository validation and metadata extraction (last commit, contributors, issues)
  - [x] 2.3 Build dependency parser for package.json (Node.js/npm ecosystem)
  - [x] 2.4 Build dependency parser for requirements.txt (Python/pip ecosystem)
  - [x] 2.5 Build dependency parser for Cargo.toml (Rust ecosystem)
  - [x] 2.6 Build dependency parser for pom.xml and build.gradle (Java ecosystem)
  - [x] 2.7 Implement smart dependency file detection across repository structure
  - [x] 2.8 Add error handling for private repositories and invalid URLs

- [x] 3.0 Build Vulnerability Scanning and NVD Integration
  - [x] 3.1 Integrate with National Vulnerability Database (NVD) API v2.0
  - [x] 3.2 Implement CVE lookup by package name and version with caching
  - [x] 3.3 Filter vulnerabilities to Critical and High severity only
  - [x] 3.4 Add rate limiting and retry logic for external API calls
  - [x] 3.5 Map vulnerabilities to CVE identifiers with detailed descriptions
  - [x] 3.6 Implement circuit breaker pattern for external service resilience
  - [x] 3.7 Add vulnerability data enrichment with CVSS scores and impact details

- [x] 4.0 Develop Security Scoring Algorithm and Reporting
  - [x] 4.1 Implement weighted scoring: Critical vulnerabilities = 10 points, High = 5 points
  - [x] 4.2 Add maintenance health scoring based on last commit date and contributor activity
  - [x] 4.3 Calculate overall security score (0-100 scale) with component breakdown
  - [x] 4.4 Generate actionable recommendations (package updates, security practices)
  - [x] 4.5 Add comparative context generation ("Better than X% of similar repositories")
  - [x] 4.6 Create detailed analysis report structure with vulnerability lists and metadata
  - [x] 4.7 Implement security badge generation for embeddable widgets

- [ ] 5.0 Create Asynchronous Job Processing with Redis and Background Workers
  - [x] 5.1 Set up Redis connection and configuration for job queue management
  - [x] 5.2 Implement Celery worker configuration with task routing
  - [x] 5.3 Create background task for complete repository security analysis
  - [x] 5.4 Add job status tracking (pending, in_progress, completed, failed)
  - [x] 5.5 Implement analysis timeout handling (5-minute maximum)
  - [x] 5.6 Create job result storage with 24-hour expiration
  - [ ] 5.7 Add error handling and retry logic for failed analysis tasks
  - [ ] 5.8 Implement concurrent job processing without UI blocking

- [ ] 6.0 Implement Real-time Progress Updates via WebSocket
  - [ ] 6.1 Set up WebSocket connection handling in FastAPI
  - [ ] 6.2 Create progress update events for analysis stages
  - [ ] 6.3 Implement progress broadcasting to connected clients
  - [ ] 6.4 Add granular progress messages ("Scanning dependencies...", "Checking vulnerabilities...")
  - [ ] 6.5 Handle WebSocket disconnections and reconnection logic
  - [ ] 6.6 Ensure progress updates are delivered within 2 seconds of status changes
  - [ ] 6.7 Add WebSocket authentication and job ID validation

- [ ] 7.0 Build Frontend Single-Page Application with Next.js
  - [ ] 7.1 Initialize Next.js project with TypeScript and Tailwind CSS
  - [ ] 7.2 Create main analysis page with URL input form and clean, modern design
  - [ ] 7.3 Implement repository URL validation and error display
  - [ ] 7.4 Build real-time progress display component with WebSocket integration
  - [ ] 7.5 Create analysis results display with security score and vulnerability list
  - [ ] 7.6 Add responsive design for desktop and mobile devices
  - [ ] 7.7 Implement loading states and error handling throughout the application
  - [ ] 7.8 Add social sharing buttons with pre-populated text for results

- [ ] 8.0 Integrate Results Display, Sharing, and Export Functionality
  - [ ] 8.1 Design and implement vulnerability details display with CVE links
  - [ ] 8.2 Create shareable URLs for analysis results with 24-hour persistence
  - [ ] 8.3 Add social media sharing integration (Twitter, LinkedIn) with key findings
  - [ ] 8.4 Implement JSON export functionality for programmatic access
  - [ ] 8.5 Create embeddable security badge widget with HTML/markdown snippets
  - [ ] 8.6 Add copy-to-clipboard functionality for sharing URLs and badges
  - [ ] 8.7 Implement analysis result caching to improve performance for shared links

- [ ] 9.0 Update Deployment Configuration for Production Readiness
  - [ ] 9.1 Add Redis deployment configuration to Helm chart
  - [ ] 9.2 Create Celery worker deployment manifest for background processing
  - [ ] 9.3 Update API deployment with environment variables for external APIs
  - [ ] 9.4 Add frontend build process to Docker container
  - [ ] 9.5 Configure ingress for external access with proper routing
  - [ ] 9.6 Update values.yaml with production configuration and resource limits
  - [ ] 9.7 Add health checks and monitoring endpoints for Kubernetes probes
  - [ ] 9.8 Create docker-compose.yml for local development environment

## Relevant Files
- `src/api/main.py` - Main FastAPI application with health check and analysis endpoints
- `src/api/models.py` - Pydantic models for API requests/responses, including VulnerabilityData, AnalysisResult, SecurityScore
- `src/api/utils/validators.py` - Repository URL validation with GitHub API verification
- `src/api/utils/exceptions.py` - Custom exception hierarchy for structured error handling
- `src/api/security/github_client.py` - GitHub API client with rate limiting, caching, and error handling
- `src/api/security/repository_analyzer.py` - Repository validation and metadata extraction service
- `src/api/security/dependency_parser.py` - Multi-ecosystem dependency parsing with smart file discovery
- `src/api/security/vulnerability_scanner.py` - NVD API integration for CVE lookup and vulnerability scanning
- `src/api/security/cve_lookup.py` - Advanced CVE lookup with multi-tier caching and version matching
- `src/api/security/circuit_breaker.py` - Circuit breaker pattern for external service resilience
- `src/api/security/vulnerability_enrichment.py` - CVSS analysis and impact details for vulnerabilities
- `src/api/security/scoring.py` - Security scoring algorithm with weighted vulnerability scoring and reporting
- `src/api/security/reporting.py` - Detailed analysis report structure with multiple export formats
- `requirements.txt` - Python dependencies with version constraints
- `requirements-dev.txt` - Development dependencies for testing and code quality
- `Dockerfile.api` - Docker configuration for API service deployment