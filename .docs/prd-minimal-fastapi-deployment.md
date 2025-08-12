# Product Requirements Document: Minimal FastAPI Deployment

## Introduction/Overview

This PRD defines the requirements for deploying a minimal FastAPI application to the DigitalOcean Kubernetes cluster as the first step in building the Astrid distributed data pipeline platform. This deployment serves as a "tracer bullet" to validate our core infrastructure setup, container registry integration, and Helm workflow before adding complexity with additional services, database connectivity, and business logic.

The feature involves creating a simple health check endpoint that will serve as both an infrastructure validation tool and a permanent monitoring endpoint for future Kubernetes probes and Prometheus monitoring.

## Goals

1. **Validate Infrastructure Setup**: Confirm that the DigitalOcean Kubernetes cluster, container registry, and Helm deployment workflow are properly configured and functional.
2. **Establish Deployment Foundation**: Create a repeatable, fast deployment process using Helm that can be used for future services in the Astrid microservices platform.
3. **Implement Permanent Health Monitoring**: Deploy a `/health` endpoint that will serve as the foundation for Kubernetes liveness/readiness probes and future monitoring systems.
4. **Enable Development Workflow**: Provide a working deployment that allows manual testing and debugging using standard CLI tools (kubectl, curl, helm).

## User Stories

1. **As a developer**, I want to deploy a minimal API to Kubernetes so that I can validate my infrastructure setup before building complex features.

2. **As a developer**, I want a permanent `/health` endpoint so that I can monitor service availability and use it for future Kubernetes health checks.

3. **As a developer**, I want a fast and repeatable Helm deployment process so that I can tear down and redeploy services reliably during development.

4. **As a future monitoring system (Prometheus)**, I want a standardized `/health` endpoint so that I can track service availability and operational status.

5. **As Kubernetes**, I want access to a health endpoint so that I can perform liveness and readiness checks on the API pods.

## Functional Requirements

### Application Code Requirements
1. The system must provide a FastAPI application with a single endpoint at `GET /health`.
2. The `/health` endpoint must return a JSON response: `{"status": "ok", "service": "astrid-api"}`.
3. The application must not require any database connections or external dependencies for this initial version.
4. The application must be located at `src/api/main.py` in the project structure.

### Containerization Requirements
5. The system must include a `Dockerfile.api` that uses `python:3.11-slim` as the base image.
6. The container must install the required dependencies: `fastapi` and `uvicorn`.
7. The container must expose port 80.
8. The container must run the application using uvicorn.
9. The Docker image must be buildable and pushable to the DigitalOcean Container Registry.

### Kubernetes Deployment Requirements
10. The system must include a Helm chart located in `helm/astrid/` directory.
11. The Helm chart must include a `values.yaml` file to manage image repository and tag configuration.
12. The system must include a `templates/api-deployment.yaml` manifest that:
    - Creates a Deployment resource
    - Specifies exactly 1 replica
    - Pulls the correct image from DigitalOcean Container Registry
    - Uses image configuration from values.yaml
13. The system must include a `templates/api-service.yaml` manifest that:
    - Creates a Service resource
    - Uses ClusterIP type (internal only)
    - Selects pods from the api-deployment
    - Exposes port 80

### Deployment and Verification Requirements
14. The system must be deployable using the command: `helm install astrid ./helm/astrid`
15. After deployment, `kubectl get pods` must show one pod with a name like `astrid-api-*` in Running state.
16. After deployment, `kubectl get service` must show a service named `astrid-api-service` with a ClusterIP.
17. The deployed service must be accessible via port forwarding using: `kubectl port-forward svc/astrid-api-service 8080:80`
18. The health endpoint must respond correctly when accessed via: `curl http://localhost:8080/health`

## Non-Goals (Out of Scope)

1. **Database Integration**: No database connections, PostgreSQL setup, or data persistence (planned for PRD #2).
2. **Authentication/Authorization**: No user authentication, API keys, or access control mechanisms.
3. **External Service Integration**: No message bus, external APIs, or third-party service connections.
4. **Production Security**: No HTTPS, security headers, or production-grade security configurations.
5. **Horizontal Scaling**: No auto-scaling, multiple replicas, or load balancing configuration.
6. **Ingress Configuration**: No external access via ingress controllers or load balancers.
7. **Monitoring/Logging Infrastructure**: No Prometheus setup, log aggregation, or alerting systems.
8. **Automated CI/CD**: No automated builds, tests, or deployment pipelines.
9. **Error Handling**: No comprehensive error responses, retry mechanisms, or failure recovery.
10. **Performance Optimization**: No performance tuning, caching, or optimization requirements.

## Design Considerations

### Application Structure
- Use standard FastAPI patterns for minimal setup
- Follow Python project structure conventions with `src/api/` directory
- Keep the application stateless and dependency-free for this iteration

### Container Design
- Use slim Python base image for smaller container size
- Minimize installed packages to reduce attack surface
- Follow container best practices for port exposure and command execution

### Kubernetes Resources
- Use Deployment for pod management and declarative updates
- Use ClusterIP service type to maintain internal-only access
- Structure Helm templates for easy extension and configuration management

## Technical Considerations

### Dependencies
- **DigitalOcean Container Registry**: Must be configured and accessible for image pushing/pulling
- **DigitalOcean Kubernetes Cluster**: Must be running and accessible via kubectl
- **Helm**: Must be installed and configured to deploy to the target cluster
- **Docker**: Required for building and pushing container images

### Image Management
- Images should be tagged consistently for version tracking
- Use DigitalOcean Container Registry URL format in Helm values
- Consider image pull policies for development workflow

### Development Workflow Integration
- Deployment process should be fast enough for rapid iteration (target: minutes, not hours)
- Manual debugging capabilities must be preserved via kubectl commands
- Port forwarding should work reliably for local testing

## Success Metrics

### Primary Success Criteria
1. **Deployment Success Rate**: 100% successful deployment when infrastructure is properly configured
2. **Deployment Speed**: Complete deployment process (build, push, deploy) completes in under 5 minutes
3. **Health Endpoint Reliability**: `/health` endpoint responds with correct JSON 100% of the time when service is running
4. **Manual Testing Workflow**: Port forwarding and curl testing workflow works reliably for development validation

### Infrastructure Validation Metrics
1. **Container Registry Integration**: Successful image push and pull operations
2. **Kubernetes Cluster Functionality**: Pods reach Running state consistently
3. **Helm Workflow**: Clean installation and uninstallation without errors
4. **Service Discovery**: ClusterIP service correctly routes traffic to pods

## Open Questions

1. **Image Versioning Strategy**: Should we use semantic versioning, git commit hashes, or timestamps for image tags in this development phase?

2. **Resource Limits**: Should we set CPU/memory limits on the deployment even for this minimal service, or keep it unlimited for simplicity?

3. **Health Check Configuration**: Should we implement Kubernetes liveness/readiness probes pointing to the `/health` endpoint in this PRD, or defer to a future iteration?

4. **Namespace Strategy**: Should the deployment target the `default` namespace or create a dedicated namespace like `astrid`?

5. **Helm Release Naming**: Should we use a consistent naming convention for Helm releases across all future services (e.g., `astrid-api`, `astrid-worker`, etc.)?

6. **Development vs Production Values**: Should we create separate values files for different environments now, or keep a single values.yaml for this development-focused deployment?

---

**Document Version**: 1.0  
**Target Implementation**: Development/Staging Environment  
**Priority**: High (Infrastructure Foundation)  
**Estimated Implementation Time**: 1-2 development sessions