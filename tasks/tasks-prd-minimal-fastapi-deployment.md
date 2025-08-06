# Tasks: Minimal FastAPI Deployment

Based on PRD: `prd-minimal-fastapi-deployment.md`

## Relevant Files

- `src/api/main.py` - Main FastAPI application with health endpoint implementation
- `Dockerfile.api` - Container configuration for the FastAPI application
- `helm/astrid/Chart.yaml` - Helm chart metadata and version information
- `helm/astrid/values.yaml` - Configuration values for image repository, tag, and service settings
- `helm/astrid/templates/api-deployment.yaml` - Kubernetes Deployment manifest for the API service
- `helm/astrid/templates/api-service.yaml` - Kubernetes Service manifest for internal cluster communication
- `requirements.txt` - Python dependencies for the FastAPI application

### Notes

- This is the first deployment to the Kubernetes cluster, so no existing infrastructure patterns to follow
- Focus on establishing deployment foundation and validating infrastructure setup
- All files are new creation - no existing codebase modifications needed
- Use standard Kubernetes and Helm conventions for manifest structure
- Container registry integration with DigitalOcean requires proper image naming and authentication

## Tasks

- [x] 1.0 Create FastAPI Application Structure
  - [x] 1.1 Create src/api directory structure
  - [x] 1.2 Create requirements.txt with fastapi and uvicorn dependencies
  - [x] 1.3 Implement main.py with FastAPI app and /health endpoint
  - [x] 1.4 Test the application locally to ensure it runs and responds correctly
- [ ] 2.0 Implement Docker Containerization
  - [ ] 2.1 Create Dockerfile.api with python:3.11-slim base image
  - [ ] 2.2 Configure Docker build process for dependency installation
  - [ ] 2.3 Set up port exposure and uvicorn command execution
  - [ ] 2.4 Build and test Docker image locally
- [ ] 3.0 Create Helm Chart Foundation
  - [ ] 3.1 Create helm/astrid directory structure
  - [ ] 3.2 Create Chart.yaml with chart metadata
  - [ ] 3.3 Create values.yaml with image configuration
  - [ ] 3.4 Create templates directory for Kubernetes manifests
- [ ] 4.0 Configure Kubernetes Deployment Resources
  - [ ] 4.1 Create api-deployment.yaml template with Deployment resource
  - [ ] 4.2 Create api-service.yaml template with ClusterIP Service
  - [ ] 4.3 Configure image references and labels for proper pod selection
  - [ ] 4.4 Validate Helm chart syntax and template rendering
- [ ] 5.0 Deploy and Verify Application
  - [ ] 5.1 Build and push Docker image to DigitalOcean Container Registry
  - [ ] 5.2 Install Helm chart to Kubernetes cluster
  - [ ] 5.3 Verify pod and service creation using kubectl
  - [ ] 5.4 Test health endpoint using port forwarding and curl