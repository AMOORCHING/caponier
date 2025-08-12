# Helm Deployment Commands for DigitalOcean Kubernetes

## Steps to deploy the Astrid API to your DigitalOcean Kubernetes cluster:

### Prerequisites:
1. **Install kubectl and configure it for your DigitalOcean cluster:**
   ```bash
   # Install kubectl if not already installed
   brew install kubectl
   
   # Get your cluster credentials from DigitalOcean
   doctl kubernetes cluster kubeconfig save YOUR-CLUSTER-NAME
   ```

2. **Verify cluster connection:**
   ```bash
   kubectl cluster-info
   kubectl get nodes
   ```

### Deployment Commands:

1. **Install the Helm chart:**
   ```bash
   helm install astrid ./helm/astrid
   ```

2. **Alternative: Install with custom values or override registry:**
   ```bash
   helm install astrid ./helm/astrid \
     --set api.image.repository=registry.digitalocean.com/astrid-registry/astrid-api \
     --set api.image.tag=0.1.0
   ```

3. **Check deployment status:**
   ```bash
   helm status astrid
   helm list
   ```

### Verification Commands:

1. **Check pods are running:**
   ```bash
   kubectl get pods
   kubectl get pods -l app.kubernetes.io/name=astrid
   ```

2. **Check service is created:**
   ```bash
   kubectl get services
   kubectl get service astrid-api-service
   ```

3. **View pod logs:**
   ```bash
   kubectl logs -l app.kubernetes.io/component=api
   ```

4. **Test the health endpoint:**
   ```bash
   # Port forward to access the service locally
   kubectl port-forward svc/astrid-api-service 8080:80
   
   # In another terminal, test the endpoint
   curl http://localhost:8080/health
   ```

### Troubleshooting:

1. **Check pod status if not running:**
   ```bash
   kubectl describe pod -l app.kubernetes.io/component=api
   ```

2. **Check events:**
   ```bash
   kubectl get events --sort-by=.metadata.creationTimestamp
   ```

3. **Uninstall if needed:**
   ```bash
   helm uninstall astrid
   ```

### Expected Results:
- ✅ One pod named `astrid-api-*` in `Running` state
- ✅ One service named `astrid-api-service` with `ClusterIP`
- ✅ Health endpoint responding with `{"status": "ok", "service": "astrid-api"}`