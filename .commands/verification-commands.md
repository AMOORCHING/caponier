# Kubernetes Deployment Verification Commands

## After running `helm install astrid ./helm/astrid`, use these commands to verify the deployment:

### 1. Verify Pod Creation and Status

```bash
# Check all pods
kubectl get pods

# Expected output should show:
# NAME                         READY   STATUS    RESTARTS   AGE
# astrid-api-xxxxxxxxx-xxxxx   1/1     Running   0          30s
```

```bash
# Check pods with specific labels
kubectl get pods -l app.kubernetes.io/name=astrid

# Get detailed pod information
kubectl describe pod -l app.kubernetes.io/component=api
```

### 2. Verify Service Creation

```bash
# Check all services
kubectl get services

# Expected output should include:
# NAME                TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)   AGE
# astrid-api-service  ClusterIP   10.245.xxx.xxx  <none>        80/TCP    30s
```

```bash
# Get detailed service information
kubectl get service astrid-api-service -o wide
kubectl describe service astrid-api-service
```

### 3. Check Deployment Status

```bash
# Verify the deployment
kubectl get deployments
kubectl describe deployment astrid-api
```

### 4. View Application Logs

```bash
# Check application logs
kubectl logs -l app.kubernetes.io/component=api

# Expected logs should show FastAPI/uvicorn startup messages:
# INFO:     Started server process [1]
# INFO:     Waiting for application startup.
# INFO:     Application startup complete.
# INFO:     Uvicorn running on http://0.0.0.0:80 (Press CTRL+C to quit)
```

### 5. Check Events for Any Issues

```bash
# View recent events
kubectl get events --sort-by=.metadata.creationTimestamp

# Look for any error events related to image pulling, pod scheduling, etc.
```

## Success Criteria Checklist:

- ✅ **Pod Status**: One pod with name `astrid-api-*` in `Running` state
- ✅ **Service Status**: Service `astrid-api-service` with ClusterIP assigned
- ✅ **Pod Ready**: Pod shows `1/1` in the READY column
- ✅ **No Restart**: RESTARTS column should be `0` for new deployment
- ✅ **Logs**: Application logs show successful FastAPI startup
- ✅ **No Error Events**: No error events in the cluster events

## Common Issues and Solutions:

### If Pod is in `ImagePullBackOff` or `ErrImagePull`:
- Verify image was pushed to registry: `docker pull registry.digitalocean.com/astrid-registry/astrid-api:latest`
- Check image pull secrets are configured
- Verify registry authentication: `doctl registry login`

### If Pod is in `Pending` state:
- Check node resources: `kubectl describe nodes`
- Verify cluster has sufficient capacity

### If Pod is in `CrashLoopBackOff`:
- Check application logs: `kubectl logs -l app.kubernetes.io/component=api --previous`
- Verify health check endpoint is working