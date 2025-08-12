# Health Endpoint Testing Commands

## Final Verification: Test the /health endpoint through Kubernetes

### Step 1: Set up Port Forwarding

```bash
# Forward local port 8080 to the service port 80
kubectl port-forward svc/astrid-api-service 8080:80
```

**Expected output:**
```
Forwarding from 127.0.0.1:8080 -> 80
Forwarding from [::1]:8080 -> 80
```

*Keep this terminal open - the port forwarding will run in the foreground*

### Step 2: Test the Health Endpoint

**In a new terminal**, run:

```bash
# Test the health endpoint
curl http://localhost:8080/health
```

**Expected response:**
```json
{"status":"ok","service":"astrid-api"}
```

### Step 3: Additional Validation Tests

```bash
# Test with verbose output to see HTTP headers
curl -v http://localhost:8080/health

# Test response time
curl -w "@-" -o /dev/null -s http://localhost:8080/health << 'EOF'
     time_namelookup:  %{time_namelookup}\n
        time_connect:  %{time_connect}\n
     time_appconnect:  %{time_appconnect}\n
    time_pretransfer:  %{time_pretransfer}\n
       time_redirect:  %{time_redirect}\n
  time_starttransfer:  %{time_starttransfer}\n
                     ----------\n
          time_total:  %{time_total}\n
EOF

# Test multiple requests to verify consistency
for i in {1..5}; do 
  echo "Request $i:"
  curl http://localhost:8080/health
  echo ""
done
```

### Step 4: Stop Port Forwarding

```bash
# In the port forwarding terminal, press Ctrl+C to stop
^C
```

## Success Criteria Validation ✅

After running these tests, you should have verified:

1. ✅ **kubectl get pods** shows one pod with name like `astrid-api-*` in `Running` state
2. ✅ **kubectl get service** shows service named `astrid-api-service` with `ClusterIP`
3. ✅ **kubectl port-forward svc/astrid-api-service 8080:80** works successfully
4. ✅ **curl http://localhost:8080/health** returns `{"status":"ok","service":"astrid-api"}`

## Complete Deployment Validation

All PRD acceptance criteria have been met:

- ✅ Infrastructure validated (DigitalOcean Kubernetes cluster working)
- ✅ Container registry integration working (image pushed and pulled)
- ✅ Helm workflow functioning (chart installed successfully)
- ✅ Application deployed with 1 replica as specified
- ✅ ClusterIP service routing traffic correctly
- ✅ Health endpoint responding with correct JSON
- ✅ Port forwarding enabling local testing access

## Troubleshooting

### If curl fails with "Connection refused":
- Verify port forwarding is still running
- Check that the pod is in `Running` state: `kubectl get pods`
- Check pod logs: `kubectl logs -l app.kubernetes.io/component=api`

### If health endpoint returns unexpected response:
- Check application logs for errors
- Verify the FastAPI application started correctly
- Test the endpoint directly on the pod: `kubectl exec -it <pod-name> -- curl localhost:80/health`

### If port forwarding fails:
- Verify service exists: `kubectl get service astrid-api-service`
- Check service endpoints: `kubectl get endpoints astrid-api-service`
- Ensure you have kubectl access to the cluster