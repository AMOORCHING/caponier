# Docker Push Commands for DigitalOcean Container Registry

## Steps to push the image to your DigitalOcean Container Registry:

1. **Install doctl (if not already installed):**
   ```bash
   brew install doctl
   ```

2. **Authenticate with DigitalOcean:**
   ```bash
   doctl auth init
   ```

3. **Login to your container registry:**
   ```bash
   doctl registry login
   ```

4. **Tag the image for your registry:**
   ```bash
   docker tag astrid-api:0.1.0 registry.digitalocean.com/astrid-registry/astrid-api:0.1.0
   docker tag astrid-api:0.1.0 registry.digitalocean.com/astrid-registry/astrid-api:latest
   ```

5. **Push the image:**
   ```bash
   docker push registry.digitalocean.com/astrid-registry/astrid-api:0.1.0
   docker push registry.digitalocean.com/astrid-registry/astrid-api:latest
   ```

6. **Update values.yaml with your actual registry name:**
   Replace `your-registry` in `helm/astrid/values.yaml` with your actual DigitalOcean registry name.

## Note:
Replace `YOUR-REGISTRY-NAME` with your actual DigitalOcean Container Registry name.