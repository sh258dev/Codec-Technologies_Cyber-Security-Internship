# Step-by-step Deployment Guide — Secure Web Application (AWS & GCP)

**Objective:** Deploy a containerized web application securely to AWS or GCP using HTTPS and a managed database (Postgres/MySQL). This guide shows practical, secure-default steps, CI/CD snippets, and a security checklist.

**Assumptions & scope**
- Your app is containerized (has a `Dockerfile`).
- You want managed DB (RDS on AWS, Cloud SQL on GCP).
- You own the domain name you’ll use for TLS (optional; both platforms also support managed certificates).
- You have admin access to the relevant cloud accounts and can create IAM roles and networking resources.

---

## Common prerequisites (both clouds)
1. Install and configure CLI tools (AWS CLI or `gcloud`), Docker, and Git on your workstation/CI environment.
2. Create a separate project or account for production workloads.
3. Set up least-privilege service accounts / IAM users for automation (CI/CD).
4. Have a secrets manager available (AWS Secrets Manager / GCP Secret Manager) and avoid storing secrets in code.
5. Ensure your app reads DB credentials and other secrets from environment variables or a secrets provider.

---

## Step 0 — Prepare your app (local)
1. Add a production-ready `Dockerfile` (example below).
2. Expose a single port (e.g., `8080`) and add a `/health` endpoint returning `200`.
3. Ensure the app supports configuration by environment variables (DB URL, secret keys, allowed hosts).
4. Include graceful shutdown handling and logging to stdout/stderr (so container platform can collect logs).

**Example minimal Dockerfile**
```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY pyproject.toml requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV PORT=8080
EXPOSE 8080
CMD ["gunicorn", "app:app", "-b", "0.0.0.0:8080", "--workers", "3"]
```

---

# Option A — Secure deploy on AWS (ECS Fargate + ALB + RDS)

### Overview
Use Amazon ECR for container registry, AWS ECS Fargate for serverless containers, Application Load Balancer (ALB) + AWS Certificate Manager (ACM) for TLS, and Amazon RDS (Postgres/MySQL) as managed DB. Store secrets in Secrets Manager and logs in CloudWatch.

### Steps
**1) Build & push image to ECR**
- Create ECR repository.
- Authenticate and push image from CI or local: `aws ecr get-login-password | docker login --username AWS --password-stdin <account>.dkr.ecr.<region>.amazonaws.com` then `docker tag` and `docker push`.

**2) Create RDS instance (managed DB)**
- Create a Postgres or MySQL RDS instance.
- Use Multi-AZ for production and enable automated backups and point-in-time recovery.
- Set `Public accessibility` = **No**. Place DB in private subnets.
- Use encryption at rest (enable KMS) and enforce TLS for DB connections.
- Create a dedicated DB user (not the master) for the app.

**3) Networking & VPC**
- Create a VPC with at least 3 subnets across AZs (2+ recommended): public subnets for ALB and private subnets for ECS tasks and RDS.
- Security Groups:
  - ALB SG: allow inbound 443 (and 80 if redirecting) from 0.0.0.0/0, outbound to ECS SG.
  - ECS task SG: allow inbound from ALB SG on app port (8080), outbound to RDS SG and to internet if needed.
  - RDS SG: allow inbound from ECS SG on DB port (5432/3306), no public inbound.

**4) Create ACM TLS certificate**
- Request a public certificate for your domain in AWS Certificate Manager (ACM) in the region for the ALB (or use a global cert for CloudFront).
- Validate domain ownership (DNS validation preferred).

**5) Create ECS cluster & Task Definition (Fargate)**
- Create an ECS cluster with Fargate capacity.
- Create a Task Definition referencing the ECR image. Use minimal task-level IAM role (task execution role) and an optional task role for app permissions.
- Inject secrets via `secrets` in the Task Definition using Secrets Manager or SSM Parameter Store (not environment variables in plain text).
- Configure container port mapping to host port `8080`.

**6) Create an ALB and ECS Service**
- Create a target group for the ECS service with health check path `/health` and health threshold tuned for your app.
- Create an HTTPS listener on ALB (443) and attach ACM certificate; optionally redirect 80->443.
- Create ECS Service using the Task Definition and attach to the ALB target group.

**7) IAM & least privilege**
- ECS Task execution role: `AmazonECSTaskExecutionRolePolicy` to pull images and send logs.
- Task role: grant only necessary permissions (e.g., read from Secrets Manager and S3 if required), follow least privilege.

**8) Secrets & configuration**
- Store DB credentials in Secrets Manager and mount them via ECS `secrets` (this injects values into env vars from Secrets Manager, never store plaintext in tasks).
- Use Parameter Store for non-sensitive config if needed.

**9) CI/CD (recommended: GitHub Actions)**
- Build image in CI, push to ECR, update ECS task definition & service. A minimal GitHub Actions job uses `aws-actions/configure-aws-credentials`, `docker/login-action`, build/push, then `aws ecs update-service` or use `aws-actions/amazon-ecs-deploy-task-definition`.

**10) Logging & monitoring**
- Configure CloudWatch Logs for container logs.
- Enable RDS enhanced monitoring and automated backups.
- Create CloudWatch alarms for high error rates, high CPU, or low healthy host counts.
- Enable AWS GuardDuty and AWS Config for threat detection and drift.

**11) WAF & edge protection**
- Add AWS WAF in front of ALB to filter common attacks; use managed rule sets.
- Optionally use CloudFront in front for global edge caching and additional TLS + WAF controls.

**12) Backups & BCDR**
- Enable automated RDS backups and snapshots, test restores periodically.
- Keep infrastructure as code (Terraform / CloudFormation) and a reproducible pipeline.

**13) Post-deploy security checks**
- Verify TLS with the cert in ACM and that ALB only serves HTTPS.
- Verify DB is not publicly accessible.
- Check IAM roles for excessive permissions.
- Run vulnerability scan on container images (ECR image scanning) and dependency checks.

---

## Option A — Example GitHub Actions snippet (push image & update ECS)
```yaml
name: Deploy to ECS
on: [push]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: aws-actions/configure-aws-credentials@v2
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: us-east-1
      - name: Login to ECR
        uses: aws-actions/amazon-ecr-login@v1
      - name: Build, tag, push
        run: |
          IMAGE_TAG=${{ github.sha }}
          docker build -t $ECR_REGISTRY:$IMAGE_TAG .
          docker tag $ECR_REGISTRY:$IMAGE_TAG $ECR_REGISTRY:latest
          docker push $ECR_REGISTRY:$IMAGE_TAG
          docker push $ECR_REGISTRY:latest
      - name: Deploy to ECS
        uses: aws-actions/amazon-ecs-deploy-task-definition@v1
        with:
          task-definition: ecs-task-def.json
          service: my-service
          cluster: my-cluster
```

---

# Option B — Secure deploy on GCP (Cloud Run + Cloud SQL + Artifact Registry)

### Overview
Use Artifact Registry for images, Cloud Run (fully managed) for containers, Cloud SQL for a managed DB, Secret Manager for secrets, and Cloud Load Balancing / managed certs for TLS (Cloud Run provides automatic TLS for the default domain and supports custom domains with managed certs).

### Steps
**1) Build & push image to Artifact Registry**
- Create an Artifact Registry repository (Docker format).
- `gcloud auth configure-docker` then `docker build` and `docker push` to `LOCATION-docker.pkg.dev/PROJECT/REPO/IMAGE:TAG`.

**2) Create Cloud SQL (managed DB)**
- Create a Postgres or MySQL instance with automated backups and high availability if needed.
- Use **private IP** if you want DB to only be accessible inside VPC.
- Create a dedicated DB user and enable SSL for connections.
- Note the instance connection name: `PROJECT:REGION:INSTANCE`.

**3) Service account & IAM**
- Create a service account for Cloud Run with `roles/cloudsql.client`, `roles/secretmanager.secretAccessor`, and limited additional roles.
- Grant Cloud Run runtime service account the Cloud SQL Client role.

**4) Deploy Cloud Run with Cloud SQL connectivity**
- Use the Cloud SQL connection via the `--add-cloudsql-instances` flag when deploying:
  `gcloud run deploy my-service --image=LOCATION-docker.pkg.dev/PROJECT/REPO/IMAGE:TAG --add-cloudsql-instances=PROJECT:REGION:INSTANCE --region=REGION --platform=managed --set-env-vars=DATABASE_URL=...`
- If using private IP instance you may need Serverless VPC Access connector.

**5) Secrets & config**
- Store DB password and other sensitive data in Secret Manager.
- Grant Cloud Run runtime access to secrets and mount them as environment variables (or fetch at runtime via the Secret Manager API).

**6) Custom domain & TLS**
- For default `*.run.app` domain, TLS is automatic.
- To use your domain, map the custom domain in Cloud Run and GCP will provision a managed certificate automatically (DNS validation required).

**7) CI/CD (Cloud Build / GitHub Actions)**
- Use Cloud Build triggers or GitHub Actions to build/push and deploy. Example: GitHub Actions builds the container and uses `gcloud` to deploy to Cloud Run.

**8) Logging & monitoring**
- Cloud Run logs go to Cloud Logging; monitor errors and latency in Cloud Monitoring.
- Enable Cloud SQL insights and automated backups.

**9) WAF / edge**
- Use Cloud Armor to protect against DDoS and common web attacks.
- Optionally put Cloud CDN / HTTPS Load Balancer in front for advanced edge controls.

**10) Post-deploy security checks**
- Confirm that Cloud SQL is not publicly accessible and requires Private IP or authorized networks.
- Confirm service account only has the permissions it needs.
- Run container image vulnerability scanning (Container Analysis / Artifact Registry scanning).

---

## Option B — Example `gcloud` deploy command (Cloud Run)
```bash
# Build & push
docker build -t REGION-docker.pkg.dev/PROJECT/REPO/IMAGE:TAG .
docker push REGION-docker.pkg.dev/PROJECT/REPO/IMAGE:TAG
# Deploy to Cloud Run with Cloud SQL
gcloud run deploy my-service \
  --image REGION-docker.pkg.dev/PROJECT/REPO/IMAGE:TAG \
  --region=REGION \
  --platform=managed \
  --add-cloudsql-instances=PROJECT:REGION:INSTANCE \
  --set-env-vars=DATABASE_URL="postgres://user:$(secret)@/dbname?host=/cloudsql/PROJECT:REGION:INSTANCE"
```

---

## Security checklist (applies to both clouds)
- Use HTTPS/TLS with strong ciphers; redirect HTTP -> HTTPS.
- Store secrets in a secrets manager; rotate credentials regularly.
- Use least-privilege IAM roles for services and CI.
- Disable public access on managed DB; use private networking where possible.
- Enable automated backups and test restore procedures.
- Enable logging and create alerts for suspicious activity and high error rates.
- Scan container images and dependencies for vulnerabilities.
- Enforce security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options) from the app or via ALB/Load Balancer.
- Rate-limit authentication endpoints and implement account lockout after repeated failures.
- Enable WAF (AWS WAF / Cloud Armor) with managed rules.
- Use network segmentation: separate public and private subnets.
- Monitor IAM policy changes and perform regular audits.

---

## Recommended IaC & automation (optional but best practice)
- Keep your infrastructure as code using Terraform / CloudFormation (AWS) or Terraform / Deployment Manager (GCP).
- Store IaC in a repo and protect the main branch; enable code reviews and CI linting.
- Use CI to run tests, build images, push artifacts, and trigger deployments.

---

## Post-deployment testing & validation
1. Run automated smoke tests hitting health endpoints and sample public pages.
2. Run security scanning (OWASP ZAP, Snyk, image scanners).
3. Validate that TLS is configured correctly (no weak ciphers) and that HSTS is enabled.
4. Confirm backups and automated failover work (test restore from snapshot).
5. Check logs and set up alerting for high error rates, CPU spikes, or unauthorized attempts.

---

## Cost & scaling notes
- Start small: use Fargate/Cloud Run autoscaling to manage cost; enable scaling policies with limits.
- Managed DBs are charged separately — use appropriate instance sizes and storage auto-scaling.
- Use cost alerts and budgets to avoid surprises.

---

## Quick comparison (high-level)
- **AWS ECS Fargate**: deeper AWS-native feature set (ACM, ALB, VPC) and good for complex networking; slightly more configuration overhead.
- **GCP Cloud Run**: easiest serverless container deployment with automatic TLS for default domain and fast setup; simpler for stateless services.


