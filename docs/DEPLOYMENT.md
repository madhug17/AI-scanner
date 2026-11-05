# Deployment Guide

## 1. Local Development (Docker Compose)

The easiest way to run the entire distributed stack locally is with Docker Compose:

```bash
# Clone the repository
git clone https://github.com/madhug17/AI-scanner.git
cd AI-scanner

# Start all services (Backend, PostgreSQL, Redis, Kafka, Zookeeper, Prometheus, Grafana)
docker-compose up -d --build

# View logs
docker-compose logs -f backend
```

### Exposed Endpoints
- **Web UI & Dashboard:** [http://localhost:8000/](http://localhost:8000/)
- **Swagger API Docs:** [http://localhost:8000/docs](http://localhost:8000/docs)
- **Prometheus Metrics:** [http://localhost:9090](http://localhost:9090)
- **Grafana Dashboard:** [http://localhost:3000](http://localhost:3000) (admin / admin)

---

## 2. Local Python Execution (Standalone)

```bash
# Install dependencies
pip install -r requirements.txt reportlab prometheus-client pyjwt passlib

# Start the FastAPI server (serves both API and HTML/CSS/JS frontend)
python -m uvicorn scanner.main:app --host 127.0.0.1 --port 8000 --reload

# In a separate terminal, run scans via CLI if desired:
python -m scanner.main /path/to/repo --no-external
```

---

## 3. Kubernetes Deployment

Production Kubernetes manifests are available in `k8s/`:

```bash
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/postgres.yaml
kubectl apply -f k8s/redis.yaml
kubectl apply -f k8s/api-deployment.yaml
kubectl apply -f k8s/worker-deployment.yaml
kubectl apply -f k8s/service.yaml
```

