#!/bin/bash
echo ""
echo "================================================"
echo "  DriftGuard — Starting API Server"
echo "================================================"
echo ""
cd ~/driftguard
pip install fastapi uvicorn boto3 httpx structlog rich typer --break-system-packages -q
echo "Dependencies installed"
echo ""
echo "API running at:  http://localhost:8000"
echo "Interactive docs: http://localhost:8000/docs"
echo ""
PYTHONPATH=~/driftguard python3 -m uvicorn backend.api.main:app --host 0.0.0.0 --port 8000 --reload
