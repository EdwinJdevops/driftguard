from fastapi import FastAPI, HTTPException, BackgroundTasks, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from datetime import datetime, timezone
from contextlib import asynccontextmanager
import uuid, json

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("DriftGuard API started")
    yield

app = FastAPI(title="DriftGuard", description="Detect drift. Fix it. Keep your cloud honest.", version="1.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

class WorkspaceCreate(BaseModel):
    name: str
    provider: str = "aws"
    region: str = "us-east-1"
    github_repo: str | None = None
    scan_interval_minutes: int = 60
    auto_pr_enabled: bool = True

class ScanRequest(BaseModel):
    state_file_content: dict | None = None

@app.get("/")
def root():
    return {"name":"DriftGuard","tagline":"Detect drift. Fix it. Keep your cloud honest.","version":"1.0.0","docs":"/docs","health":"/health"}

@app.get("/health")
def health():
    return {"status":"ok","version":"1.0.0","timestamp":datetime.now(timezone.utc).isoformat()}

@app.get("/dashboard/stats")
def stats():
    return {"total_workspaces":0,"open_findings":0,"critical_findings":0,"posture_score":100.0,"cost_delta":0.0}

@app.post("/workspaces", status_code=201)
def create_workspace(body: WorkspaceCreate):
    return {"id":str(uuid.uuid4()),"name":body.name,"provider":body.provider,"region":body.region,"github_repo":body.github_repo,"scan_interval_minutes":body.scan_interval_minutes,"auto_pr_enabled":body.auto_pr_enabled,"is_active":True,"created_at":datetime.now(timezone.utc).isoformat()}

@app.post("/workspaces/{workspace_id}/scan")
def trigger_scan(workspace_id: str, body: ScanRequest, background_tasks: BackgroundTasks):
    scan_id = str(uuid.uuid4())
    if body.state_file_content:
        background_tasks.add_task(run_scan, workspace_id, scan_id, body.state_file_content)
    return {"scan_id":scan_id,"workspace_id":workspace_id,"status":"pending","message":"Scan queued. Check /scans/"+scan_id+" for results."}

scan_results = {}

def run_scan(workspace_id: str, scan_id: str, state: dict):
    try:
        import sys, os
        sys.path.insert(0, os.path.expanduser("~/driftguard"))
        from backend.engines.drift import TerraformStateParser, DriftAnalyzer, PostureScorer
        parser = TerraformStateParser()
        tf = parser.parse(state)
        live = {"aws_instance":{},"aws_s3_bucket":{},"aws_security_group":{},"aws_db_instance":{}}
        analyzer = DriftAnalyzer()
        findings = analyzer.analyze(tf, live, "us-east-1")
        scorer = PostureScorer()
        score = scorer.score(findings, max(len(tf),1))
        scan_results[scan_id] = {
            "scan_id":scan_id,"workspace_id":workspace_id,"status":"completed",
            "total_resources":len(tf),"drift_count":len(findings),"posture_score":score,
            "findings":[{"resource_type":f.resource_type,"resource_id":f.resource_id,"severity":f.severity.value,"drift_type":f.drift_type.value,"diff_summary":f.diff_summary,"security_impact":f.security_impact,"compliance_violations":f.compliance_violations,"cost_delta":f.cost_delta_monthly,"terraform_patch":f.terraform_patch} for f in findings]
        }
    except Exception as e:
        scan_results[scan_id] = {"scan_id":scan_id,"status":"failed","error":str(e)}

@app.get("/scans/{scan_id}")
def get_scan(scan_id: str):
    if scan_id not in scan_results:
        return {"scan_id":scan_id,"status":"pending","message":"Scan still running or not found"}
    return scan_results[scan_id]

@app.get("/findings")
def list_findings():
    all_findings = []
    for s in scan_results.values():
        all_findings.extend(s.get("findings",[]))
    return {"findings":all_findings,"total":len(all_findings)}

@app.post("/findings/{finding_id}/ignore")
def ignore_finding(finding_id: str):
    return {"id":finding_id,"status":"ignored"}

@app.post("/findings/{finding_id}/resolve")
def resolve_finding(finding_id: str):
    return {"id":finding_id,"status":"resolved"}

@app.post("/webhooks/github")
async def github_webhook(request: Request):
    payload = await request.json()
    return {"received":True,"event":request.headers.get("x-github-event")}
