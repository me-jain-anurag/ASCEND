import json
from pathlib import Path
from typing import Optional, List
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(
    title="ASCEND Analysis Core API",
    version="1.0.0",
    description="Mock backend serving ER-schema-compliant fixtures for ASCEND Workstream C"
)

# Enable CORS for local Vite dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"

def load_fixture(name: str) -> dict:
    file_path = FIXTURES_DIR / name
    if not file_path.exists():
        raise HTTPException(status_code=500, detail=f"Fixture file {name} not found")
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)

# Internal runtime state for interactive demo persistence
state = {
    "active_scenario": "default",
    "applied_fixes": [],
    "eliminated_path_ids": []
}

class ApplyFixRequest(BaseModel):
    fix_id: str

class EnumerateRequest(BaseModel):
    scenario: Optional[str] = "default"

@app.get("/api/network")
def get_network():
    """Returns hosts and reachability edges."""
    # TODO(Part A/B): replace fixture read with call into environment_graph
    network_data = load_fixture("network.json")
    return network_data

@app.post("/api/enumerate")
def enumerate_paths(payload: Optional[EnumerateRequest] = None, scenario: Optional[str] = None):
    """Enumerates attack paths from entry point to crown jewel."""
    # TODO(Part A/B): replace fixture read with call into enumerator
    paths_data = load_fixture("paths.json")
    chosen_scenario = scenario or (payload.scenario if payload else None) or state["active_scenario"]
    
    scenario_info = paths_data.get("scenarios", {}).get(chosen_scenario)
    if not scenario_info:
        scenario_info = paths_data["scenarios"]["default"]
        chosen_scenario = "default"
    
    state["active_scenario"] = chosen_scenario
    
    # If fixes were applied, filter out eliminated paths
    all_paths = scenario_info.get("paths", [])
    if state["applied_fixes"]:
        filtered_paths = [p for p in all_paths if p["path_id"] not in state["eliminated_path_ids"]]
    else:
        filtered_paths = all_paths

    return {
        "scenario": chosen_scenario,
        "name": scenario_info.get("name"),
        "entry_point": scenario_info.get("entry_point"),
        "crown_jewel": scenario_info.get("crown_jewel"),
        "total_paths": len(filtered_paths),
        "paths": filtered_paths,
        "description": scenario_info.get("description", "")
    }

@app.post("/api/verify")
def verify_paths():
    """Performs per-path and per-step verification outcomes from execution verifier."""
    # TODO(Part A/B): replace fixture read with call into verifier
    verify_data = load_fixture("verify.json")
    return verify_data

@app.get("/api/remediation")
def get_remediation():
    """Returns ranked fixes and fixes-vs-paths efficacy curve."""
    # TODO(Part A/B): replace fixture read with call into chokepoint
    remediation_data = load_fixture("remediation.json")
    return remediation_data

@app.post("/api/remediation/apply")
def apply_remediation(req: ApplyFixRequest):
    """Applies a fix and returns eliminated attack paths."""
    # TODO(Part A/B): replace fixture read with call into chokepoint
    remediation_data = load_fixture("remediation.json")
    target_fix = next((f for f in remediation_data.get("ranked_fixes", []) if f["fix_id"] == req.fix_id), None)
    
    if not target_fix:
        raise HTTPException(status_code=404, detail=f"Fix {req.fix_id} not found in remediation plan")
    
    if req.fix_id not in state["applied_fixes"]:
        state["applied_fixes"].append(req.fix_id)
        for pid in target_fix.get("paths_eliminated", []):
            if pid not in state["eliminated_path_ids"]:
                state["eliminated_path_ids"].append(pid)
                
    return {
        "status": "applied",
        "applied_fix": target_fix,
        "all_applied_fixes": state["applied_fixes"],
        "eliminated_path_ids": state["eliminated_path_ids"],
        "message": f"Chokepoint fix '{target_fix['title']}' applied successfully. {len(state['eliminated_path_ids'])} attack path(s) eliminated."
    }

@app.get("/api/status")
def get_status():
    """Returns run state and summary metrics."""
    # TODO(Part A/B): replace fixture read with call into scorer
    status_data = load_fixture("status.json")
    # Update active scenario and applied fixes in status response
    status_data["summary_metrics"]["active_scenario"] = state["active_scenario"]
    status_data["summary_metrics"]["applied_fixes_count"] = len(state["applied_fixes"])
    status_data["summary_metrics"]["eliminated_paths_count"] = len(state["eliminated_path_ids"])
    return status_data

@app.post("/api/reset")
def reset_state():
    """Helper endpoint to reset demo run state and applied fixes."""
    state["active_scenario"] = "default"
    state["applied_fixes"] = []
    state["eliminated_path_ids"] = []
    return {"status": "reset", "message": "Demo state successfully reset to initial conditions."}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
