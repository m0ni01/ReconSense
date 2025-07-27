from fastapi import FastAPI, HTTPException, APIRouter
import subprocess
from pydantic import BaseModel
from typing import Optional



router = APIRouter(prefix="/scanner", tags=["Scanners"])


from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import subprocess


class ScanRequest(BaseModel):
    url: str

@router.post("/nuclei",tags=["Scanners"])
def scan_nuclei(request: ScanRequest):
    try:
        result = subprocess.run(
            ["nuclei", "-u", request.url, ],
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            # Include both stdout and stderr for debugging
            raise HTTPException(
                status_code=500,
                detail={
                    "message": "Nuclei scan failed",
                    "stdout": result.stdout,
                    "stderr": result.stderr
                }
            )
        return {"result": result.stdout}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))



@router.post("/nikto", tags=["Scanners"])
def scan_nikto(request: ScanRequest):
    try:
        result = subprocess.run(
            ["nikto", "-h", request.url],
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            raise HTTPException(
                status_code=500,
                detail={
                    "message": "Nikto scan failed",
                    "stdout": result.stdout,
                    "stderr": result.stderr
                }
            )
        return {"result": result.stdout}
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/dalfox", tags=["Scanners"])
def dalfox_scan(url: str):
    command = ["dalfox", "url", url, "--format", "json"]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True
        )
        return {
            "tool": "dalfox",
            "target": url,
            "result": result.stdout
        }
    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=f"Dalfox scan failed: {e.stderr}")


XSSTRIKE_PATH = "/home/m0ni01/project/reconsense/XSStrike/xsstrike.py" 
@router.get("/xsstrike", tags=["Scanners"])
def xsstrike_scan(url: str):
    command = ["python3", XSSTRIKE_PATH, "-u", url, "--crawl", "--skip"]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True
        )
        return {
            "tool": "xsstrike",
            "target": url,
            "result": result.stdout
        }
    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=f"XSStrike scan failed: {e.stderr}")
