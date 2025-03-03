from fastapi import FastAPI , APIRouter , HTTPException
import nmap
import re

router = APIRouter()

@router.get("/nmap/quick_scan")
def quick_scan(target: str):
    """
    Perform a quick scan (-F) on a given target.
    """
    try:
        nmap.scan(hosts=target, arguments="-F")
        return nmap.all_hosts()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))    

@router.get("/nmap/ports/")
def open_ports(target: str):
    """
    Get open ports for a target.
    """
    try:
        nmap.scan(target, arguments="-p-")
        open_ports = {host: nmap[host]["tcp"].keys() for host in nmap.all_hosts()}
        return open_ports
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/nmap/os/")
def detect_os(target: str):
    """
    Perform OS detection on the target.
    """
    try:
        nmap.scan(hosts=target, arguments="-O")
        return nmap.all_hosts()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

def is_valid_nmap_options(options: str) -> bool:
    """
    Validates Nmap options to prevent command injection.
    """
    # Block dangerous characters
    if ";" in options or "&" in options or "`" in options:
        return False

    # Allow only valid Nmap parameters
    valid_nmap_pattern = re.compile(r"^[-\w\s,./]+$")
    return bool(valid_nmap_pattern.match(options))


@router.post("/nmap/custom/scan/")
def custom_scan(request: str):
    """
    Perform an Nmap scan with user-specified options.
    """
    try:
        # Validate options to prevent command injection
        if not is_valid_nmap_options(request.options):
            raise HTTPException(status_code=400, detail="Invalid or dangerous scan options!")

        # Execute the scan
        scan_result = nmap.scan(hosts=request.target, arguments=request.options)

        return {
            "target": request.target,
            "nmap_version": nmap.nmap_version(),
            "scan_info": scan_result["nmap"]["scanstats"],
            "hosts": scan_result.get("scan", {}),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))