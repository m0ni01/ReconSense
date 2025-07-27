from fastapi import FastAPI , APIRouter , HTTPException ,Body
from pydantic import BaseModel
import nmap
import re
import os
import subprocess

router = APIRouter()

@router.get("/nmap/quick_scan", tags=["Active Scan"])
def quick_scan(target: str):
    """
    Perform a quick scan (-F) on a given target.
    """
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=target, arguments="-F")
        results = {host: nm[host].all_protocols() for host in nm.all_hosts()}
        return {"hosts": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
@router.get("/nmap/ports/", tags=["Active Scan"])
def open_ports(target: str):
    """
    Get open ports for a target.
    """
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=target, arguments="-p-")
        open_ports = {host: list(nm[host]["tcp"].keys()) for host in nm.all_hosts() if "tcp" in nm[host]}
        return open_ports
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/nmap/os/", tags=["Active Scan"])
def detect_os(target: str):
    """
    Perform OS detection on the target.
    """
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=target, arguments="-O")
        os_info = {host: nm[host].get("osmatch", []) for host in nm.all_hosts()}
        return os_info
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def is_valid_nmap_options(options: str) -> bool:
    """
    Validates Nmap options to prevent command injection.
    """
    if any(x in options for x in [";", "&", "`"]):
        return False

    valid_nmap_pattern = re.compile(r"^[-\w\s,./]+$")
    return bool(valid_nmap_pattern.match(options))



class ScanOptions(BaseModel):
    options: str  # The full Nmap command string, e.g. "-O 192.168.100.1"

@router.post("/nmap/custom/scan/", tags=["Active Scan"])
def custom_scan(scan: ScanOptions):
    """
    Accepts a full Nmap command as a single string (e.g. "-O 192.168.1.1").
    """
    try:
        parts = scan.options.strip().split()
        if len(parts) < 2:
            raise HTTPException(status_code=400, detail="Please include target IP in options.")

        target = parts[-1]
        arguments = " ".join(parts[:-1])

        nm = nmap.PortScanner()
        nm.scan(hosts=target, arguments=arguments)

        return {
            "target": target,
            "nmap_version": nm.nmap_version(),
            "scan_info": nm.scanstats(),
            "hosts": list(nm.all_hosts()),
            "raw_result": nm._scan_result  # includes full scan info
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/domain/sublister",tags=["Active Scan"])
def sublister_scan(domain: str):
    output_file = f"/tmp/{domain}_subdomains.txt"

    try:
        command = [
            "sublist3r",
            "-d", domain,
            "-o", output_file
        ]
        
        subprocess.run(command, check=True)

        with open(output_file, "r") as f:
            subdomains = [line.strip() for line in f.readlines() if line.strip()]
        
        os.remove(output_file)

        return {"domain": domain, "subdomains": subdomains}

    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail="Sublist3r scan failed.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
@router.get("/domain/amass",tags=["Active Scan"])
def amass_scan(Domain: str):
    command = ["amass", "enum", "-passive", "-d", Domain]
    subdomains = subprocess.run(command)
    return {"tool": "amass", "domain": Domain, "subdomains": subdomains}

#finding all paths
# @router.get("/domain/hakrawler",description="Use Complete URL")
# def amass_scan(Domain: str):
#     output_file = f"/tmp/{Domain}_paths.txt"

#     try:
#         command = f'echo "{Domain}" | hakrawler'
#         with open(output_file, "w") as out_file:
#             subprocess.run(command, shell=True, stdout=out_file, stderr=subprocess.PIPE, check=True)

#         with open(output_file, "r") as f:
#             paths = [line.strip() for line in f.readlines() if line.strip()]

        
#         return {"tool": "hakrawler", "domain": Domain, "paths": paths}

#     except subprocess.CalledProcessError as e:
#         raise HTTPException(status_code=500, detail=f"Hakrawler failed: {e.stderr.decode().strip()}")
#     except Exception as ex:
#         raise HTTPException(status_code=500, detail=str(ex))
def sanitize_filename(domain: str):
    # Remove scheme (http/https) and replace slashes/colons for safe filenames
    domain = re.sub(r'^https?://', '', domain)
    domain = domain.replace('/', '_').replace(':', '_')
    return domain

@router.get(
    "/domain/hakrawler",
    summary="Run Hakrawler for URL discovery",
    description="This endpoint uses Hakrawler to discover internal paths from a given domain or URL.",
    tags=["Active Scan"]
)
def hakrawler_scan(domain: str , description="Target domain or full URL"):
    try:
        safe_name = sanitize_filename(domain)
        output_file = f"/tmp/{safe_name}_paths.txt"

        command = f'echo {domain} | hakrawler -insecure '
        with open(output_file, "w") as out_file:
            subprocess.run(command, shell=True, stdout=out_file, stderr=subprocess.PIPE, check=True)

        with open(output_file, "r") as f:
            paths = [line.strip() for line in f.readlines() if line.strip()]

        os.remove(output_file)
        return {
            "tool": "hakrawler",
            "domain": domain,
            "paths": paths
        }

    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=f"Hakrawler failed: {e.stderr}")
    except Exception as ex:
        raise HTTPException(status_code=500, detail=str(ex))


@router.get("/domain/gau", summary="Use GAU to fetch URLs with parameters",tags=["Active Scan"])
def gau_scan(domain: str , description="Target domain (no protocol)"):
    try:
        safe_name = sanitize_filename(domain)
        output_file = f"/tmp/{safe_name}_gau_urls.txt"

        # Run GAU and store the output
        command = f'gau {domain} > {output_file}'
        subprocess.run(command, shell=True, check=True)

        # Read and extract only URLs with parameters
        with open(output_file, "r") as f:
            all_urls = [line.strip() for line in f.readlines()]
            param_urls = [url for url in all_urls if '?' in url]

        os.remove(output_file)  # optional: clean up

        return {
            "tool": "gau",
            "domain": domain,
            "urls_with_parameters": param_urls
        }

    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=f"GAU failed: {e.stderr}")
    except Exception as ex:
        raise HTTPException(status_code=500, detail=str(ex))
