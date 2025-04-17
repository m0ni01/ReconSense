from fastapi import FastAPI , APIRouter , HTTPException
import nmap
import re
import os
import subprocess

router = APIRouter()

@router.get("/nmap/quick_scan",tags=["Active Scan"])
def quick_scan(target: str):
    """
    Perform a quick scan (-F) on a given target.
    """
    try:
        nmap.scan(hosts=target, arguments="-F")
        return nmap.all_hosts()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))    

@router.get("/nmap/ports/",tags=["Active Scan"])
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


@router.get("/nmap/os/",tags=["Active Scan"])
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


@router.post("/nmap/custom/scan/",tags=["Active Scan"])
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
