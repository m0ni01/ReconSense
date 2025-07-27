import requests
from pydantic import BaseModel
from fastapi import APIRouter
import hashlib , base64
import subprocess
import whois 
from  .slack_config  import send_slack_message
router = APIRouter()

# crt.sh API for subdomains
class DomainInput(BaseModel):
    domain: str

@router.post("/crtsh/", tags=["RECON BASIC - PASSIVE"])
def crtsh_query(data: DomainInput):
    domain = data.domain
    url = f"https://crt.sh/?q={domain}&output=json"
    headers = {"User-Agent": "Mozilla/5.0"}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        subdomains = {entry["name_value"] for entry in response.json()}

        # Slack notification update
        message = (
            f":white_check_mark: *CRTSH Task Completed!*\n"
            f"*Domain:* `{domain}`\n"
            f"*Subdomains Found:* {len(subdomains)}\n"
            f"> {', '.join(subdomains) if subdomains else 'No subdomains found.'}"
        )
        send_slack_message(message)
        return list(subdomains)
    
    return []

# favicon hash
@router.post("/favicon-hash",tags=["RECON BASIC - PASSIVE"])
def get_favicon_hash(data: DomainInput):
    domain = data.domain
    """Fetch favicon and compute its MD5 hash."""
    favicon_url = f"https://{domain}/favicon.ico"

    try:
        response = requests.get(favicon_url, timeout=5)
        if response.status_code == 200:
            # Convert favicon to base64
            favicon_base64 = base64.b64encode(response.content).decode()
            # Compute MD5 hash
            md5_hash = hashlib.md5(favicon_base64.encode()).hexdigest()
            return {
                "domain": domain,
                "favicon_url": favicon_url,
                "md5_hash": md5_hash
            }
        else:
            return {"error": f"Failed to fetch favicon (Status: {response.status_code})"}
    except requests.RequestException as e:
        return {"error": str(e)}


# using dig to get dns information
@router.post("/dig",tags=["RECON BASIC - PASSIVE"])
def get_dns_records(data: DomainInput):
    domain = data.domain
    try:
        output = subprocess.check_output(["dig", domain, "ANY", "+short"], text=True)
        return {"dns_records": output.split("\n")}
    except Exception as e:
        return {"error": str(e)}
    
    
@router.post("/Wappalyzer",tags=["RECON BASIC - PASSIVE"])
def get_wappalyzer(domain,api_key):
    url_wappalyzer=f"https://api.wappalyzer.com/v2/lookup/?urls=https://{domain}&sets=all"
    headers = {"User-Agent": "Mozilla/5.0",
               "x-api-key": f"{api_key}"}
    try:
        response = requests.get(url_wappalyzer,headers=headers)
        if response.status_code ==200:
            return response
        else:
            return {"error": f"Failed to get wappaluzer (Status: {response.status_code})"}
    except Exception as e:
        return {"error": str(e)}
@router.post("/revers_ip_lookup",tags=["RECON BASIC - PASSIVE"])
def reverse_ip_lookup(data:DomainInput):
    domain = data.domain
    try:
        response = requests.get(f"https://api.hackertarget.com/reverseiplookup/?q={domain}")
        if response.status_code == 200:
            return {"reverse_ips": response.text.split("\n")}
        return {"error": "Failed to fetch reverse IP data"}
    except Exception as e:
        return {"error": str(e)}   
    
  
@router.get("/whois",tags=["RECON BASIC - PASSIVE"])
async def whois_lookup(domain: str):
    try:
        data = whois.whois(domain)
        return {
            "domain": domain,
            "registrar": data.registrar,
            "creation_date": str(data.creation_date),
            "expiration_date": str(data.expiration_date),
            "updated_date": str(data.updated_date),
            "name_servers": data.name_servers,
            "status": data.status,
            "emails": data.emails
        }
    except Exception as e:
        return {"error": str(e)}

    
@router.get("/virustotal",tags=["RECON BASIC - PASSIVE"])
async def virustotal_lookup(domain: str):
    url = "https://www.virustotal.com/api/v3"
    apikey= "2acb1631b26620829c793bdf082fc8cb6f2b7c9f997b080fd08728147400e0d9"
    header = {"x-apikey":apikey}
    try:
        response = requests.get(f"{url}/domains/{domain}/subdomains", headers=header)
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"Failed to get VirusTotal data (Status: {response.status_code})"}
    except response.exceptions.RequestException as e:
        return {"error": str(e)}    
        
# SecurityTrails API
# def securitytrails_query(domain, api_key):
#     url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
#     headers = {"APIKEY": api_key}
#     response = requests.get(url, headers=headers)

#     if response.status_code == 200:
#         return response.json().get("subdomains", [])
#     return []

# @router.get("/recon/subdomains/passive")
# def get_subdomains(domain: str, api_key: str = None):
#     subdomains = crtsh_query(domain)
#     if api_key:
#         subdomains.extend(securitytrails_query(domain, api_key))
#     return {"domain": domain, "subdomains": list(set(subdomains))}
