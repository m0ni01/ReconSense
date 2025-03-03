from fastapi import FastAPI
import shodan
import requests
from fastapi import APIRouter

#todo
    #created function to store shodan api from used and store it to database
SHODAN_API_KEY = "dXP5bLXYdlunlZnuXx1eXy5S9f8p2ipS"
shodan_client = shodan.Shodan(SHODAN_API_KEY)

router = APIRouter()

# Fetch IP Information from Shodan
@router.get("/ip/{ip}")
async def shodan_ip(ip: str):
    try:
        data = shodan_client.host(ip)
        return {
            "ip": data["ip_str"],
            "hostnames": data.get("hostnames", []),
            "ports": data.get("ports", []),
            "org": data.get("org"),
            "isp": data.get("isp"),
            "asn": data.get("asn"),
            "country": data.get("country_name"),
            "city": data.get("city"),
            "vulnerabilities": data.get("vulns", []),
            "last_update": data.get("last_update"),
        }
    except shodan.APIError as e:
        return {"error": str(e)}


# getting assest with favicon hash
@router.get("/favicon/")
async def search_by_favicon(hash: str):
    """Find IPs hosting the same favicon hash (useful for bug bounty asset discovery)."""
    favicon_hash = hash
    if not favicon_hash:
        return {"error": "Favicon not found"}

    query = f"http.favicon.hash:{favicon_hash}"
    try:
        results = shodan_client.search(query)
        ip_list = [{"ip": match["ip_str"], "ports": match.get("ports", [])} for match in results["matches"]]
        return {"favicon_hash": favicon_hash, "related_ips": ip_list}
    except shodan.APIError as e:
        return {"error": str(e)}

# Find All Assets Related to a Domain
@router.get("/shodan/domain/{domain}")
async def shodan_domain_lookup(domain: str):
    """Finds all related IPs and services for a domain via Shodan."""
    try:
        results = shodan_client.search(f"hostname:{domain}")
        assets = [{"ip": match["ip_str"], "ports": match.get("ports", []), "org": match.get("org")} for match in results["matches"]]
        return {"domain": domain, "assets": assets}
    except shodan.APIError as e:
        return {"error": str(e)}

# Find Related IPs Using ASN Lookup
@router.get("/shodan/asn/{asn}")
async def shodan_asn_lookup(asn: str):
    """Finds all IPs under a given ASN using Shodan."""
    try:
        results = shodan_client.search(f"asn:{asn}")
        ip_list = [{"ip": match["ip_str"], "org": match.get("org")} for match in results["matches"]]
        return {"asn": asn, "related_ips": ip_list}
    except shodan.APIError as e:
        return {"error": str(e)}

# Get Open Ports Across an IP Range
@router.get("/shodan/ports/{ip_range}")
async def shodan_ports(ip_range: str):
    """Finds all open ports for a given IP range."""
    try:
        results = shodan_client.search(f"net:{ip_range}")
        ports = set()
        for match in results["matches"]:
            ports.update(match.get("ports", []))
        return {"ip_range": ip_range, "open_ports": list(ports)}
    except shodan.APIError as e:
        return {"error": str(e)}
