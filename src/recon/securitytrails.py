from fastapi import FastAPI
import requests
from fastapi import APIRouter
from pysecuritytrails import SecurityTrails, SecurityTrailsError
from typing import Literal

router = APIRouter()
st = SecurityTrails("msU8H8c4oHp_UHxxNhcpfotnHXoyMtuf")

@router.get("/")
def securitytrails_query():
    return {"msg":"securitytrails working fine"}

# Testing api key
@router.get("/test")
def test_api_key():
    try:
        msg = st.ping()
        return {"msg": msg}
    except SecurityTrailsError as e:
        return e 

# Get domain info 
@router.get("/domaininfo")
def get_domain_info(domain: str):
    try:
        info = st.domain_info(domain)
        return {
            "data":info
        }
    except SecurityTrailsError as e:
        return {"error": str(e)}

# Get domain subdomains
@router.get("/domain_subdomains")
def get_domain_subdomain(domain:str):
    try:
        subdomains = st.domain_subdomains(domain)
        return {
            "data":subdomains
        }
    except SecurityTrailsError as e:
        return {"error": str(e)}

@router.get("/domain_whois")
def get_domain_whois(domain:str):
    try:
        whois_info = st.domain_whois(domain)
        return {
            "data":whois_info
        }
    except SecurityTrailsError as e:
        return {"error": str(e)}
    
# get domain dns history
@router.get("/domain_dns_history")
def get_domain_dns_history(domain:str,Type: str , Page:int):
    try:
        dns_history = st.domain_history_dns(domain,Type,Page)
        return {
            "data":dns_history
        }
    except SecurityTrailsError as e:
        return {"error": str(e)}


#ssl certificates
@router.get("/ssl_certificates")
def get_ssl_certificates(domain:str,include_subdomain: bool,status:Literal["valid","all","expired"] = "valid"):
    url = f"https://api.securitytrails.com/v1/domain/{domain}/ssl?include_subdomains={include_subdomain}&status={status}"
    header = {"apikey": "msU8H8c4oHp_UHxxNhcpfotnHXoyMtuf",
              "accept": "application/json"}
    try:
        response = requests.get(url,headers=header)
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}
    
        