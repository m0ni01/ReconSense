from fastapi import FastAPI
from .recon import routes , subdomain_passive , shodan_recon , securitytrails , tools , subdomain_active
version="v1"

app = FastAPI(
    title="ReconSense",
    description="Bugbounty Recon Framework",
    version=version
)

@app.get("/")
def read_root():
    return {"message": "Bug Bounty Recon Framework Running!"}

app.include_router(routes.router,prefix="/reconhere")


app.include_router(subdomain_passive.router,prefix="/recon/subdomains/passive")
app.include_router(shodan_recon.router,prefix="/recon/subdomains/passive/shodan")
app.include_router(securitytrails.router,prefix="/recon/subdomains/passive/securitytrails")
app.include_router(tools.router,prefix="/tools")
app.include_router(subdomain_active.router,prefix="/recon/active")