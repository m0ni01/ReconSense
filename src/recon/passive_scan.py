#this file contain some basic tools that will be avaible in framework
#decoders
#encoders
#repeater

from fastapi import FastAPI,Requests
from fastapi import APIRouter
from pydantic import BaseModel
import httpx


# Define the request structure
class RequestData(BaseModel):
    url: str
    method: str
    headers: dict = None
    body: dict = None
    
router = APIRouter()


@router.post("/tools/request_tool/")
async def request_tool(request_data: RequestData):
    async with httpx.AsyncClient() as client:
        method = request_data.method.upper()
        headers = request_data.headers or {}
        body = request_data.body or {}

        try:
            response = await client.request(
                method, request_data.url, headers=headers, json=body
            )

            return {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "body": response.text
            }
        except Exception as e:
            return {"error": str(e)}