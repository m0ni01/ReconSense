#this file contain some basic tools that will be avaible in framework
#decoders
#encoders
#repeater

from fastapi import FastAPI , requests , HTTPException
from fastapi import APIRouter
from pydantic import BaseModel
import httpx
from typing import Literal , Optional
import logging
import base64
from urllib.parse import quote, unquote

logging.basicConfig(level=logging.INFO)

# Define the request structure
class RequestData(BaseModel):
    url: str
    method: str
    headers: dict = None
    body: dict = None
    
router = APIRouter()


@router.post("/request_tool/")
async def send_request(
    url: str,
    method: Literal["GET", "POST", "TRACE"],
    header : Optional[str]= None,
    body: Optional[str] = None
):
    async with httpx.AsyncClient() as client:
        try:
            response = await client.request(
                method=method,
                url=url,
                headers=header or {},  # Ensure headers is always a dictionary
                content=body.encode("utf-8") if body else None,  # Send raw body if provided
            )
            
            # Log the response
            logging.info(f"Response: {response.status_code} {response.text}")

            return {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "body": response.text
            }

        except Exception as e:
            logging.error(f"Error: {str(e)}")
            raise HTTPException(status_code=500, detail=str(e))


@router.post("/base64/encode/")
async def encode_base64(text: str):
    """
    Encodes the given text into Base64 format.
    """
    try:
        encoded_bytes = base64.b64encode(text.encode("utf-8"))
        encoded_str = encoded_bytes.decode("utf-8")
        return {"original_text": text, "base64_encoded": encoded_str}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/base64/decode/")
async def decode_base64(encoded_text: str):
    """
    Decodes the given Base64-encoded text back to its original string.
    """
    try:
        decoded_bytes = base64.b64decode(encoded_text.encode("utf-8"))
        decoded_str = decoded_bytes.decode("utf-8")
        return {"base64_encoded": encoded_text, "decoded_text": decoded_str}
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid Base64 string")
    
    
@router.post("/url/encode/")
async def encode_url(text: str):
    """
    Encodes a given string into a URL-safe format.
    """
    try:
        encoded_url = quote(text)
        return {"original_text": text, "url_encoded": encoded_url}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/url/decode/")
async def decode_url(encoded_text: str):
    """
    Decodes a URL-encoded string back to its original form.
    """
    try:
        decoded_url = unquote(encoded_text)
        return {"url_encoded": encoded_text, "decoded_text": decoded_url}
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid URL-encoded string")

@router.post("/unicode/encode/")
async def encode_unicode(text: str):
    """
    Encodes a given text into a Unicode escape sequence.
    """
    try:
        encoded_unicode = text.encode("unicode_escape").decode("utf-8")
        return {"original_text": text, "unicode_encoded": encoded_unicode}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/unicode/decode/")
async def decode_unicode(encoded_text: str):
    """
    Decodes a Unicode escape sequence back to its original form.
    """
    try:
        decoded_unicode = encoded_text.encode("utf-8").decode("unicode_escape")
        return {"unicode_encoded": encoded_text, "decoded_text": decoded_unicode}
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid Unicode-encoded string")


from fastapi import FastAPI, HTTPException
import html

app = FastAPI()

@router.post("/html/encode/")
async def encode_html(text: str):
    """
    Encodes HTML special characters into their entity representations.
    """
    try:
        encoded_html = html.escape(text)
        return {"original_text": text, "html_encoded": encoded_html}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/html/decode/")
async def decode_html(encoded_text: str):
    """
    Decodes HTML entities back to their original characters.
    """
    try:
        decoded_html = html.unescape(encoded_text)
        return {"html_encoded": encoded_text, "decoded_text": decoded_html}
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid HTML-encoded string")
