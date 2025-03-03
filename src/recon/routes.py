from fastapi import APIRouter , status
from fastapi.exceptions import HTTPException
from typing import List


router = APIRouter()

@router.get("/test")
def sayit():
        return {"msg":f"nothing to say"}
    