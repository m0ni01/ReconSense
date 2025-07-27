import os
import json
import asyncio
from typing import List
from fastapi import APIRouter, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from dotenv import load_dotenv

# --- vvv CHANGE IN IMPORTS vvv ---
# REMOVE the OpenAI-specific imports
# from agents import Agent, function_tool, Runner, AsyncOpenAI, OpenAIChatCompletionsModel
# ADD the native Google library and its corresponding model from the agents framework
import google.generativeai as genai
from agents import Agent, function_tool, Runner, RunConfig
# NOTE: You will need to find the correct Model class for the native Google API.
# It might be named GoogleGenerativeAIModel or something similar. Check your 'agents' library docs.
# For this example, we will assume it's called 'GoogleGenerativeAIModel'.
from agents.models.google import GoogleGenerativeAIModel # <--- THIS IS A LIKELY PATH, PLEASE VERIFY
# --- ^^^ CHANGE IN IMPORTS ^^^ ---


GEMINI_API_KEY = "AIzaSyAcnP2ggQFQMGZe8WwZsGdk4ckGwc05RL0"

router = APIRouter(prefix="/recon", tags=["Recon Agent"])

# Pydantic output model (no changes here)
class Finding(BaseModel):
    plugin: str
    description: str
    severity: str
    cve_ids: List[str] = []

class ScanAnalysis(BaseModel):
    host: str
    findings: List[Finding]
    summary: str

# Tool function (no changes here)
@function_tool
def load_scan(json_str: str) -> dict:
    return json.loads(json_str)

# --- vvv CLIENT CONFIGURATION CHANGE vvv ---
# REMOVE the old OpenAI-compatible client
# external_client = AsyncOpenAI(...)

# CONFIGURE the native Google client
genai.configure(api_key=GEMINI_API_KEY)
# --- ^^^ CLIENT CONFIGURATION CHANGE ^^^ ---


@router.post("/analyze-scan", response_model=ScanAnalysis)
async def analyze_scan(file: UploadFile = File(...)):
    if file.content_type != "application/json":
        raise HTTPException(status_code=400, detail="Only JSON files are supported.")

    try:
        scan_json_str = (await file.read()).decode("utf-8")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to decode file: {e}")

    # --- vvv MODEL CONFIGURATION CHANGE vvv ---
    # Use the native Google model class from your agents library
    model = GoogleGenerativeAIModel(
        model_name="gemini-2.0-flash", # Use the same model name
    )

    # RunConfig can likely stay the same, but no longer needs the OpenAI-specific client
    run_config = RunConfig(
        model=model,
        # model_provider=external_client, # This is no longer needed
        tracing_disabled=True
    )
    # --- ^^^ MODEL CONFIGURATION CHANGE ^^^ ---

    agent = Agent(
        name="Security Recon Agent",
        instructions=(
            # Instructions remain the same
            "You are an AI security analyst. You will receive a JSON scan result via the `load_scan` tool. "
            "Your goal is to provide a comprehensive and visually engaging security report. "
            "Include detailed insights such as scanned hosts, identified vulnerabilities, plugins used, descriptions, severity levels, and CVE IDs. "
            "Even if the input data is limited, infer and highlight potential vulnerabilities, weak points, or misconfigurations. "
            "Be sure to include any suspected parameters, common attack vectors, and best-practice gaps. "
            "Summarize your findings with clear, actionable insights, and rate the overall security posture of the scanned entity. "
            "Your output will be converted into a professional report, so prioritize clarity, depth, and presentation quality."
        ),
        tools=[load_scan],
        output_type=ScanAnalysis,
        model=model
    )

    try:
        # The Runner call remains the same
        result = await Runner.run(agent, input=scan_json_str, run_config=run_config)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Agent processing failed: {str(e)}")

    if not result.final_output:
        raise HTTPException(status_code=500, detail="Agent did not return output")

    return result.final_output