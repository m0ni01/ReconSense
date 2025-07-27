import os
import json
import asyncio
import time
from typing import List
from fastapi import BackgroundTasks, APIRouter, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse ,FileResponse
from weasyprint import HTML, CSS
from pydantic import BaseModel
from dotenv import load_dotenv
from agents import Agent, function_tool, Runner, AsyncOpenAI, OpenAIChatCompletionsModel
from agents.run import RunConfig
import httpx
from weasyprint import HTML
from datetime import datetime
import markdown2 , base64

# Load env if needed
load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "AIzaSyAcnP2ggQFQMGZe8WwZsGdk4ckGwc05RL0")

router = APIRouter(prefix="/recon", tags=["Recon Agent"])

# ✅ Pydantic models
class Finding(BaseModel):
    plugin: str
    description: str
    severity: str
    cve_ids: List[str] = []

class ScanAnalysis(BaseModel):
    host: str
    findings: List[Finding]
    summary: str

# ✅ Helper function tool
@function_tool
def load_scan(json_str: str) -> dict:
    return json.loads(json_str)

# ✅ PDF generator using WeasyPrint
def generate_pdf(report_text: str, output_path: str):
    # Convert the main report from Markdown to HTML
    html_body = markdown2.markdown(
        report_text,
        extras=["fenced-code-blocks", "code-friendly"] # For better code block handling
    )

    # --- 1. Advanced CSS for a Professional Look ---
    professional_css = """
    /* Import a professional font */
    @import url('https://fonts.googleapis.com/css2?family=Roboto:wght@400;700&display=swap');

    @page {
        size: A4;
        margin: 1.5cm; /* Standard professional margin */
    }
    
    @page:first {
        /* You can have different styles for the first page if needed */
        margin: 0;
    }

    body {
        font-family: 'Roboto', 'Segoe UI', sans-serif;
        color: #333;
        line-height: 1.6;
        font-size: 11pt;
    }

    h1, h2, h3, h4 {
        color: #004a99; /* Professional blue for headers */
        font-weight: 700;
        margin-top: 1.2em;
        margin-bottom: 0.6em;
        line-height: 1.2;
    }
    
    h1 {
        font-size: 24pt;
        border-bottom: 2px solid #004a99;
        padding-bottom: 10px;
        margin-top: 0;
    }

    h2 {
        font-size: 18pt;
        border-bottom: 1px solid #d0d0d0;
        padding-bottom: 8px;
    }

    h3 {
        font-size: 14pt;
        color: #0056b3;
    }
    
    p {
        margin-bottom: 1em;
    }

    /* Styling for code blocks (for technical evidence) */
    pre {
        background-color: #f4f4f4;
        border: 1px solid #ddd;
        border-radius: 4px;
        padding: 12px;
        white-space: pre-wrap;       /* Wrap long lines */
        word-wrap: break-word;       /* Break words if necessary */
        font-family: 'Courier New', Courier, monospace;
        font-size: 9pt;
        margin: 1em 0;
    }

    code {
        font-family: 'Courier New', Courier, monospace;
        background-color: #eef;
        padding: 2px 4px;
        border-radius: 3px;
        font-size: 9pt;
    }

    /* Highlight important text that the AI makes bold */
    strong {
        font-weight: 700;
        color: #c00000; /* A subtle red for emphasis */
    }

    ul, ol {
        padding-left: 25px; /* Proper indentation for lists */
    }

    li {
        margin-bottom: 0.5em;
    }

    /* Header and Footer for the content pages */
    .page-header, .page-footer {
        position: fixed;
        width: 100%;
        font-size: 9pt;
        color: #777;
    }
    .page-header {
        top: 0;
        text-align: right;
        border-bottom: 1px solid #ddd;
        padding-bottom: 5px;
    }
    .page-footer {
        bottom: 0;
        text-align: right;
        border-top: 1px solid #ddd;
        padding-top: 5px;
    }
    .page-number:after {
        content: counter(page);
    }
    """

    # --- 2. Professional Title Page ---
    title_page_html = f"""
    <html>
        <head>
            <style>
                @page {{ margin: 0; }}
                body {{
                    font-family: 'Roboto', sans-serif;
                    text-align: center;
                    display: flex;
                    flex-direction: column;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    background-color: #003366;
                    color: white;
                }}
                .title {{ font-size: 32pt; font-weight: 700; margin-bottom: 20px; }}
                .subtitle {{ font-size: 18pt; font-weight: 400; margin-bottom: 40px; opacity: 0.9; }}
                .footer {{ position: absolute; bottom: 60px; font-size: 12pt; opacity: 0.7; }}
            </style>
        </head>
        <body>
            <div class="title">Security Assessment Report</div>
            <div class="subtitle">Date: {datetime.now().strftime('%B %d, %Y')}</div>
            <div class="footer">Rconsense AI Security Analysis Engine</div>
        </body>
    </html>
    """

    # --- 3. Content Pages with Header, Footer, and Body ---
    report_content_html = f"""
    <html>
        <head>
            <meta charset="utf-8">
            <style>{professional_css}</style>
        </head>
        <body>
            <div class="page-header">Confidential & Internal Use Only</div>
            <div class="page-footer">Page <span class="page-number"></span></div>
            {html_body}
        </body>
    </html>
    """
    
    # --- 4. Combine and Write to PDF ---
    # We now pass the stylesheet object to WeasyPrint
    css_stylesheet = CSS(string=professional_css)
    
    # Create the combined document
    html = HTML(string=title_page_html)
    doc = html.render(stylesheets=[css_stylesheet])

    # Add the report content pages
    content_html = HTML(string=report_content_html)
    content_pages = content_html.render(stylesheets=[css_stylesheet]).pages
    
    # Add the content pages to the document
    for page in content_pages:
        doc.pages.append(page)

    doc.write_pdf(output_path)


# def generate_pdf(report_text: str, output_path: str, target_domain: str): # ✅ 1. Added target_domain
#     # Convert the main report from Markdown to HTML
#     html_body = markdown2.markdown(
#         report_text,
#         extras=["fenced-code-blocks", "code-friendly"] # For better code block handling
#     )

#     # --- 1. Advanced CSS for a Professional Look ---
#     # (This CSS is unchanged from your working version)
#     professional_css = """
#     /* Import a professional font */
#     @import url('https://fonts.googleapis.com/css2?family=Roboto:wght@400;700&display=swap');
#     @page { size: A4; margin: 1.5cm; }
#     @page:first { margin: 0; }
#     body { font-family: 'Roboto', 'Segoe UI', sans-serif; color: #333; line-height: 1.6; font-size: 11pt; }
#     h1, h2, h3, h4 { color: #004a99; font-weight: 700; margin-top: 1.2em; margin-bottom: 0.6em; line-height: 1.2; }
#     h1 { font-size: 24pt; border-bottom: 2px solid #004a99; padding-bottom: 10px; margin-top: 0; }
#     h2 { font-size: 18pt; border-bottom: 1px solid #d0d0d0; padding-bottom: 8px; }
#     h3 { font-size: 14pt; color: #0056b3; }
#     p { margin-bottom: 1em; }
#     pre { background-color: #f4f4f4; border: 1px solid #ddd; border-radius: 4px; padding: 12px; white-space: pre-wrap; word-wrap: break-word; font-family: 'Courier New', Courier, monospace; font-size: 9pt; margin: 1em 0; }
#     code { font-family: 'Courier New', Courier, monospace; background-color: #eef; padding: 2px 4px; border-radius: 3px; font-size: 9pt; }
#     strong { font-weight: 700; color: #c00000; }
#     ul, ol { padding-left: 25px; }
#     li { margin-bottom: 0.5em; }
#     .page-header, .page-footer { position: fixed; width: 100%; font-size: 9pt; color: #777; }
#     .page-header { top: 0; text-align: right; border-bottom: 1px solid #ddd; padding-bottom: 5px; }
#     .page-footer { bottom: 0; text-align: right; border-top: 1px solid #ddd; padding-top: 5px; }
#     .page-number:after { content: counter(page); }
#     """

#     # --- 2. Professional Title Page ---
#     title_page_html = f"""
#     <html>
#         <head>
#             <style>
#                 @page {{ margin: 0; }}
#                 body {{
#                     font-family: 'Roboto', sans-serif; text-align: center;
#                     display: flex; flex-direction: column; justify-content: center; align-items: center;
#                     height: 100vh; background-color: #003366; color: white;
#                 }}
#                 .title {{ font-size: 32pt; font-weight: 700; margin-bottom: 20px; }}
#                 .subtitle {{ font-size: 18pt; font-weight: 400; margin-bottom: 40px; opacity: 0.9; }}
#                 .footer {{ position: absolute; bottom: 60px; font-size: 12pt; opacity: 0.7; }}
#             </style>
#         </head>
#         <body>
#             <div class="title">Security Assessment Report</div>
#             <!-- ✅ 2. Replaced hardcoded value with the dynamic target_domain -->
#             <div class="subtitle">Prepared for {target_domain}</div>
#             <div class="subtitle">Date: {datetime.now().strftime('%B %d, %Y')}</div>
#             <div class="footer">Rconsense AI Security Analysis Engine</div>
#         </body>
#     </html>
#     """

#     # --- 3. Content Pages with Header, Footer, and Body ---
#     report_content_html = f"""
#     <html>
#         <head>
#             <meta charset="utf-8">
#             <style>{professional_css}</style>
#         </head>
#         <body>
#             <div class="page-header">Confidential & Internal Use Only</div>
#             <div class="page-footer">Page <span class="page-number"></span></div>
#             {html_body}
#         </body>
#     </html>
#     """
    
#     # --- 4. Combine and Write to PDF ---
#     # (This rendering logic is UNCHANGED from your working version)
#     css_stylesheet = CSS(string=professional_css)
    
#     html = HTML(string=title_page_html)
#     doc = html.render(stylesheets=[css_stylesheet])

#     content_html = HTML(string=report_content_html)
#     content_pages = content_html.render(stylesheets=[css_stylesheet]).pages
    
#     for page in content_pages:
#         doc.pages.append(page)

#     doc.write_pdf(output_path)

#     doc.write_pdf(output_path)


# ✅ Gemini-compatible client (AsyncOpenAI stub - not used here but retained for compatibility)
external_client = AsyncOpenAI(
    api_key=GEMINI_API_KEY,
    base_url="https://generativelanguage.googleapis.com/v1beta/"
)

async def call_gemini(prompt: str) -> str:
    url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent"
    headers = {"Content-Type": "application/json"}
    params = {"key": GEMINI_API_KEY}
    payload = { "contents": [ { "parts": [ { "text": prompt } ] } ] }

    async with httpx.AsyncClient(timeout=120) as client:
        try:
            response = await client.post(url, headers=headers, params=params, json=payload)
            response.raise_for_status()
            return response.json()["candidates"][0]["content"]["parts"][0]["text"]
        except httpx.HTTPStatusError as exc:
            raise HTTPException(status_code=exc.response.status_code, detail=f"Gemini API error: {exc.response.text}")
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Unexpected error: {repr(e)}")

def cleanup_file(path: str):
    os.remove(path)

# ✅ API Endpoint (Modified)
@router.post("/analyze-scan")
async def analyze_scan(file: UploadFile = File(...), background_tasks: BackgroundTasks = None):
    if file.content_type != "application/json":
        raise HTTPException(status_code=400, detail="Only JSON files are supported.")

    try:
        scan_json_str = (await file.read()).decode("utf-8")
        scan_data = json.loads(scan_json_str)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to decode file: {e}")

    # Split data into chunks if needed
    if isinstance(scan_data, list):
        chunks = [scan_data[i:i + 5] for i in range(0, len(scan_data), 5)]
    elif isinstance(scan_data, dict) and "findings" in scan_data:
        findings = scan_data["findings"]
        chunks = [findings[i:i + 5] for i in range(0, len(findings), 5)]
    else:
        chunks = [scan_data]

    all_responses = []
    prompt_base = """
You are a premier Reconsense AI security analyst creating a board-level security report. Your output must be a single, complete Markdown document, formatted for exceptional clarity and professionalism for a PDF conversion.

**Formatting and Structure Mandates:**

1.  **Strict Markdown:** Use clean, standard Markdown for all formatting.
2.  **Section Numbering:** All H2 level headers (##) must be numbered (e.g., `## 1. Executive Summary`).
3.  **Critical Highlighting:** Emphasize the most critical phrases (e.g., specific risks or required actions) using **bold text**.
    *   *Example:* This exposes a **critical risk of remote code execution**.
4.  **Clean Technical Data:**
    *   Enclose all technical evidence (JSON, lists of domains, IP addresses) in fenced Markdown code blocks (```).
    *   **IMPORTANT:** When presenting lists (like subdomains) inside a code block, format them one item per line. Do NOT include `\n` characters in the output.
    *   *Correct Example:*
        ```
        onlineadmissions.umt.edu.pk
        www.onlineadmissions.umt.edu.pk
        sktonline.umt.edu.pk
        ```
5.  **Use Tables for Vulnerabilities:** The "Identified Vulnerabilities" section MUST be a Markdown table with the columns: `ID`, `Severity`, `Vulnerability Description`, and `Evidence/Affected Components`.
    *   *Example:*
        ```markdown
        | ID  | Severity | Vulnerability Description                                        | Evidence/Affected Components                               |
        |:----|:---------|:-----------------------------------------------------------------|:-----------------------------------------------------------|
        | V-01| Critical | **DNS Resolution Failure** renders the primary domain inaccessible. | DNS lookup timeouts for umt.edu.pk (see Technical Analysis). |
        | V-02| High     | **Shared Hosting Environment** exposes the site to neighbor risks. | Reverse IP lookup shows numerous unrelated, high-risk domains. |
        ```

**Required Report Structure:**

*   `# Security Assessment Report: [Target Domain]`
*   `## 1. Executive Summary`
*   `## 2. Scope and Methodology` (Briefly describe the tools used)
*   `## 3. Technical Analysis` (Detailed, tool-by-tool breakdown of findings)
*   `## 4. Identified Vulnerabilities` (Use the Markdown table format described above)
*   `## 5. Business Impact Analysis`
*   `## 6. Recommendations and Remediation Plan` (Categorize into Technical and Organizational)
*   `## 7. Conclusion`
"""

    for idx, chunk in enumerate(chunks):
        chunk_str = json.dumps(chunk, indent=2)
        try:
            response = await call_gemini(prompt_base + "\n\nScan Data:\n" + chunk_str)
            all_responses.append(response)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Gemini call failed on chunk {idx+1}: {str(e)}")

    full_report = "\n\n".join(all_responses)
    pdf_output_path = f"/tmp/report_{int(time.time())}.pdf"
    
    # Generate the PDF
    generate_pdf(full_report, pdf_output_path)

    # ✅ Add the cleanup task to run after the response is sent
    background_tasks.add_task(cleanup_file, pdf_output_path)

    # ✅ Return the generated PDF file
    return FileResponse(
        path=pdf_output_path,
        media_type='application/pdf',
        filename=f"Security_Report_{datetime.now().strftime('%Y-%m-%d')}.pdf"
    )

# ✅ API Endpoint
#sucessful-001
# @router.post("/analyze-scan")
# async def analyze_scan(file: UploadFile = File(...)):
#     if file.content_type != "application/json":
#         raise HTTPException(status_code=400, detail="Only JSON files are supported.")

#     try:
#         scan_json_str = (await file.read()).decode("utf-8")
#         scan_data = json.loads(scan_json_str)
#     except Exception as e:
#         raise HTTPException(status_code=400, detail=f"Failed to decode file: {e}")

#     # Split data into chunks if needed
#     if isinstance(scan_data, list):
#         chunks = [scan_data[i:i + 5] for i in range(0, len(scan_data), 5)]
#     elif isinstance(scan_data, dict) and "findings" in scan_data:
#         findings = scan_data["findings"]
#         chunks = [findings[i:i + 5] for i in range(0, len(findings), 5)]
#     else:
#         chunks = [scan_data]

#     all_responses = []
#     prompt_base = """
# You are an AI security analyst. You will receive a JSON scan result via the `load_scan` tool.
# Your goal is to provide a comprehensive and visually engaging security report.

# You must:

# 1. Write a **professional 5-page style report** based only on the available data in the scan.
# 2. Include the following sections:
#    - Executive Summary
#    - Technical Analysis (with references to actual JSON data)
#    - Vulnerabilities (with severity, evidence, CVE if applicable)
#    - Recommendations (technical, organizational, and future work)
#    - Inferred Risks and Business Impact
# 3. Mention specific data from the scan like domains, IPs, open ports, OS, DNS results, etc.
# 4. Even if the scan is partial or limited, make the best analysis possible using inference and known attack patterns.
# 5. The report should be **complete and final** – do not suggest a “Part 2” or defer work to the future.
# 6. Structure it to be directly usable in a PDF report generator.
# 7. Prioritize clarity, technical accuracy, and a formal tone.
# """

#     for idx, chunk in enumerate(chunks):
#         chunk_str = json.dumps(chunk, indent=2)
#         try:
#             response = await call_gemini(prompt_base + "\n\nScan Data:\n" + chunk_str)
#             all_responses.append(response)
#         except Exception as e:
#             raise HTTPException(status_code=500, detail=f"Gemini call failed on chunk {idx+1}: {str(e)}")

#     full_report = "\n\n".join(all_responses)
#     pdf_output_path = f"/tmp/report_{int(time.time())}.pdf"
#     generate_pdf(full_report, pdf_output_path)

#     return JSONResponse(content={"summary": full_report})

# POST endpoint to analyze uploaded scan JSON
# @router.post("/analyze-scan", response_model=ScanAnalysis)
# async def analyze_scan(file: UploadFile = File(...)):
#     if file.content_type != "application/json":
#         raise HTTPException(status_code=400, detail="Only JSON files are supported.")

#     try:
#         scan_json_str = (await file.read()).decode("utf-8")
#     except Exception as e:
#         raise HTTPException(status_code=400, detail=f"Failed to decode file: {e}")

#     # Configure model and agent run setup
#     model = OpenAIChatCompletionsModel(
#         model="gemini-1.5-flash",  # Gemini-compatible model
#         openai_client=external_client
#     )

#     run_config = RunConfig(
#         model=model,
#         model_provider=external_client,
#         tracing_disabled=True
#     )

#     agent = Agent(
#     name="Security Recon Agent",
#     instructions=(
#         "You are an AI security analyst. You will receive a JSON scan result via the `load_scan` tool. "
#         "Your goal is to provide a comprehensive and visually engaging security report. "
#         "Include detailed insights such as scanned hosts, identified vulnerabilities, plugins used, descriptions, severity levels, and CVE IDs. "
#         "Even if the input data is limited, infer and highlight potential vulnerabilities, weak points, or misconfigurations. "
#         "Be sure to include any suspected parameters, common attack vectors, and best-practice gaps. "
#         "Summarize your findings with clear, actionable insights, and rate the overall security posture of the scanned entity. "
#         "Your output will be converted into a professional report, so prioritize clarity, depth, and presentation quality."
#     ),
#     tools=[load_scan],
#     output_type=ScanAnalysis,
#     model=model
# )

#     try:
#         result = await Runner.run(agent, input=scan_json_str, run_config=run_config)
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=f"Agent processing failed: {str(e)}")

#     if not result.final_output:
#         raise HTTPException(status_code=500, detail="Agent did not return output")

#     return result.final_output