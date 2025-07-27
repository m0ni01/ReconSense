import os
import asyncio
import httpx # <--- IMPORT httpx
from openai import AsyncOpenAI
from dotenv import load_dotenv

# --- Option 2: Hardcode key for this test ---
GEMINI_API_KEY = "AIzaSyAcnP2ggQFQMGZe8WwZsGdk4ckGwc05RL0" # Use your actual key

if not GEMINI_API_KEY:
    print("ERROR: GEMINI_API_KEY not found.")
    exit()

print("API Key loaded. Initializing client...")

# --- vvv NEW CODE TO FORCE IPV4 vvv ---
# Create a custom httpx transport that only allows IPv4 addresses
# This prevents the client from getting stuck on a broken IPv6 route.
transport = httpx.AsyncHTTPTransport(local_address="0.0.0.0")
# --- ^^^ NEW CODE TO FORCE IPV4 ^^^ ---


# This is the same client setup, but now with the custom transport
client = AsyncOpenAI(
    api_key="AIzaSyAcnP2ggQFQMGZe8WwZsGdk4ckGwc05RL0",
    base_url="https://generativelanguage.googleapis.com/v1beta/openai/",
    http_client=httpx.AsyncClient(transport=transport) # <--- USE THE CUSTOM TRANSPORT
)

async def main():
    try:
        print("Attempting to connect to the API (forcing IPv4) to list models...")
        models = await client.models.list()
        print("\n✅ SUCCESS! Connection established.")
        print("Available models (first 5):")
        for model in list(models)[:5]:
            print(f"  - {model.id}")

    except Exception as e:
        print(f"\n❌ FAILED: An error occurred during the API call.")
        print(f"Error Type: {type(e).__name__}")
        print(f"Error Details: {e}")

if __name__ == "__main__":
    # Make sure you have httpx installed: pip install httpx
    asyncio.run(main())