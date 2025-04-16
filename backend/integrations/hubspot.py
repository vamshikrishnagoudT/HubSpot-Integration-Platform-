import json
import secrets
from fastapi import Request, HTTPException
from fastapi.responses import HTMLResponse
import httpx
import asyncio
import base64
from integrations.integration_item import IntegrationItem
from redis_client import add_key_value_redis, get_value_redis, delete_key_redis
from dotenv import load_dotenv
import os

load_dotenv()

CLIENT_ID = os.getenv("HUBSPOT_CLIENT_ID", "133a33e9-6e48-4fd3-b0a3-f0e064318cb7")
CLIENT_SECRET = os.getenv("HUBSPOT_CLIENT_SECRET", "1dd4908b-44f0-4338-89d0-f5a40d48864a")
REDIRECT_URI = "http://localhost:8000/integrations/hubspot/oauth2callback"
encoded_client_id_secret = base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()
authorization_url = f"https://app.hubspot.com/oauth/authorize?client_id={CLIENT_ID}&response_type=code&redirect_uri={REDIRECT_URI}"

async def authorize_hubspot(user_id, org_id):
    if not CLIENT_ID or not CLIENT_SECRET:
        raise HTTPException(status_code=500, detail="HubSpot credentials not configured")
    state_data = {
        "state": secrets.token_urlsafe(32),
        "user_id": user_id,
        "org_id": org_id
    }
    encoded_state = json.dumps(state_data)
    await add_key_value_redis(f"hubspot_state:{org_id}:{user_id}", encoded_state, expire=600)
    # Update scope to include both required scopes
    auth_url = f"{authorization_url}&state={encoded_state}&scope=crm.objects.contacts.read%20crm.objects.contacts.write"
    return auth_url

async def oauth2callback_hubspot(request: Request):
    if request.query_params.get("error"):
        raise HTTPException(status_code=400, detail=request.query_params.get("error_description"))
    code = request.query_params.get("code")
    encoded_state = request.query_params.get("state")
    state_data = json.loads(encoded_state)
    original_state = state_data.get("state")
    user_id = state_data.get("user_id")
    org_id = state_data.get("org_id")
    saved_state = await get_value_redis(f"hubspot_state:{org_id}:{user_id}")
    if not saved_state or original_state != json.loads(saved_state).get("state"):
        raise HTTPException(status_code=400, detail="State does not match.")
    async with httpx.AsyncClient() as client:
        response, _ = await asyncio.gather(
            client.post(
                "https://api.hubapi.com/oauth/v1/token",
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": REDIRECT_URI,
                    "client_id": CLIENT_ID,
                    "client_secret": CLIENT_SECRET
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            ),
            delete_key_redis(f"hubspot_state:{org_id}:{user_id}")
        )
    if response.status_code != 200:
        raise HTTPException(status_code=400, detail="Failed to get tokens")
    credentials = response.json()
    await add_key_value_redis(f"hubspot_credentials:{org_id}:{user_id}", json.dumps(credentials), expire=600)
    close_window_script = """
    <html>
        <script>
            window.close();
        </script>
    </html>
    """
    return HTMLResponse(content=close_window_script)

async def get_hubspot_credentials(user_id, org_id):
    credentials = await get_value_redis(f"hubspot_credentials:{org_id}:{user_id}")
    if not credentials:
        raise HTTPException(status_code=400, detail="No credentials found.")
    credentials = json.loads(credentials)
    await delete_key_redis(f"hubspot_credentials:{org_id}:{user_id}")
    return credentials

async def create_integration_item_metadata_object(response_json):
    # To be implemented in Sprint 3
    pass

async def get_items_hubspot(credentials):
    # To be implemented in Sprint 3
    pass