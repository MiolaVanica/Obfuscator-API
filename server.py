from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
import json
import os
from cryptography.fernet import Fernet
from telegram import Bot, InlineKeyboardButton, InlineKeyboardMarkup
import asyncio
from dotenv import load_dotenv
from functools import wraps
import secrets
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()

app = FastAPI()

# Configuration
APPROVAL_BOT_TOKEN = os.getenv("APPROVAL_BOT_TOKEN")
ADMIN_CHAT_ID = os.getenv("ADMIN_CHAT_ID")
API_SECRET = os.getenv("API_SECRET")

# Generate RSA key pair for server
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# Load Fernet key
with open("fernet_key.bin", "rb") as f:
    FERNET_KEY = f.read()
fernet = Fernet(FERNET_KEY)

# Load encrypted code and mapping
with open("obfuscated_code.bin", "rb") as f:
    encrypted_code = f.read()
with open("mapping.bin", "rb") as f:
    encrypted_mapping = f.read()
obfuscated_code = fernet.decrypt(encrypted_code).decode()
reverse_mapping = json.loads(fernet.decrypt(encrypted_mapping).decode())

# Store pending requests
pending_requests = {}

class ExecutionRequest(BaseModel):
    secret: str
    session_key: str
    client_public_key: str

def require_secret(func):
    @wraps(func)
    async def wrapper(request: ExecutionRequest, *args, **kwargs):
        if request.secret != API_SECRET:
            logger.error("Invalid API secret provided")
            raise HTTPException(status_code=403, detail="Invalid API secret")
        return await func(request, *args, **kwargs)
    return wrapper

async def send_approval_message(request_id: str, session_key: str):
    try:
        bot = Bot(token=APPROVAL_BOT_TOKEN)
        keyboard = [
            [
                InlineKeyboardButton("Accept", callback_data=f"accept_{request_id}"),
                InlineKeyboardButton("Reject", callback_data=f"reject_{request_id}"),
            ]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await bot.send_message(
            chat_id=ADMIN_CHAT_ID,
            text=f"New execution request (ID: {request_id})\nSession Key: {session_key[:10]}...",
            reply_markup=reply_markup
        )
        logger.info(f"Sent approval message for request ID: {request_id}")
    except Exception as e:
        logger.error(f"Failed to send approval message: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to send approval message")

@app.get("/public_key")
async def get_public_key():
    try:
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        logger.info("Served public key")
        return {"public_key": public_pem.decode()}
    except Exception as e:
        logger.error(f"Error serving public key: {str(e)}")
        raise HTTPException(status_code=500, detail="Error serving public key")

@app.post("/execute")
@require_secret
async def execute_code(request: ExecutionRequest):
    logger.info(f"Received execution request with session_key: {request.session_key}")
    try:
        client_public_key = serialization.load_pem_public_key(request.client_public_key.encode())
    except Exception as e:
        logger.error(f"Invalid client public key: {str(e)}")
        raise HTTPException(status_code=400, detail="Invalid client public key")

    request_id = secrets.token_hex(16)
    pending_requests[request_id] = {
        "status": "pending",
        "result": None,
        "session_key": request.session_key,
        "client_public_key": client_public_key
    }
    logger.info(f"Stored pending request ID: {request_id}")
    
    await send_approval_message(request_id, request.session_key)
    
    for _ in range(300):
        if pending_requests[request_id]["status"] != "pending":
            break
        await asyncio.sleep(1)
    
    request_data = pending_requests.pop(request_id, None)
    if not request_data:
        logger.error(f"Request ID {request_id} timed out")
        raise HTTPException(status_code=408, detail="Request timed out")
    
    if request_data["status"] == "approved":
        logger.info(f"Request ID {request_id} approved")
        decrypted_code = obfuscated_code
        for code, original in reverse_mapping.items():
            decrypted_code = decrypted_code.replace(code, original)
        
        encrypted_code = request_data["client_public_key"].encrypt(
            decrypted_code.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return {"encrypted_code": encrypted_code.hex()}
    else:
        logger.info(f"Request ID {request_id} rejected")
        raise HTTPException(status_code=403, detail="Decryption Rejected! Contact @SCDP3")

@app.post("/handle_callback")
async def handle_callback(update: dict):
    logger.info(f"Received Telegram update: {update}")
    try:
        callback_data = update.get("callback_query", {}).get("data", "")
        if not callback_data:
            logger.error("No callback data in update")
            return {"status": "error", "message": "No callback data"}
        action, request_id = callback_data.split("_", 1)
        if request_id not in pending_requests:
            logger.error(f"Invalid request ID: {request_id}")
            return {"status": "error", "message": "Invalid request ID"}
        if action == "accept":
            pending_requests[request_id]["status"] = "approved"
            logger.info(f"Approved request ID: {request_id}")
        elif action == "reject":
            pending_requests[request_id]["status"] = "rejected"
            logger.info(f"Rejected request ID: {request_id}")
        return {"status": "success"}
    except Exception as e:
        logger.error(f"Error handling callback: {str(e)}")
        raise HTTPException(status_code=500, detail="Error handling callback")
