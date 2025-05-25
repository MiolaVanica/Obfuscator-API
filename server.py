import os
import asyncio
import secrets
from typing import Dict
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from cryptography.fernet import Fernet
import telegram
from telegram import InlineKeyboardButton, InlineKeyboardMarkup
from dotenv import load_dotenv
import logging
from datetime import datetime, timedelta

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()
load_dotenv()

# Bot configuration
APPROVAL_BOT_TOKEN = os.getenv("APPROVAL_BOT_TOKEN")
APPROVAL_CHAT_ID = os.getenv("APPROVAL_CHAT_ID")
bot = telegram.Bot(token=APPROVAL_BOT_TOKEN)

# In-memory storage for pending requests
pending_requests: Dict[str, Dict] = {}

class ExecutionRequest(BaseModel):
    secret: str
    session_key: str

class CallbackRequest(BaseModel):
    update: dict

# Load encrypted code and Fernet key
with open("obfuscated_code.bin", "rb") as f:
    encrypted_code = f.read()
with open("fernet_key.bin", "rb") as f:
    fernet_key = f.read()

@app.post("/execute")
async def execute_code(request: ExecutionRequest):
    if request.secret != os.getenv("API_SECRET"):
        raise HTTPException(status_code=403, detail="Invalid secret")
    
    request_id = secrets.token_hex(16)
    session_key = request.session_key
    
    # Store pending request with expiry
    pending_requests[request_id] = {
        "session_key": session_key,
        "created_at": datetime.now(),
        "approved": False
    }
    
    logger.info(f"Received execution request with session_key: {session_key}")
    logger.info(f"Stored pending request ID: {request_id}")
    
    # Send approval message to Telegram
    keyboard = [
        [
            InlineKeyboardButton("Accept", callback_data=f"accept_{request_id}"),
            InlineKeyboardButton("Reject", callback_data=f"reject_{request_id}")
        ]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    message = await bot.send_message(
        chat_id=APPROVAL_CHAT_ID,
        text=f"New execution request (ID: {request_id})\nSession Key: {session_key[:10]}...",
        reply_markup=reply_markup
    )
    logger.info(f"Sent approval message for request ID: {request_id}")
    
    # Wait for approval (up to 5 minutes)
    start_time = datetime.now()
    while (datetime.now() - start_time).total_seconds() < 300:
        if request_id in pending_requests and pending_requests[request_id]["approved"]:
            logger.info(f"Request ID {request_id} approved")
            del pending_requests[request_id]
            return {
                "encrypted_code": encrypted_code.hex(),
                "fernet_key": fernet_key.hex()
            }
        await asyncio.sleep(1)
    
    # Timeout or rejection
    if request_id in pending_requests:
        del pending_requests[request_id]
    raise HTTPException(status_code=400, detail="Request timed out or rejected")

@app.post("/handle_callback")
async def handle_callback(callback: CallbackRequest):
    update = telegram.Update.de_json(callback.update, bot)
    logger.info(f"Received Telegram update: {callback.update}")
    
    if not update.callback_query:
        logger.info("Ignoring non-callback update")
        return {"status": "ignored"}
    
    query = update.callback_query
    await query.answer()
    
    data = query.data
    logger.info(f"Processing callback data: {data}")
    
    if not data:
        logger.error("No callback data received")
        return {"status": "error", "message": "No callback data"}
    
    if data.startswith("accept_") or data.startswith("reject_"):
        request_id = data.split("_", 1)[1]
        if request_id not in pending_requests:
            logger.error(f"Unknown request ID: {request_id}")
            await query.message.edit_text("Error: Request ID not found or expired")
            return {"status": "error", "message": "Unknown request ID"}
        
        if data.startswith("accept_"):
            pending_requests[request_id]["approved"] = True
            logger.info(f"Approved request ID: {request_id}")
            await query.message.edit_text(f"Request ID {request_id} approved")
        else:
            del pending_requests[request_id]
            logger.info(f"Rejected request ID: {request_id}")
            await query.message.edit_text(f"Request ID {request_id} rejected")
        
        logger.info(f"Answered callback query ID: {query.id}")
        return {"status": "processed"}
    
    logger.error("Unknown callback data")
    return {"status": "error", "message": "Unknown callback data"}