import os
from dotenv import load_dotenv

load_dotenv()

# Telegram API credentials (shared)
API_ID = int(os.getenv("API_ID", "0"))
API_HASH = os.getenv("API_HASH", "")
NGROK_URL = os.getenv("NGROK_URL", "")

def load_bots():
    """Load all bot configurations from .env"""
    bots = {}
    i = 1
    
    while True:
        token = os.getenv(f"BOT_{i}_TOKEN")
        if not token:
            break
        
        bot_id = token.split(":")[0]
        bots[bot_id] = {
            'id': bot_id,
            'token': token,
            'name': os.getenv(f"BOT_{i}_NAME", f"Bot{i}"),
            'admin_id': os.getenv(f"BOT_{i}_ADMIN_ID", ""),
            'index': i
        }
        i += 1
    
    return bots

# Load all bots
BOTS = load_bots()

def get_bot_by_id(bot_id):
    """Get bot config by bot ID"""
    return BOTS.get(str(bot_id))

def get_bot_by_token(token):
    """Get bot config by token"""
    bot_id = token.split(":")[0]
    return BOTS.get(bot_id)

def get_all_bots():
    """Get all bot configurations"""
    return BOTS

def get_admin_id(bot_id):
    """Get admin chat ID for a specific bot"""
    bot = get_bot_by_id(bot_id)
    return bot['admin_id'] if bot else None

# Print loaded bots on import
print(f"\n📋 Loaded {len(BOTS)} bot(s):")
for bot_id, config in BOTS.items():
    print(f"   • {config['name']} (ID: {bot_id}) → Admin: {config['admin_id']}")
print()
