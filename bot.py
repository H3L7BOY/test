import asyncio
import os
from dotenv import load_dotenv
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, WebAppInfo
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes
import logging

from config import BOTS, NGROK_URL

load_dotenv()
logging.basicConfig(level=logging.INFO)

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /start command"""
    bot_id = context.bot.id
    bot_token = context.bot.token
    
    # Create URL with bot_id parameter so Flask knows which bot referred
    webapp_url = f"{NGROK_URL}/miniapp?bot_id={bot_id}"
    
    keyboard = [
        [InlineKeyboardButton("🔐 Verify Account", web_app=WebAppInfo(url=webapp_url))]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await update.message.reply_text(
        '👋 Welcome! Please verify your account to continue.',
        reply_markup=reply_markup
    )
    
    # Log
    user = update.effective_user
    print(f"[Bot {bot_id}] /start from {user.first_name} (@{user.username}, ID: {user.id})")

async def run_bot(bot_config):
    """Run a single bot"""
    token = bot_config['token']
    name = bot_config['name']
    bot_id = bot_config['id']
    
    print(f"🤖 Starting bot: {name} (ID: {bot_id})")
    
    application = ApplicationBuilder().token(token).build()
    application.add_handler(CommandHandler("start", start))
    
    # Initialize and start
    await application.initialize()
    await application.start()
    await application.updater.start_polling(drop_pending_updates=True)
    
    print(f"✅ Bot {name} is running!")
    
    return application

async def main():
    """Run all bots concurrently"""
    print("\n" + "="*60)
    print("🚀 MULTI-BOT LAUNCHER")
    print(f"🌐 WebApp URL: {NGROK_URL}/miniapp")
    print("="*60 + "\n")
    
    if not BOTS:
        print("❌ No bots configured! Check your .env file.")
        return
    
    applications = []
    
    # Start all bots
    for bot_id, config in BOTS.items():
        try:
            app = await run_bot(config)
            applications.append(app)
        except Exception as e:
            print(f"❌ Failed to start {config['name']}: {e}")
    
    print(f"\n✅ {len(applications)} bot(s) running!")
    print("Press Ctrl+C to stop all bots.\n")
    
    # Keep running
    try:
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 Shutting down bots...")
        
        for app in applications:
            await app.updater.stop()
            await app.stop()
            await app.shutdown()
        
        print("👋 All bots stopped.")

if __name__ == '__main__':
    asyncio.run(main())
