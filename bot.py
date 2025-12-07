import os
from dotenv import load_dotenv
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, WebAppInfo
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes
import logging

load_dotenv()

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
NGROK_URL = os.getenv("NGROK_URL", "https://polycarpellary-tonisha-implicatively.ngrok-free.dev")

logging.basicConfig(level=logging.DEBUG)

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    keyboard = [
        [InlineKeyboardButton("🔐 Start Verification", web_app=WebAppInfo(url=f"{NGROK_URL}/miniapp"))]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text(
        '👋 Welcome! Click the button below to verify your account.',
        reply_markup=reply_markup
    )

def main() -> None:
    print("\n" + "="*50)
    print(f"🤖 Bot starting...")
    print(f"🌐 WebApp URL: {NGROK_URL}/miniapp")
    print("="*50 + "\n")
    
    application = ApplicationBuilder().token(TELEGRAM_BOT_TOKEN).build()
    application.add_handler(CommandHandler("start", start))
    application.run_polling()

if __name__ == '__main__':
    main()
