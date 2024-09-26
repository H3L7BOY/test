import logging
import re
from telegram import Update
from telegram.ext import ApplicationBuilder, MessageHandler, filters, ContextTypes

# Set up logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

# Replace with your bot token
BOT_TOKEN = '7103493107:AAGxkbuN8RfQogoEaEWD5-_oR6Uw4AvU8Pw'

# Regex to identify Telegram group links
GROUP_LINK_REGEX = r'https://t.me/blackheadscc'

async def handle_group_link(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    message_text = update.message.text
    if re.search(GROUP_LINK_REGEX, message_text):
        await update.message.reply_text("I can't join groups automatically, but you can invite me!")

def main() -> None:
    application = ApplicationBuilder().token(BOT_TOKEN).build()

    # Handler for messages containing group links
    message_handler = MessageHandler(filters.TEXT, handle_group_link)
    application.add_handler(message_handler)

    application.run_polling()

if __name__ == '__main__':
    main()
