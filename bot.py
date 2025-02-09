import requests
import json

url = 'http://194.15.36.55:8821/purchase'

payload = {
    "shop_url": "https://lemonsandfood.com",
    "card_info": "484187878|12|26|470",
    "proxy": "" # optional
}

response = requests.post(url, json=payload)

if response.status_code == 200:
    print("Request successful:", response.json())
else:
    print(f"Error: {response.status_code}, {response.json()}")
