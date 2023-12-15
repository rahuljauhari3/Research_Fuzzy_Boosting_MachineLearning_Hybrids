from cryptography.hazmat.primitives.asymmetric import ed25519
from urllib.parse import urlparse, urlencode
import urllib
import json
import requests


def remove_trailing_zeros(dictionary):
    for key, value in dictionary.items():
        if isinstance(value, (int, float)) and dictionary[key] == int(dictionary[key]):
            dictionary[key] = int(dictionary[key])
    return dictionary


def get_signature_of_request(secret_key: str, request_string: str) -> str:
    try:
        request_string = bytes(request_string, 'utf-8')
        secret_key_bytes = bytes.fromhex(secret_key)
        secret_key = ed25519.Ed25519PrivateKey.from_private_bytes(secret_key_bytes)
        signature_bytes = secret_key.sign(request_string)
        signature = signature_bytes.hex()
    except ValueError:
        return False
        raise ValueError("Please Enter valid keys")
    return signature


def signatureMessage(method: str, url: str, payload: dict):
    message = method + url + json.dumps(payload, separators=(',', ':'), sort_keys=True)
    return message


class ApiTradingClient:
    secret_key = None
    api_key = None

    def __init__(self, secret_key: str, api_key: str):
        self.secret_key = secret_key
        self.api_key = api_key
        self.base_url = "https://coinswitch.co"
        self.headers = {
            "Content-Type": "application/json"
        }

    def call_api(self, url: str, method: str, headers: dict = None, payload: dict = {}):
        final_headers = self.headers.copy()
        if headers is not None:
            final_headers.update(headers)

        response = requests.request(method, url, headers=headers, json=payload)
        if response.status_code == 429:
            print("rate limiting")

        return response.json()

    def make_request(self, method: str, endpoint: str, payload: dict = {}, params: dict = {}):
        decoded_endpoint = endpoint
        if method == "GET" and len(params) != 0:
            endpoint += ('&', '?')[urlparse(endpoint).query == ''] + urlencode(params)
            decoded_endpoint = urllib.parse.unquote_plus(endpoint)

        signature_msg = signatureMessage(method, decoded_endpoint, payload)

        signature = get_signature_of_request(self.secret_key, signature_msg)
        if signature == False:
            return {"message": "Please Enter Valid Keys"}

        headers = {
            "X-AUTH-SIGNATURE": signature,
            "X-AUTH-APIKEY": self.api_key
        }

        url = f"{self.base_url}{endpoint}"

        response = self.call_api(url, method, headers=headers, payload=payload)
        return json.dumps(response, indent=4)

    def check_connection(self):
        return self.make_request("GET", "/api-trading-service/api/v1/ping")

    def validate_keys(self):
        return self.make_request("GET", "/api-trading-service/api/v1/validate/keys")

    def create_order(self, payload: dict = {}):
        return self.make_request("POST", "/trade/api/v2/order", payload=payload)

    def cancel_order(self, payload: dict = {}):
        return self.make_request("DELETE", "/trade/api/v2/order", payload=payload)

    def get_open_orders(self, params: dict = {}):
        return self.make_request("GET", "/trade/api/v2/orders", params=params)

    def get_closed_orders(self, params: dict = {}):
        return self.make_request("GET", "/trade/api/v2/orders", params=params)

    def get_user_portfolio(self):
        return self.make_request("GET", "/trade/api/v2/user/portfolio")

    def get_24h_all_pairs_data(self, params: dict = {}):
        return self.make_request("GET", "/trade/api/v2/24hr/all-pairs/ticker", params=params)

    def get_24h_coin_pair_data(self, params: dict = {}):
        return self.make_request("GET", "/trade/api/v2/24hr/ticker", params=params)

    def get_depth(self, params: dict = {}):
        return self.make_request("GET", "/trade/api/v2/depth", params=params)

    def get_trades(self, params: dict = {}):
        return self.make_request("GET", "/trade/api/v2/trades", params=params)

    def get_candlestick_data(self, params: dict = {}):
        return self.make_request("GET", "/trade/api/v2/candles", params=params)

    def get_exchange_precision(self, payload: dict = {}):
        return self.make_request("POST", "/trade/api/v2/exchangePrecision", payload=payload)

    def get_order(self, params: dict = {}):
        return self.make_request("GET", "/trade/api/v2/order", params=params)

    def get_active_coins(self, params: dict = {}):
        return self.make_request("GET", "/trade/api/v2/coins", params=params)


secret_key = ""  # provided by coinswitch
api_key = ""    # provided by coinswitch

api_trading_client = ApiTradingClient(secret_key, api_key)

# check connection (To check connection to endpoints)
# print(api_trading_client.check_connection())

# create order
payload = {
    "side": "buy",              # BUY/SELL value only
    "symbol": "USDT/INR",       # eg; BTC/USDT for binance, BTC/INR for csx and wazirx
    "type": "limit",            # Limit order as is
    "price": 86.48,             # refer to binance UI for prices
    "quantity": 8.40,           # minimum 10 USDT worth coins in case of binance
    "exchange": "coinswitchx"   # COINSWITCHX / BINANCE / WAZIRX
}
# print(api_trading_client.create_order(payload=payload))

# cancel order
payload = {
    "order_id": "a4886f94-1652-4cf6-9019-4f3fd9ec5359"
}
# print(api_trading_client.cancel_order(payload=payload))

# get portfolio
# print(api_trading_client.get_user_portfolio())

# get open orders
params = {
    "count": 20,
    "from_time": 1600261657954,
    "to_time": 1687261657954,
    "side": "sell",
    "symbol": "usdt/inr",
    "exchange": "coinswitchx,wazirx",
    "type": "limit",
}
# print(api_trading_client.get_open_orders(params = params))

# get closed orders
params = {
    "count": 20,
    "from_time": 1600261657954,
    "to_time": 1687261657954,
    "side": "sell",
    "symbol": "btc/inr,eth/inr",
    "exchange": "coinswitchx,wazirx",
    "type": "limit",
    "status": "EXECUTED"
}
# print(api_trading_client.get_closed_orders(params = params))

# get ticker 24hr all pair data
params = {
    "exchange": "COINSWITCHX"
}
# print(api_trading_client.get_24h_all_pairs_data(params=params))

# get ticker data of coin pair
params = {
    "symbol": "btc/inr",
    "exchange": 'coinswitchx,wazirx'
}
# print(api_trading_client.get_24h_coin_pair_data(params=params))

# get candlestick data
params = {
    "end_time": "1662681600000",
    "start_time": "1647388800000",
    "symbol": "BTC/INR",
    "interval": "1440",
    "exchange": "wazirx"
}
# print(api_trading_client.get_candlestick_data(params = params))


# get trades
params = {
    "exchange": "WAZIRX",
    "symbol": "btc/inr"
}
# print(api_trading_client.get_trades(params=params))

# get exchange precision
payload = {
    "exchange": "binance"
}
# print(api_trading_client.get_exchange_precision(payload = payload))

# #get depth
params = {
    "exchange": "wazirx",
    "symbol": "xlm/inr"
}
# print(api_trading_client.get_depth(params = params))

# GET_ORDER
params = {
    "order_id": "81ec20ac-a4a3-4eda-9b2b-81d41cc09dde",
}
# print(api_trading_client.get_order(params=params))

# get active coins
params = {
    "exchange": "binance",
}
# print(api_trading_client.get_active_coins(params=params))
