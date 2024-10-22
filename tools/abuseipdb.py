import requests

API_KEY = "[YOUR API HERE]"
BASE_URL = "https://api.abuseipdb.com/api/v2/check"

def query_ip(ip_address):
    headers = {
        'Accept': 'application/json',
        'Key': API_KEY
    }
    params = {
        'ipAddress': ip_address,
        'maxAgeInDays': 90
    }

    response = requests.get(BASE_URL, headers=headers, params=params)
    if response.status_code == 200:
        return response.json()
    else:
        return {'error': 'Unable to fetch data from AbuseIPDB'}
