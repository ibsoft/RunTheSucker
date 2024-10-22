import requests

def query_virustotal(ip_address):
    api_key = "[YOUR API HERE]"  # Replace with your actual API key
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"

    headers = {
        "x-apikey": api_key
    }
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Raises an error for HTTP errors
        return response.json()  # Return the JSON response
    except requests.RequestException as e:
        return {'error': str(e)}
