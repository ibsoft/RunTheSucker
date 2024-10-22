# tools/whois_tool.py
import whois


def query_whois(ip_address):
    try:
        # Using WHOIS to retrieve information
        whois_info = whois.whois(ip_address)
        return {
            'domain_name': whois_info.domain_name,
            'registrar': whois_info.registrar,
            'whois_server': whois_info.whois_server,
            'referral_url': whois_info.referral_url,
            'updated_date': whois_info.updated_date,
            'creation_date': whois_info.creation_date,
            'expiration_date': whois_info.expiration_date,
            'name_servers': whois_info.name_servers
        }
    except Exception as e:
        return {'error': str(e)}
