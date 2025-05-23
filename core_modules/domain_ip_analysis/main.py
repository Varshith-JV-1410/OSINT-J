import whois
import dns.resolver
import logging
import shodan

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def get_whois_info(domain_or_ip):
    """
    Performs a WHOIS lookup for a given domain or IP address.

    Args:
        domain_or_ip (str): The domain name or IP address.

    Returns:
        str or dict: The WHOIS information, or an error message.
    """
    logging.info(f"Performing WHOIS lookup for: {domain_or_ip}")
    try:
        w = whois.whois(domain_or_ip)
        if w.status is None and not w.name_servers : #.name_servers is empty for some invalid domains
             if not w.get('domain_name'): # Check if domain_name is None or empty
                logging.warning(f"No WHOIS data found or invalid domain/IP: {domain_or_ip}")
                return "No WHOIS data found or invalid domain/IP."
        return w
    except whois.parser.PywhoisError as e:
        logging.error(f"WHOIS lookup failed for {domain_or_ip}: {e}")
        return f"WHOIS lookup failed: {e}"
    except Exception as e:
        logging.error(f"An unexpected error occurred during WHOIS lookup for {domain_or_ip}: {e}")
        return f"An unexpected error occurred: {e}"

def get_dns_records(domain):
    """
    Fetches A, MX, and TXT DNS records for a given domain.

    Args:
        domain (str): The domain name.

    Returns:
        dict: A dictionary containing DNS records, or an error message.
    """
    logging.info(f"Fetching DNS records for: {domain}")
    records = {}
    record_types = ['A', 'MX', 'TXT']
    
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            records[record_type] = [str(rdata) for rdata in answers]
        except dns.resolver.NoAnswer:
            records[record_type] = []
            logging.warning(f"No {record_type} records found for {domain}")
        except dns.resolver.NXDOMAIN:
            logging.error(f"Domain not found: {domain}")
            return f"DNS lookup failed: Domain not found ({domain})"
        except dns.exception.Timeout:
            logging.error(f"DNS lookup timed out for {domain}")
            return f"DNS lookup failed: Timed out ({domain})"
        except Exception as e:
            logging.error(f"An unexpected error occurred during DNS lookup for {domain} ({record_type}): {e}")
            return f"An unexpected error occurred during DNS lookup ({record_type}): {e}"
            
    return records

def get_shodan_info(ip_address, api_key):
    """
    Placeholder for Shodan IP lookup.

    Args:
        ip_address (str): The IP address to query.
        api_key (str): The Shodan API key.

    Returns:
        str: A placeholder message.
    """
    logging.info(f"Attempting Shodan lookup for IP: {ip_address}")
    if not api_key:
        logging.warning("Shodan API key not provided.")
        return "Shodan integration pending API key."
    
    # Actual Shodan API call would go here
    # For now, just a placeholder
    try:
        # api = shodan.Shodan(api_key)
        # host_info = api.host(ip_address)
        # return host_info 
        # For now, returning placeholder
        logging.info("Shodan integration is not fully implemented yet.")
        return "Shodan integration pending API key and full implementation."
    except Exception as e:
        logging.error(f"Error during Shodan lookup for {ip_address}: {e}")
        return f"Error during Shodan lookup: {e}"
