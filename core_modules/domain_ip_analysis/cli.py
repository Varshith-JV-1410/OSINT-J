import click
import logging
import json # For pretty printing dicts
from .main import get_whois_info, get_dns_records, get_shodan_info
# It's good practice to also import any necessary config loading here if we were to use api_keys.yml
# For now, we'll just pass the API key as an option for Shodan

# Configure basic logging for the CLI, if not already configured by main
# This ensures CLI-specific messages or issues during CLI operation are caught.
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

@click.group()
def cli():
    """A CLI tool for Domain and IP Analysis."""
    pass

@cli.command()
@click.argument('target', required=True)
def whois(target):
    """Performs a WHOIS lookup for a domain or IP address."""
    click.echo(f"Fetching WHOIS information for: {target}...")
    result = get_whois_info(target)
    if isinstance(result, dict):
        # Attempt to print a more structured output for WHOIS if it's a dict
        # whois library can return a string or a dict like object
        try:
            # Filter out None values for cleaner output and handle potential non-string items
            filtered_result = {k: (v if isinstance(v, (str, list, dict, int, float, bool)) else str(v)) 
                               for k, v in result.items() if v is not None}
            click.echo(json.dumps(filtered_result, indent=4, default=str)) # use default=str for non-serializable
        except TypeError: # Fallback for complex, non-serializable whois objects
             click.echo(str(result)) # Convert the whole result to string if specific items fail
    else:
        click.echo(result)

@cli.command()
@click.argument('domain', required=True)
def dns(domain):
    """Fetches A, MX, and TXT DNS records for a domain."""
    click.echo(f"Fetching DNS records for: {domain}...")
    result = get_dns_records(domain)
    if isinstance(result, str): # Error message
        click.echo(click.style(result, fg='red'))
    else:
        click.echo(click.style("DNS Records:", bold=True))
        for record_type, records in result.items():
            click.echo(click.style(f"  {record_type}:", fg='green'))
            if records:
                for record_data in records:
                    click.echo(f"    - {record_data}")
            else:
                click.echo("      No records found.")

@cli.command()
@click.argument('ip_address', required=True)
@click.option('--api-key', help="Your Shodan API key. Alternatively, configure it in config/api_keys.yml (not implemented yet).")
def shodan(ip_address, api_key):
    """
    Performs a Shodan lookup for an IP address.
    (Note: Full Shodan functionality is pending.)
    """
    click.echo(f"Attempting Shodan lookup for IP: {ip_address}...")
    if not api_key:
        click.echo(click.style("Shodan API key not provided. You can use --api-key YOUR_KEY.", fg='yellow'))
        click.echo(click.style("Alternatively, configure it in config/api_keys.yml (this feature is not fully implemented yet).", fg='yellow'))
        # Proceed with the call, main.py handles the missing API key for now
    
    # In a real scenario, you'd load the API key from a config file here if not provided
    # For now, get_shodan_info handles the logic if api_key is None
    result = get_shodan_info(ip_address, api_key)
    
    if isinstance(result, str) and ("pending" in result or "Error" in result or "failed" in result):
        click.echo(click.style(result, fg='yellow'))
    elif isinstance(result, dict): # Assuming successful Shodan query returns a dict
        click.echo(json.dumps(result, indent=4))
    else: # Other string messages or unexpected results
        click.echo(result)

if __name__ == '__main__':
    cli()
