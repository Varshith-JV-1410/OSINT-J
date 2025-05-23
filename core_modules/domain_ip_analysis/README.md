# Domain and IP Analysis Module

## Overview

The Domain and IP Analysis module is a core component of the All-In-One OSINT Platform. It provides essential tools for gathering information about domain names and IP addresses. Currently, it supports WHOIS lookups, DNS record retrieval, and includes a placeholder for future Shodan integration for IP address intelligence.

## Features

-   **WHOIS Information (`get_whois_info`)**: Retrieves WHOIS data for a given domain or IP address, including registrar details, contact information (where available), name servers, and domain status.
-   **DNS Records (`get_dns_records`)**: Fetches common DNS records (A, MX, TXT) for a specified domain.
-   **Shodan IP Lookup (`get_shodan_info`)**: Placeholder for querying the Shodan API to get information about an IP address (e.g., open ports, services, vulnerabilities). Full implementation is pending.

## Requirements

This module relies on the following Python libraries:

-   `python-whois`: For WHOIS lookups.
-   `dnspython`: For DNS record retrieval.
-   `shodan`: For Shodan API interaction (currently a placeholder).
-   `click`: For building the command-line interface.

These dependencies are listed in `core_modules/domain_ip_analysis/requirements.txt` and can be installed by navigating to this directory and running:

```bash
pip install -r requirements.txt
```

## CLI Usage

The module includes a command-line interface (CLI) for direct interaction with its functionalities. To use the CLI, navigate to the project's root directory and run the module using Python's `-m` flag.

The general command structure is:

```bash
python -m core_modules.domain_ip_analysis.cli <command> [options] <target>
```

### Commands:

1.  **`whois <domain_or_ip>`**
    *   Performs a WHOIS lookup for the specified domain name or IP address.
    *   **Example:**
        ```bash
        python -m core_modules.domain_ip_analysis.cli whois google.com
        ```
    *   **Output:** Prints the WHOIS information as a JSON object if successful. If data is not found or an error occurs, it prints an informative message. For IP addresses, WHOIS data can be limited.

2.  **`dns <domain>`**
    *   Fetches A, MX, and TXT DNS records for the specified domain.
    *   **Example:**
        ```bash
        python -m core_modules.domain_ip_analysis.cli dns google.com
        ```
    *   **Output:** Prints a structured list of DNS records, grouped by type (A, MX, TXT). If no records are found for a type, it indicates so. Errors (e.g., domain not found) are printed as messages.

3.  **`shodan <ip_address> [--api-key YOUR_KEY]`**
    *   Attempts a Shodan lookup for the specified IP address.
    *   **Note:** This feature is currently a placeholder. It will indicate that full implementation and API key handling are pending.
    *   **Example:**
        ```bash
        python -m core_modules.domain_ip_analysis.cli shodan 1.1.1.1
        python -m core_modules.domain_ip_analysis.cli shodan 1.1.1.1 --api-key YOUR_SHODAN_API_KEY
        ```
    *   **Output:** Currently, it prints a message indicating that Shodan integration is pending or requires an API key. The `--api-key` option is available, but full functionality is not yet implemented. In the future, the Shodan API key will ideally be managed through a central configuration file (e.g., `config/api_keys.yml`).

## Running Tests

Unit tests are provided to ensure the module's functionality. To run the tests, navigate to the project's root directory and execute:

```bash
python -m unittest discover -s core_modules/domain_ip_analysis/tests -p "test_*.py"
```
Alternatively, you can navigate into the `core_modules/domain_ip_analysis/tests` directory and run:
```bash
python -m unittest test_main.py
```

## Developer Notes

-   **`main.py`**: Contains the core logic for the WHOIS, DNS, and Shodan lookup functions. It handles interactions with external libraries and data processing.
-   **`cli.py`**: Implements the command-line interface using the `click` library. It parses arguments and calls the respective functions in `main.py`, then formats and displays the output.
-   **`tests/test_main.py`**: Contains unit tests for the functions in `main.py`, utilizing `unittest.mock` to simulate external calls and error conditions.

This documentation should provide a good starting point for using and developing the Domain and IP Analysis module.
