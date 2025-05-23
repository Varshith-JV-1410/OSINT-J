import unittest
from unittest.mock import patch, MagicMock
import logging

# Since we are running tests from the root directory, we need to adjust the import path
from core_modules.domain_ip_analysis.main import get_whois_info, get_dns_records, get_shodan_info

# Import exceptions for mocking
from whois.parser import PywhoisError
from dns.resolver import NXDOMAIN, NoAnswer, Timeout
from dns.exception import DNSException


# Suppress most logging output during tests for cleaner test results
# logging.disable(logging.CRITICAL) # Keep this commented or manage more granularly

class TestMainAnalysis(unittest.TestCase):

    @patch('core_modules.domain_ip_analysis.main.whois.whois')
    def test_get_whois_info_valid_domain(self, mock_whois):
        """Test get_whois_info with a valid domain."""
        mock_whois_return = MagicMock()
        mock_whois_return.domain_name = "google.com"
        mock_whois_return.registrar = "MarkMonitor Inc."
        mock_whois_return.name_servers = ["ns1.google.com", "ns2.google.com"]
        mock_whois_return.status = "clientDeleteProhibited"
        mock_whois_return.emails = "abusecomplaints@markmonitor.com"
        mock_whois_return.get.return_value = "google.com"
        mock_whois.return_value = mock_whois_return

        result = get_whois_info("google.com")
        self.assertEqual(result.domain_name, "google.com")
        self.assertIn("ns1.google.com", result.name_servers)
        mock_whois.assert_called_once_with("google.com")

    @patch('core_modules.domain_ip_analysis.main.whois.whois')
    def test_get_whois_info_invalid_domain_exception(self, mock_whois):
        """Test get_whois_info with an invalid domain raising PywhoisError."""
        mock_whois.side_effect = PywhoisError("Mocked WHOIS lookup failed")
        
        result = get_whois_info("invalid-domain-example.com")
        self.assertEqual(result, "WHOIS lookup failed: Mocked WHOIS lookup failed")
        mock_whois.assert_called_once_with("invalid-domain-example.com")

    @patch('core_modules.domain_ip_analysis.main.whois.whois')
    def test_get_whois_info_no_data(self, mock_whois):
        """Test get_whois_info when no WHOIS data is returned (e.g., empty/None fields)."""
        mock_whois_return = MagicMock()
        mock_whois_return.status = None
        mock_whois_return.name_servers = [] 
        mock_whois_return.get.return_value = None
        mock_whois_return.domain_name = None 
        mock_whois.return_value = mock_whois_return
        
        result = get_whois_info("nodata.com")
        self.assertEqual(result, "No WHOIS data found or invalid domain/IP.")
        mock_whois.assert_called_once_with("nodata.com")
        mock_whois_return.get.assert_called_once_with('domain_name')

    @patch('core_modules.domain_ip_analysis.main.dns.resolver.resolve')
    def test_get_dns_records_valid_domain(self, mock_resolve):
        """Test get_dns_records with a valid domain."""
        mock_a_record = MagicMock()
        mock_a_record.address = "192.0.2.1"
        mock_a_record.__str__ = lambda self: self.address # Ensure str(mock_a_record) returns the IP

        mock_mx_record = MagicMock()
        # dnspython MX rdata objects have 'exchange' which is a Name object. str() on it gives FQDN.
        mock_mx_record.exchange.to_text.return_value = "mail.example.com." 
        mock_mx_record.__str__ = lambda self: self.exchange.to_text()


        mock_txt_record = MagicMock()
        # dnspython TXT rdata objects have 'strings' (list of bytes)
        mock_txt_record.strings = [b"v=spf1 include:_spf.example.com ~all"]
        mock_txt_record.__str__ = lambda self: b" ".join(self.strings).decode('utf-8').strip('"')


        def resolve_side_effect(domain, record_type):
            if record_type == 'A':
                return [mock_a_record]
            elif record_type == 'MX':
                return [mock_mx_record]
            elif record_type == 'TXT':
                return [mock_txt_record]
            raise ValueError(f"Unexpected record type: {record_type}")

        mock_resolve.side_effect = resolve_side_effect
        
        expected_result = {
            'A': ['192.0.2.1'],
            'MX': ['mail.example.com.'],
            'TXT': ["v=spf1 include:_spf.example.com ~all"]
        }
        result = get_dns_records("example.com")
        self.assertEqual(result, expected_result)
        self.assertEqual(mock_resolve.call_count, 3)

    @patch('core_modules.domain_ip_analysis.main.dns.resolver.resolve')
    def test_get_dns_records_nxdomain(self, mock_resolve):
        """Test get_dns_records with a domain that results in NXDOMAIN."""
        mock_resolve.side_effect = NXDOMAIN
        
        result = get_dns_records("nonexistent-domain.com")
        self.assertEqual(result, "DNS lookup failed: Domain not found (nonexistent-domain.com)")
        mock_resolve.assert_called_once() 

    @patch('core_modules.domain_ip_analysis.main.dns.resolver.resolve')
    def test_get_dns_records_no_answer(self, mock_resolve):
        """Test get_dns_records when a specific record type has no answer."""
        mock_a_record = MagicMock()
        mock_a_record.address = "192.0.2.1"
        mock_a_record.__str__ = lambda self: self.address


        def resolve_side_effect(domain, record_type):
            if record_type == 'A':
                return [mock_a_record]
            elif record_type == 'MX':
                raise NoAnswer 
            elif record_type == 'TXT':
                raise NoAnswer 
            raise ValueError(f"Unexpected record type: {record_type}")

        mock_resolve.side_effect = resolve_side_effect
        
        expected_result = {
            'A': ['192.0.2.1'],
            'MX': [],
            'TXT': []
        }
        result = get_dns_records("example.com")
        self.assertEqual(result, expected_result)
        self.assertEqual(mock_resolve.call_count, 3)
        
    @patch('core_modules.domain_ip_analysis.main.dns.resolver.resolve')
    def test_get_dns_records_timeout(self, mock_resolve):
        """Test get_dns_records with a DNS timeout."""
        mock_resolve.side_effect = Timeout
        
        result = get_dns_records("timeout-domain.com")
        self.assertEqual(result, "DNS lookup failed: Timed out (timeout-domain.com)")
        mock_resolve.assert_called_once()

    def test_get_shodan_info_no_api_key(self):
        """Test get_shodan_info returns the placeholder message when no API key."""
        result = get_shodan_info("1.1.1.1", None)
        self.assertEqual(result, "Shodan integration pending API key.")

    def test_get_shodan_info_with_api_key_placeholder(self):
        """Test get_shodan_info returns the placeholder message even with an API key (current behavior)."""
        result = get_shodan_info("1.1.1.1", "DUMMY_API_KEY")
        self.assertEqual(result, "Shodan integration pending API key and full implementation.")

if __name__ == '__main__':
    unittest.main()
