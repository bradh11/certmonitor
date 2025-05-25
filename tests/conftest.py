# testsconftest.py

from unittest.mock import MagicMock

import pytest

from certmonitor import CertMonitor


@pytest.fixture
def sample_cert():
    """Standard certificate fixture for testing."""
    return {
        "subject": {
            "countryName": "US",
            "stateOrProvinceName": "California",
            "localityName": "Los Angeles",
            "organizationName": "Internet\u00a0Corporation\u00a0for\u00a0Assigned\u00a0Names\u00a0and\u00a0Numbers",
            "commonName": "www.example.org",
        },
        "issuer": {
            "countryName": "US",
            "organizationName": "DigiCert Inc",
            "commonName": "DigiCert Global G2 TLS RSA SHA256 2020 CA1",
        },
        "version": 3,
        "serialNumber": "075BCEF30689C8ADDF13E51AF4AFE187",
        "notBefore": "Jan 30 00:00:00 2024 GMT",
        "notAfter": "Mar  1 23:59:59 2030 GMT",  # Set to a future date
        "subjectAltName": {
            "DNS": [
                "www.example.org",
                "example.net",
                "example.edu",
                "example.com",
                "example.org",
                "www.example.com",
                "www.example.edu",
                "www.example.net",
            ]
        },
        "OCSP": ["http://ocsp.digicert.com"],
        "caIssuers": [
            "http://cacerts.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crt"
        ],
        "crlDistributionPoints": [
            "http://crl3.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl",
            "http://crl4.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl",
        ],
    }


@pytest.fixture
def expired_cert():
    """Certificate fixture that is expired for testing expiration validation."""
    return {
        "subject": {"commonName": "expired.example.com"},
        "issuer": {"organizationName": "Test CA"},
        "version": 3,
        "serialNumber": "123456789",
        "notBefore": "Jan  1 00:00:00 2020 GMT",
        "notAfter": "Jan  1 23:59:59 2021 GMT",  # Expired
        "subjectAltName": {"DNS": ["expired.example.com"]},
    }


@pytest.fixture
def self_signed_cert():
    """Self-signed certificate fixture for testing root certificate validation."""
    return {
        "subject": {
            "commonName": "self-signed.example.com",
            "organizationName": "Self Signed",
        },
        "issuer": {
            "commonName": "self-signed.example.com",
            "organizationName": "Self Signed",
        },
        "version": 3,
        "serialNumber": "987654321",
        "notBefore": "Jan  1 00:00:00 2024 GMT",
        "notAfter": "Jan  1 23:59:59 2025 GMT",
        "subjectAltName": {"DNS": ["self-signed.example.com"]},
    }


@pytest.fixture
def wildcard_cert():
    """Wildcard certificate fixture for testing hostname validation."""
    return {
        "subject": {"commonName": "*.example.com"},
        "issuer": {"organizationName": "Wildcard CA"},
        "version": 3,
        "serialNumber": "111222333",
        "notBefore": "Jan  1 00:00:00 2024 GMT",
        "notAfter": "Jan  1 23:59:59 2025 GMT",
        "subjectAltName": {"DNS": ["*.example.com", "example.com"]},
    }


@pytest.fixture
def ip_cert():
    """IP address certificate fixture for testing IP validation."""
    return {
        "subject": {"commonName": "192.168.1.1"},
        "issuer": {"organizationName": "IP CA"},
        "version": 3,
        "serialNumber": "444555666",
        "notBefore": "Jan  1 00:00:00 2024 GMT",
        "notAfter": "Jan  1 23:59:59 2025 GMT",
        "subjectAltName": {"IP Address": ["192.168.1.1", "::1"]},
    }


@pytest.fixture
def sample_der():
    """DER-encoded certificate fixture."""
    return b"0\x82\x07n0\x82\x06V\xa0\x03\x02\x01\x02\x02\x10\x07[\xce\xf3\x06\x89\xc8\xad\xdf\x13\xe5\x1a\xf4\xaf\xe1\x870\r\x06\t*\x86H\x86\xf7\r\x01\x01\x0b\x05\x000Y1\x0b0\t\x06\x03U\x04\x06\x13\x02US1\x150\x13\x06\x03U\x04\n\x13\x0cDigiCert Inc1301\x06\x03U\x04\x03\x13*DigiCert Global G2 TLS RSA SHA256 2020 CA10\x1e\x17\r240130000000Z\x17\r250301235959Z0\x81\x961\x0b0\t\x06\x03U\x04\x06\x13\x02US1\x130\x11\x06\x03U\x04\x08\x13\nCalifornia1\x140\x12\x06\x03U\x04\x07\x13\x0bLos Angeles1B0@\x06\x03U\x04\n\x0c9Internet\xc2\xa0Corporation\xc2\xa0for\xc2\xa0Assigned\xc2\xa0Names\xc2\xa0and\xc2\xa0Numbers1\x180\x16\x06\x03U\x04\x03\x13\x0fwww.example.org0\x82\x01\"0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x01\x05\x00\x03\x82\x01\x0f\x000\x82\x01\n\x02\x82\x01\x01\x00\x86\x85\x0f\xbb\x0e\xf9\xca_\xd9\xf5\xe0\n2,3\xd9\xaa\x0e\x07)\xa8/\x08\xadx\xbd\xc2\x06\xbf\xf7-+\xa6\xa7'=S\xa6L\xc3K\xb2'w \xd6\xc1TI\xb8\x08\xda\xf9p\xa9a\xf6\xb2I\x9diW\xda\xfbm$4r.G\xf0\x04?\x9d\xb1[\xe2\xbcf1Y2\xe6\xa9~\xbf\xd4\xb0\xd4d\xf5k\xca{\xffr[^\x9a\xd8?\xd4\x06\xb2\xf3\xc8\xdc\x8ffZF\x84f\xa8\x18\x15y\xa7\x08\xce\x05<\xfb9\x89\xefm\xfaNqR{\xb7\xe4\xa0\xa4\x9c\x96\xc0a=\xa4\npM\xc3\x8e\xcdn\xb32l\xf2\xc7D\t\x04\xdd\xa0U\xfd#\xa5 x\xb2\x85^\xd8;\xad\x17\xff\x85\xc5\xb9t\x8d3\xb9\xb8Wn\xb5\xbcie\xdb\x0b<\x92U\x99\xf4s\xb4d$\xcagL(\x99\xcc\xdcg=y\xc7\x16\x9c+\xe6\xab\xaa\xaa5r7\xf6\x81*H\xe8?N\x19\x9a\xbf\x9eF\xaa2\x93\xff\xa5\xb2Z\xb4\xb1/\x1ei\x84\x92\x1d\xb0\xb9\x8d\xaf\xf21l\x95\x86\xf3\x02\x03\x01\x00\x01\xa3\x82\x03\xf20\x82\x03\xee0\x1f\x06\x03U\x1d#\x04\x180\x16\x80\x14t\x85\x80\xc0f\xc7\xdf7\xde\xcf\xbd)7\xaa\x03\x1d\xbe\xed\xcd\x170\x1d\x06\x03U\x1d\x0e\x04\x16\x04\x14L\xfe\xd0\x12M.!\xcfk\xfa\xf2\xf2\xb8LI\x02\x1d1\x91\x8a0\x81\x81\x06\x03U\x1d\x11\x04z0x\x82\x0fwww.example.org\x82\x0bexample.net\x82\x0bexample.edu\x82\x0bexample.com\x82\x0bexample.org\x82\x0fwww.example.com\x82\x0fwww.example.edu\x82\x0fwww.example.net0>\x06\x03U\x1d \x0470503\x06\x06g\x81\x0c\x01\x02\x020)0'\x06\x08+\x06\x01\x05\x05\x07\x02\x01\x16\x1bhttp://www.digicert.com/CPS0\x0e\x06\x03U\x1d\x0f\x01\x01\xff\x04\x04\x03\x02\x05\xa00\x1d\x06\x03U\x1d%\x04\x160\x14\x06\x08+\x06\x01\x05\x05\x07\x03\x01\x06\x08+\x06\x01\x05\x05\x07\x03\x020\x81\x9f\x06\x03U\x1d\x1f\x04\x81\x970\x81\x940H\xa0F\xa0D\x86Bhttp://crl3.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl0H\xa0F\xa0D\x86Bhttp://crl4.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl0\x81\x87\x06\x08+\x06\x01\x05\x05\x07\x01\x01\x04{0y0$\x06\x08+\x06\x01\x05\x05\x070\x01\x86\x18http://ocsp.digicert.com0Q\x06\x08+\x06\x01\x05\x05\x070\x02\x86Ehttp://cacerts.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crt0\x0c\x06\x03U\x1d\x13\x01\x01\xff\x04\x020\x000\x82\x01}\x06\n+\x06\x01\x04\x01\xd6y\x02\x04\x02\x04\x82\x01m\x04\x82\x01i\x01g\x00t\x00Nu\xa3'\\\x9a\x10\xc38[l\xd4\xdf?R\xeb\x1d\xf0\xe0\x8e\x1b\x8di\xc0\xb1\xfad\xb1b\x9a9\xdf\x00\x00\x01\x8d[\xd2\xfcd\x00\x00\x04\x03\x00E0C\x02\x1f@Q\n\x0cOl\x10U\xc6\x17\x16gn\x9a\xf0\x90\x9e\xf3s\xf5%\x9e\xb0\x9a\xfez\x1a\xc5\\\xc8\xc0\x02 8)1\xb1(\xe4rHM4O\x9e\x8c\x93\xe2a\xbcp\xba\xd6\x8cK\xe1r\x15\x1d\x11\xc5\x94\xbaMS\x00v\x00}Y\x1e\x12\xe1x*{\x1cag|^\xfd\xf8\xd0\x87\\\x14\xa0N\x95\x9e\xb9\x03/\xd9\x0e\x8c.y\xb8\x00\x00\x01\x8d[\xd2\xfc0\x00\x00\x04\x03\x00G0E\x02 ]\xbf\x96w\xa5\x91[~\n\x0c\xde\xd1\xa9\t37g\x10LB\xccAE'SK\xa7|wc@s\x02!\x00\xb2\xe8\t?fL\xc3};!s \x15y2E\xd5/+\x93\x7fc\x80\xcc\x03\x9a\xed\xdf1\xd8~\x97\x00w\x00\xe6\xd21c@w\x8c\xc1\x10A\x06\xd7q\xb9\xce\xc1\xd2@\xf6\x96\x84\x86\xfb\xba\x872\x1d\xfd\x1e7\x8eP\x00\x00\x01\x8d[\xd2\xfc_\x00\x00\x04\x03\x00H0F\x02!\x00\xe0\xaa!\xfdX\xb3u\x055\xb66v\x13eF\x81d\x97^L'Bh\x98\x86`\x1e)\xc5K\x1d\xe0\x02!\x00\xfb$\x81\x85\xb1\xd1\xa8\x97\xb9,\xb3j^\xe2V+\n\x03\xd5s\xe8\x86fK\xaa\x9e=\xba\x86\xa8k\xd10\r\x06\t*\x86H\x86\xf7\r\x01\x01\x0b\x05\x00\x03\x82\x01\x01\x00\x04\xe1n\x02>\r\xe3#F\xf4\xe3\x965\x05\x935\"\x02\x0b\x84]\xe2s\x86\xd4tO\xfc\x1b'\xaf>\xca\xad\xc3\xceF\xd6\xfa\x0f\xe2q\xf9\r\x1a\x9a\x13\xb7\xd5\x08H\xbdPX\xb3^ c\x86)\xca>\xcc\xccx&\xe1Y\x8f]\xca\x8b\xbcI1oa\xbdB\xffab\xe1\"5$&\x9bW\xeb\xe5\x00\r\xff@3lF\xc23w\x08\x98\xb2z\xf6C\xf9mH\xdf\xbf\xfe\xfa(\x1e{\x8a\xcf-a\xffl\x87\x98\xa4,b\x9a\xbb\x10\x8c\xff4Hpf\xb7mr\xc3i\xf99Kh9V\xbd\xa1\xb3m\xf4w\xf3F[\\\x19\xacO\xb3tk\x8c\xc5\xf1\x89\xcc\x93\xfe\x0c\x01o\x88\x17\xdcBq`\xe3\xeds0B\x9c\xa9/;\xa2x\x8e\xc8o\xba\xd1\x13\x0c\xd0\xc7^\x8c\x10\xfb\x01.7\x9b\xdb\xac\xf7\xa1\xac\xba\x7f\xf8\x92\xe7\xcbAD\xc8\x15\xf9\xf3\xc4\xbb\xadQ_\xbe\xde\xc7\xac\x86\x07\x9f@\xec\xb9\x0b\xf6\xb2\x8b\xcc\xb5U3f\xba3\xc2\xc4\xf0\xa2\xe9"


@pytest.fixture
def sample_pem():
    """PEM-encoded certificate fixture."""
    return """-----BEGIN CERTIFICATE-----
MIIHbjCCBlagAwIBAgIQB1vO8waJyK3fE+Ua9K/hhzANBgkqhkiG9w0BAQsFADBZ
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMTMwMQYDVQQDEypE
aWdpQ2VydCBHbG9iYWwgRzIgVExTIFJTQSBTSEEyNTYgMjAyMCBDQTEwHhcNMjQw
MTMwMDAwMDAwWhcNMjUwMzAxMjM1OTU5WjCBljELMAkGA1UEBhMCVVMxEzARBgNV
BAgTCkNhbGlmb3JuaWExFDASBgNVBAcTC0xvcyBBbmdlbGVzMUIwQAYDVQQKDDlJ
bnRlcm5ldMKgQ29ycG9yYXRpb27CoGZvcsKgQXNzaWduZWTCoE5hbWVzwqBhbmTC
oE51bWJlcnMxGDAWBgNVBAMTD3d3dy5leGFtcGxlLm9yZzCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBAIaFD7sO+cpf2fXgCjIsM9mqDgcpqC8IrXi9wga/
9y0rpqcnPVOmTMNLsid3INbBVEm4CNr5cKlh9rJJmWlX2vttJDRyLkfw9D+dsVvi
vGYxWTLmqX6/1LDUZPVrynv/cltemmg/1Aay88jchmZaRoRmqBgVeacIzgU8+zmJ
721fTnFSe7fkoKScLIBhPaQKcE3DjuxtszJsApHA3aBV/SOlIHiyhV7YO60X/4XF
uXSNM7m4V261vGNl2ws8klWZ9HO0ZCTKZKYFKKkM3GnHFpwr5quqqjVyN/aBKkjo
P04ZmrI+RqoyiP+lkrTrMS8eaYSSHbC5j3MbOW1hkBAgECAwEAAaOCA/IwggPuM
B8GA1UdIwQYMBaAFHSFgMBmx980382vnSo3qgMdvu3hEWP7QEk0ui4fNBvP8vwY
O44Y+k7qGHI2wG1bJlEA8DBxHPzr9SQwTQYEA...
-----END CERTIFICATE-----"""


@pytest.fixture
def cert_monitor():
    """Standard CertMonitor fixture for testing."""
    monitor = CertMonitor("www.example.com")
    monitor.protocol = "ssl"
    monitor.handler = MagicMock()
    return monitor


@pytest.fixture
def ssh_cert_monitor():
    """CertMonitor fixture configured for SSH testing."""
    monitor = CertMonitor("ssh.example.com", 22)
    monitor.protocol = "ssh"
    monitor.handler = MagicMock()
    return monitor


@pytest.fixture
def ssl_cert_monitor():
    """CertMonitor fixture configured for SSL testing."""
    monitor = CertMonitor("ssl.example.com", 443)
    monitor.protocol = "ssl"
    monitor.handler = MagicMock()
    return monitor


@pytest.fixture
def mock_ssl_handler():
    """Mock SSL handler for testing."""
    handler = MagicMock()
    handler.protocol = "ssl"
    handler.connect.return_value = None  # Success
    handler.fetch_raw_cert.return_value = {
        "cert_info": {"subject": {"commonName": "test.example.com"}},
        "der": b"mock_der",
        "pem": "mock_pem",
    }
    handler.fetch_raw_cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    handler.check_connection.return_value = True
    return handler


@pytest.fixture
def mock_ssh_handler():
    """Mock SSH handler for testing."""
    handler = MagicMock()
    handler.protocol = "ssh"
    handler.connect.return_value = None  # Success
    handler.fetch_raw_cert.return_value = {
        "cert_info": {"subject": {"commonName": "SSH-2.0-OpenSSH_8.0"}},
        "der": None,
        "pem": None,
    }
    handler.check_connection.return_value = True
    return handler


@pytest.fixture
def sample_cipher_info():
    """Standard cipher information fixture."""
    return {
        "cipher_suite": "TLS_AES_256_GCM_SHA384",
        "protocol_version": "TLSv1.3",
        "key_size": 256,
        "algorithm": "ECDHE-RSA-AES256-GCM-SHA384",
        "strength": "HIGH",
    }


@pytest.fixture
def weak_cipher_info():
    """Weak cipher information fixture for testing."""
    return {
        "cipher_suite": "RC4-MD5",
        "protocol_version": "SSLv3",
        "key_size": 128,
        "algorithm": "RC4-MD5",
        "strength": "LOW",
    }


@pytest.fixture
def public_key_info_rsa():
    """RSA public key information fixture."""
    return {
        "algorithm": "rsaEncryption",
        "size": 2048,
        "curve": None,
    }


@pytest.fixture
def public_key_info_ec():
    """EC public key information fixture."""
    return {
        "algorithm": "id-ecPublicKey",
        "size": 256,
        "curve": "prime256v1",
    }


@pytest.fixture
def error_response():
    """Standard error response fixture."""
    return {
        "error": "ConnectionError",
        "message": "Connection failed",
        "host": "example.com",
        "port": 443,
    }


@pytest.fixture
def mock_cert_data():
    """Complete certificate data fixture for testing."""
    return {
        "cert_info": {
            "subject": {"commonName": "test.example.com"},
            "issuer": {"organizationName": "Test CA"},
            "version": 3,
            "serialNumber": "123456789",
            "notBefore": "Jan  1 00:00:00 2024 GMT",
            "notAfter": "Jan  1 23:59:59 2025 GMT",
            "subjectAltName": {"DNS": ["test.example.com", "alt.example.com"]},
        },
        "der": b"mock_der_data",
        "pem": "-----BEGIN CERTIFICATE-----\nMOCK_PEM_DATA\n-----END CERTIFICATE-----",
        "public_key_info": {"algorithm": "rsaEncryption", "size": 2048, "curve": None},
        "public_key_der": b"mock_public_key_der",
        "public_key_pem": "-----BEGIN PUBLIC KEY-----\nMOCK_PUBLIC_KEY_PEM\n-----END PUBLIC KEY-----",
    }
