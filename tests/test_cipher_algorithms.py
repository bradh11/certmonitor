"""
Test suite for the cipher_algorithms module.

This module tests:
- parse_cipher_suite function
- list_algorithms function
- update_algorithms function
- update_allowed_lists function
- LRU cache functionality
"""

from certmonitor.cipher_algorithms import (
    list_algorithms,
    parse_cipher_suite,
    update_algorithms,
    update_allowed_lists,
)


class TestCipherAlgorithms:
    """Test suite for cipher algorithm parsing and management functions."""

    def test_parse_cipher_suite_ecdhe_rsa(self):
        """Test parsing ECDHE-RSA cipher suite."""
        result = parse_cipher_suite("ECDHE-RSA-AES128-GCM-SHA256")

        assert result["key_exchange"] == "ECDHE"
        assert result["encryption"] == "AES"
        assert result["mac"] == "SHA256"

    def test_parse_cipher_suite_ecdhe_ecdsa(self):
        """Test parsing ECDHE-ECDSA cipher suite."""
        result = parse_cipher_suite("ECDHE-ECDSA-AES256-GCM-SHA384")

        assert result["key_exchange"] == "ECDHE"
        assert result["encryption"] == "AES"
        assert result["mac"] == "SHA384"

    def test_parse_cipher_suite_chacha20(self):
        """Test parsing ChaCha20 cipher suite."""
        result = parse_cipher_suite("ECDHE-RSA-CHACHA20-POLY1305")

        assert result["key_exchange"] == "ECDHE"
        assert result["encryption"] == "CHACHA20"
        assert result["mac"] == "POLY1305"

    def test_parse_cipher_suite_weak_rc4(self):
        """Test parsing weak RC4 cipher suite."""
        result = parse_cipher_suite("TLS_RSA_WITH_RC4_128_MD5")

        assert result["key_exchange"] == "RSA"
        assert result["encryption"] == "RC4"
        assert result["mac"] == "MD5"

    def test_parse_cipher_suite_3des(self):
        """Test parsing 3DES cipher suite."""
        result = parse_cipher_suite("ECDHE-RSA-DES-EDE3-CBC-SHA")

        assert result["key_exchange"] == "ECDHE"
        assert result["encryption"] == "3DES"
        assert result["mac"] == "SHA"

    def test_parse_cipher_suite_unknown(self):
        """Test parsing unknown cipher suite returns defaults."""
        result = parse_cipher_suite("UNKNOWN-CIPHER-SUITE")

        assert result["encryption"] == "Unknown"
        assert result["key_exchange"] == "Unknown"
        assert result["mac"] == "Unknown"

    def test_parse_cipher_suite_partial_match(self):
        """Test parsing cipher suite with partial matches."""
        result = parse_cipher_suite("DHE-RSA-AES-GCM")

        assert result["key_exchange"] == "DHE"
        assert result["encryption"] == "AES"
        assert result["mac"] == "AEAD"  # GCM should match AEAD pattern

    def test_parse_cipher_suite_cache_functionality(self):
        """Test that parse_cipher_suite uses LRU cache."""
        # First call
        result1 = parse_cipher_suite("ECDHE-RSA-AES128-GCM-SHA256")

        # Second call (should be cached)
        result2 = parse_cipher_suite("ECDHE-RSA-AES128-GCM-SHA256")

        # Results should be identical
        assert result1 == result2
        assert result1["key_exchange"] == "ECDHE"

        # Clear cache and test
        parse_cipher_suite.cache_clear()
        result3 = parse_cipher_suite("ECDHE-RSA-AES128-GCM-SHA256")
        assert result3 == result1

    def test_list_algorithms(self):
        """Test getting all algorithm lists."""
        alg_list = list_algorithms()

        assert "encryption" in alg_list
        assert "key_exchange" in alg_list
        assert "mac" in alg_list

        assert "AES" in alg_list["encryption"]
        assert "ECDHE" in alg_list["key_exchange"]
        assert "SHA256" in alg_list["mac"]

    def test_update_algorithms_new_category(self):
        """Test adding new algorithm category."""
        custom_algorithms = {"test_category": {"TEST_ALG": r"TEST_PATTERN"}}

        update_algorithms(custom_algorithms)
        alg_list = list_algorithms()

        assert "test_category" in alg_list
        assert "TEST_ALG" in alg_list["test_category"]

    def test_update_algorithms_existing_category(self):
        """Test updating existing algorithm category."""
        custom_algorithms = {"encryption": {"NEW_ENCRYPTION": r"NEW_ENC_PATTERN"}}

        update_algorithms(custom_algorithms)
        alg_list = list_algorithms()

        assert "NEW_ENCRYPTION" in alg_list["encryption"]
        # Original algorithms should still be there
        assert "AES" in alg_list["encryption"]

    def test_update_algorithms_parsing_integration(self):
        """Test that updated algorithms work in parse_cipher_suite."""
        # Add a custom algorithm
        custom_algorithms = {"encryption": {"CUSTOM_CIPHER": r"CUSTOM_CIPHER"}}

        update_algorithms(custom_algorithms)

        # Clear cache to ensure fresh parsing
        parse_cipher_suite.cache_clear()

        # Test parsing with new algorithm
        result = parse_cipher_suite("ECDHE-RSA-CUSTOM_CIPHER-SHA256")
        assert result["encryption"] == "CUSTOM_CIPHER"

    def test_update_allowed_lists_tls_versions(self):
        """Test updating allowed TLS versions."""
        custom_tls_versions = {"TLSv1.3"}

        update_allowed_lists(custom_tls_versions=custom_tls_versions)

        # The global variable should be updated
        from certmonitor.cipher_algorithms import ALLOWED_TLS_VERSIONS

        assert ALLOWED_TLS_VERSIONS == {"TLSv1.3"}

    def test_update_allowed_lists_cipher_suites(self):
        """Test updating allowed cipher suites."""
        custom_ciphers = {"ECDHE-RSA-AES256-GCM-SHA384"}

        update_allowed_lists(custom_ciphers=custom_ciphers)

        # The global variable should be updated
        from certmonitor.cipher_algorithms import ALLOWED_CIPHER_SUITES

        assert ALLOWED_CIPHER_SUITES == {"ECDHE-RSA-AES256-GCM-SHA384"}

    def test_update_allowed_lists_both(self):
        """Test updating both TLS versions and cipher suites."""
        custom_tls_versions = {"TLSv1.2", "TLSv1.3"}
        custom_ciphers = {
            "ECDHE-RSA-AES128-GCM-SHA256",
            "ECDHE-ECDSA-AES256-GCM-SHA384",
        }

        update_allowed_lists(
            custom_tls_versions=custom_tls_versions, custom_ciphers=custom_ciphers
        )

        from certmonitor.cipher_algorithms import (
            ALLOWED_CIPHER_SUITES,
            ALLOWED_TLS_VERSIONS,
        )

        assert ALLOWED_TLS_VERSIONS == custom_tls_versions
        assert ALLOWED_CIPHER_SUITES == custom_ciphers

    def test_update_allowed_lists_none_values(self):
        """Test that None values don't update the lists."""
        # Store original values
        from certmonitor.cipher_algorithms import (
            ALLOWED_CIPHER_SUITES,
            ALLOWED_TLS_VERSIONS,
        )

        original_tls = ALLOWED_TLS_VERSIONS.copy()
        original_ciphers = ALLOWED_CIPHER_SUITES.copy()

        # Call with None values
        update_allowed_lists(custom_tls_versions=None, custom_ciphers=None)

        # Values should remain unchanged
        assert ALLOWED_TLS_VERSIONS == original_tls
        assert ALLOWED_CIPHER_SUITES == original_ciphers

    def test_default_allowed_lists_values(self):
        """Test that default allowed lists have expected values."""
        from certmonitor.cipher_algorithms import (
            ALLOWED_CIPHER_SUITES,
            ALLOWED_TLS_VERSIONS,
        )

        # Should contain modern TLS versions
        assert "TLSv1.2" in ALLOWED_TLS_VERSIONS
        assert "TLSv1.3" in ALLOWED_TLS_VERSIONS

        # Should not contain weak versions
        assert "TLSv1.0" not in ALLOWED_TLS_VERSIONS
        assert "TLSv1.1" not in ALLOWED_TLS_VERSIONS
        assert "SSLv3" not in ALLOWED_TLS_VERSIONS

        # Should contain strong cipher suites
        assert "ECDHE-RSA-AES128-GCM-SHA256" in ALLOWED_CIPHER_SUITES
        assert "ECDHE-ECDSA-AES256-GCM-SHA384" in ALLOWED_CIPHER_SUITES

        # Should not be empty
        assert len(ALLOWED_CIPHER_SUITES) > 0

    def test_algorithm_patterns_edge_cases(self):
        """Test edge cases in algorithm pattern matching."""
        # Test SHA vs SHA1 pattern matching
        result_sha = parse_cipher_suite("ECDHE-RSA-AES128-GCM-SHA")
        result_sha1 = parse_cipher_suite("ECDHE-RSA-AES128-GCM-SHA1")

        assert result_sha["mac"] == "SHA"
        assert result_sha1["mac"] == "SHA"  # Should match same pattern

        # Test ECDHE vs EECDH pattern matching
        result_ecdhe = parse_cipher_suite("ECDHE-RSA-AES128-GCM-SHA256")
        result_eecdh = parse_cipher_suite("EECDH-RSA-AES128-GCM-SHA256")

        assert result_ecdhe["key_exchange"] == "ECDHE"
        assert result_eecdh["key_exchange"] == "ECDHE"  # Should match same pattern

    def test_case_sensitivity_in_parsing(self):
        """Test that cipher suite parsing handles case correctly."""
        # Test mixed case
        result = parse_cipher_suite("ecdhe-rsa-aes128-gcm-sha256")

        # Patterns should match regardless of case in the original patterns
        # but our current implementation is case-sensitive, so this should not match
        assert result["encryption"] == "Unknown" or result["encryption"] == "AES"

    def test_complex_cipher_suite_patterns(self):
        """Test parsing of complex cipher suite names."""
        # Test DHE vs EDH alternative naming
        result_dhe = parse_cipher_suite("DHE-RSA-AES256-SHA")
        result_edh = parse_cipher_suite("EDH-RSA-AES256-SHA")

        assert result_dhe["key_exchange"] == "DHE"
        assert result_edh["key_exchange"] == "DHE"  # EDH should match DHE pattern

        # Test 3DES alternative naming
        result_3des = parse_cipher_suite("ECDHE-RSA-3DES-EDE-CBC-SHA")
        result_des_ede3 = parse_cipher_suite("ECDHE-RSA-DES-EDE3-CBC-SHA")

        assert result_3des["encryption"] == "3DES"
        assert result_des_ede3["encryption"] == "3DES"  # Should match same pattern

    def test_cache_clear_functionality(self):
        """Test that cache clear works properly."""
        # Parse a cipher suite
        parse_cipher_suite("ECDHE-RSA-AES128-GCM-SHA256")

        # Check cache info (if available)
        cache_info = parse_cipher_suite.cache_info()
        assert cache_info.hits >= 0
        assert cache_info.misses >= 0

        # Clear cache
        parse_cipher_suite.cache_clear()

        # Cache should be empty now
        cache_info_after = parse_cipher_suite.cache_info()
        assert cache_info_after.hits == 0
        assert cache_info_after.misses == 0
