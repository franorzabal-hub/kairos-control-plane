"""
Tests for GKE service.
"""

import pytest
from src.services.gke_service import sanitize_for_shell


class TestSanitizeForShell:
    """Tests for shell input sanitization."""

    def test_simple_string(self):
        """Test that simple strings are quoted."""
        result = sanitize_for_shell("hello")
        assert result == "'hello'"

    def test_string_with_spaces(self):
        """Test string with spaces."""
        result = sanitize_for_shell("hello world")
        assert result == "'hello world'"

    def test_dangerous_characters(self):
        """Test that dangerous shell characters are escaped."""
        dangerous = "; rm -rf /"
        result = sanitize_for_shell(dangerous)
        # The result should be safely quoted
        assert ";" not in result or result.startswith("'")
        assert result != dangerous

    def test_command_substitution(self):
        """Test that command substitution is escaped."""
        payload = "$(whoami)"
        result = sanitize_for_shell(payload)
        # Should be quoted to prevent execution
        assert result == "'$(whoami)'"

    def test_backtick_substitution(self):
        """Test that backtick substitution is escaped."""
        payload = "`whoami`"
        result = sanitize_for_shell(payload)
        assert result == "'`whoami`'"

    def test_single_quotes(self):
        """Test that single quotes are handled."""
        payload = "O'Brien"
        result = sanitize_for_shell(payload)
        # shlex.quote handles this specially
        assert "'" in result

    def test_empty_string(self):
        """Test empty string handling."""
        result = sanitize_for_shell("")
        assert result == "''"

    def test_unicode(self):
        """Test unicode characters."""
        result = sanitize_for_shell("Escuela Niños")
        assert "Niños" in result
