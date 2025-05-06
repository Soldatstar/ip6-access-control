"""
Test cases for the utils module.

This module contains unit tests for the following functionalities:
- Prompting the user for syscall permission using both CLI and GUI.
- Handling non-blocking user input with a timeout.
"""

import sys
from unittest.mock import MagicMock
from user_tool import user_interaction


def test_non_blocking_input_with_input(monkeypatch):
    """
    Test non_blocking_input when user provides input within the timeout.
    This test ensures that the function correctly captures user input.
    """
    # Given: Mock input to simulate user input
    monkeypatch.setattr("sys.stdin", MagicMock())
    monkeypatch.setattr("select.select", lambda r, w, x, timeout: ([sys.stdin], [], []))
    sys.stdin.readline = MagicMock(return_value="test_input\n")

    # When: The function is called
    result = user_interaction.non_blocking_input("Enter something: ", timeout=1.0)

    # Then: The result should match the user input
    assert result == "test_input"


def test_non_blocking_input_no_input(monkeypatch):
    """
    Test non_blocking_input when no input is provided within the timeout.
    This test ensures that the function returns None after the timeout.
    """
    # Given: Mock select to simulate no input
    monkeypatch.setattr("select.select", lambda r, w, x, timeout: ([], [], []))

    # When: The function is called
    result = user_interaction.non_blocking_input("Enter something: ", timeout=1.0)

    # Then: The result should be None
    assert result is None
