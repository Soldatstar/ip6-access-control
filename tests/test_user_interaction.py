"""
Test cases for the user_interaction module.

This module contains unit tests for the following functionalities:
- Prompting the user for syscall permission using both CLI and GUI.
- Handling non-blocking user input with a timeout.
"""

import sys
from unittest.mock import MagicMock, patch
from user_tool import user_interaction


def test_non_blocking_input_with_input(monkeypatch):
    """
    Test non_blocking_input when user provides input within the timeout.
    This test ensures that the function correctly captures user input.
    """
    # Given: Mock input to simulate user input
    monkeypatch.setattr("sys.stdin", MagicMock())
    monkeypatch.setattr("select.select", lambda r, w, x,
                        timeout: ([sys.stdin], [], []))
    sys.stdin.readline = MagicMock(return_value="test_input\n")

    # When: The function is called
    result = user_interaction.non_blocking_input(
        "Enter something: ", timeout=1.0)

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
    result = user_interaction.non_blocking_input(
        "Enter something: ", timeout=1.0)

    # Then: The result should be None
    assert result is None


def test_ask_permission_timeout(monkeypatch):
    """
    Test ask_permission when no input is provided within the timeout.
    This test ensures that the function waits for input and returns None if no decision is made.
    """
    # Given: Mock CLI input with no response
    monkeypatch.setattr("select.select", lambda r, w, x, timeout: ([], [], []))

    # Mock tkinter to prevent GUI interaction
    with patch("tkinter.Tk") as mock_tk:
        mock_tk.return_value.mainloop = MagicMock()

        # Mock threading to prevent the ask_cli thread from running
        with patch("threading.Thread", lambda *args, **kwargs: MagicMock()):
            # When: ask_permission is called
            result = user_interaction.ask_permission(
                syscall_nr=42,
                program_name="test_program",
                program_hash="test_hash",
                parameter_formated="formatted_param",
                logger=MagicMock()
            )

        # Then: The result should be None (no decision made)
        assert result is None
