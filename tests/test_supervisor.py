"""
Test cases for the supervisor module.

This module contains unit tests for the following functionalities:
- Asking for permission via ZeroMQ.
"""

import json
from unittest.mock import MagicMock, patch
from supervisor.supervisor import ask_for_permission_zmq


def test_ask_for_permission_zmq():
    """
    Test asking for permission via ZeroMQ.
    This test ensures that the function sends the correct message and processes
    the response correctly.
    """
    # Given: Mock socket and input parameters
    mock_socket = MagicMock()
    syscall_name = "open"
    syscall_nr = 2
    arguments_raw = ["filename", "flags"]
    arguments_formated = ["/path/to/file", "O_RDONLY"]

    # And: Mock response from the socket
    mock_response = {
        "status": "success",
        "data": {"decision": "ALLOW"}
    }
    mock_socket.recv_multipart.return_value = [b'', json.dumps(mock_response).encode()]

    # When: The function is called
    with patch("supervisor.supervisor.LOGGER") as mock_logger:
        decision = ask_for_permission_zmq(
            syscall_name=syscall_name,
            syscall_nr=syscall_nr,
            arguments_raw=arguments_raw,
            arguments_formated=arguments_formated,
            socket=mock_socket
        )

    # Then: The correct message should be sent
    expected_message = {
        "type": "req_decision",
        "body": {
            "program": None,  # PROGRAM_ABSOLUTE_PATH is not set in this test
            "syscall_id": syscall_nr,
            "syscall_name": syscall_name,
            "parameter_raw": arguments_raw,
            "parameter_formated": arguments_formated
        }
    }
    mock_socket.send_multipart.assert_called_once_with([b'', json.dumps(expected_message).encode()])

    # And: The decision should be correctly returned
    assert decision == "ALLOW"

    # And: The logger should log the request
    mock_logger.info.assert_called_with("Asking for permission for syscall: %s", syscall_name)
