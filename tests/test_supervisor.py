"""
Test cases for the supervisor module.

This module contains unit tests for the following functionalities:
- Asking for permission via ZeroMQ.
"""

import json
import os
from unittest.mock import MagicMock, patch
from supervisor.supervisor import ask_for_permission_zmq, is_already_decided, prepare_arguments, setup_zmq, init_shared_list,ALLOW_LIST, DENY_LIST


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
    mock_socket.recv_multipart.return_value = [
        b'', json.dumps(mock_response).encode()]

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
    mock_socket.send_multipart.assert_called_once_with(
        [b'', json.dumps(expected_message).encode()])

    # And: The decision should be correctly returned
    assert decision == "ALLOW"

    # And: The logger should log the request
    mock_logger.info.assert_called_with(
        "Asking for permission for syscall: %s", syscall_name)


def test_is_already_decided_true():
    """
    Test when a decision is already made for the given syscall and arguments.
    """
    # Given: Mocked ALLOW_LIST and DENY_LIST with a matching decision
    with patch("supervisor.supervisor.ALLOW_LIST", [[2, "arg1", "arg2"]]), \
            patch("supervisor.supervisor.DENY_LIST", []):
        syscall_nr = 2
        arguments = ["arg1", "arg2"]

        # When: The is_already_decided function is called
        result = is_already_decided(syscall_nr, arguments)

        # Then: It should return True
        assert result is True


def test_is_already_decided_false():
    """
    Test when no decision is made for the given syscall and arguments.
    """
    # Given: Mocked ALLOW_LIST and DENY_LIST without a matching decision
    with patch("supervisor.supervisor.ALLOW_LIST", [[2, "arg1", "arg2"]]), \
            patch("supervisor.supervisor.DENY_LIST", [[3, "arg3"]]):
        syscall_nr = 2
        arguments = ["arg3"]

        # When: The is_already_decided function is called
        result = is_already_decided(syscall_nr, arguments)

        # Then: It should return False
        assert result is False


def test_prepare_arguments():
    """
    Test preparing arguments from syscall arguments.
    """
    # Given: Mocked syscall arguments
    mock_syscall_args = [
        type("MockArg", (object,), {
             "name": "filename", "format": lambda: "/path/to/file"}),
        type("MockArg", (object,), {"name": "flags", "value": "O_RDONLY"}),
        type("MockArg", (object,), {"name": "mode", "value": "0777"}),
        type("MockArg", (object,), {"name": "unknown", "format": lambda: "*"})
    ]

    # When: The prepare_arguments function is called
    result = prepare_arguments(mock_syscall_args)

    # Then: The arguments should be correctly prepared
    assert result == ["/path/to/file", "O_RDONLY", "0777", "*"]


def test_init_shared_list_success(mocker):
    """
    Test initializing the shared list when the server responds successfully.
    """
    # Given: Mock socket and server response
    mock_socket = MagicMock()
    mock_response = {
        "status": "success",
        "data": {
            "allowed_syscalls": [[2, ["arg1", "arg2"]]],
            "denied_syscalls": [[3, ["arg3"]]]
        }
    }
    mock_socket.recv_multipart.side_effect = [
        [b'', json.dumps(mock_response).encode()]
    ]

    # Mock ALLOW_LIST and DENY_LIST
    mock_allow_list = mocker.patch("supervisor.supervisor.ALLOW_LIST", [])
    mock_deny_list = mocker.patch("supervisor.supervisor.DENY_LIST", [])

    # When: The init_shared_list function is called
    init_shared_list(socket=mock_socket)

    # Then: ALLOW_LIST and DENY_LIST should be populated correctly
    assert list(mock_allow_list) == [[2, "arg1", "arg2"]]
    assert list(mock_deny_list) == [[3, "arg3"]]

    # And: The correct message should be sent
    expected_message = {
        "type": "read_db",
        "body": {
            "program": None  # PROGRAM_ABSOLUTE_PATH is not set in this test
        }
    }
    mock_socket.send_multipart.assert_called_once_with(
        [b'', json.dumps(expected_message).encode()]
    )


def test_init_shared_list_error(mocker):
    """
    Test initializing the shared list when the server responds with an error.
    """
    # Given: Mock socket and server response
    mock_socket = MagicMock()
    mock_response = {
        "status": "error",
        "data": "Database not found"
    }
    mock_socket.recv_multipart.side_effect = [
        [b'', json.dumps(mock_response).encode()]
    ]
    mocker.patch("supervisor.supervisor.ALLOW_LIST", [])
    mocker.patch("supervisor.supervisor.DENY_LIST", [])

    # When: The init_shared_list function is called
    init_shared_list(socket=mock_socket)

    # Then: ALLOW_LIST and DENY_LIST should remain empty
    from supervisor.supervisor import ALLOW_LIST, DENY_LIST
    assert ALLOW_LIST == []
    assert DENY_LIST == []

    # And: The correct message should be sent
    expected_message = {
        "type": "read_db",
        "body": {
            "program": None  # PROGRAM_ABSOLUTE_PATH is not set in this test
        }
    }
    mock_socket.send_multipart.assert_called_once_with(
        [b'', json.dumps(expected_message).encode()]
    )



def test_setup_zmq(mocker):
    """
    Test setting up a ZeroMQ DEALER socket.
    """
    # Given: Mock ZeroMQ context and socket
    mock_context = mocker.patch("zmq.Context")
    mock_socket = mock_context.return_value.socket.return_value

    # When: The setup_zmq function is called
    result = setup_zmq()
    # Then: The socket should be configured and returned    mock_context.return_value.socket.assert_called_once_with(mocker.ANY)
    mock_socket.connect.assert_called_once_with("tcp://localhost:5556")
    assert result == mock_socket
