"""
Test cases for the main module.

This module contains unit tests for the following functionalities:
- Handling requests from the queue.
- Processing valid and invalid request formats.
- Interacting with the ZeroMQ listener.
"""

import json
from unittest import mock
from unittest.mock import MagicMock, patch
import hashlib
import zmq
from user_tool import user_tool_main


def test_handle_requests_valid_req_decision(monkeypatch):
    """
    Test handling a valid 'req_decision' request.
    This test ensures that the function processes the request and sends the correct response.
    """
    # Given: A valid 'req_decision' request in the queue
    mock_socket = MagicMock()
    mock_identity = b"client1"
    mock_message = {
        "type": "req_decision",
        "body": {
            "program": "/path/to/program",
            "syscall_id": 42,
            "syscall_name": "open",
            "parameter_raw": "raw_param",
            "parameter_formated": "formatted_param"
        }
    }
    user_tool_main.REQUEST_QUEUE.put((mock_socket, mock_identity, mock_message))
    mock_logger = MagicMock()
    monkeypatch.setattr("user_tool.user_tool_main.LOGGER", mock_logger)
    mock_utils = MagicMock()
    mock_utils.ask_permission.return_value = "ALLOW"
    monkeypatch.setattr("user_tool.user_tool_main.user_interaction", mock_utils)
    mock_policy_manager = MagicMock()
    monkeypatch.setattr("user_tool.user_tool_main.policy_manager", mock_policy_manager)

    # When: The handle_requests function is called
    user_tool_main.handle_requests()

    # Then: The correct response should be sent back
    expected_response = {
        "status": "success",
        "data": {"decision": "ALLOW"}
    }
    mock_socket.send_multipart.assert_called_once_with(
        [mock_identity, b'', json.dumps(expected_response).encode()]
    )
    mock_logger.info.assert_any_call(
        "Handling request for %s (hash: %s)", mock.ANY, mock.ANY)


def test_handle_requests_invalid_message_format(monkeypatch):
    """
    Test handling an invalid message format.
    This test ensures that the function logs an error and sends an error response.
    """
    # Given: An invalid message in the queue
    mock_socket = MagicMock()
    mock_identity = b"client1"
    mock_message = {"invalid": "message"}
    user_tool_main.REQUEST_QUEUE.put((mock_socket, mock_identity, mock_message))
    mock_logger = MagicMock()
    monkeypatch.setattr("user_tool.user_tool_main.LOGGER", mock_logger)

    # When: The handle_requests function is called
    user_tool_main.handle_requests()

    # Then: An error response should be sent back
    expected_response = {
        "status": "error",
        "data": {"message": "Invalid message format"}
    }
    mock_socket.send_multipart.assert_called_once_with(
        [mock_identity, b'', json.dumps(expected_response).encode()]
    )
    mock_logger.error.assert_called_once_with("Invalid message format")


def test_handle_requests_read_db_no_policy(monkeypatch, tmp_path):
    """
    Test handling a 'read_db' request when no policy exists.
    This test ensures that the function sends an appropriate error response.
    """
    # Given: A 'read_db' request with no corresponding policy file
    mock_socket = MagicMock()
    mock_identity = b"client1"
    mock_message = {
        "type": "read_db",
        "body": {"program": "/path/to/program"}
    }
    user_tool_main.REQUEST_QUEUE.put((mock_socket, mock_identity, mock_message))
    mock_logger = MagicMock()
    monkeypatch.setattr("user_tool.user_tool_main.LOGGER", mock_logger)
    monkeypatch.setattr("user_tool.user_tool_main.POLICIES_DIR", str(tmp_path))

    # When: The handle_requests function is called
    user_tool_main.handle_requests()

    # Then: An error response should be sent back
    expected_response = {
        "status": "error",
        "data": {"message": "No policy found"}
    }
    mock_socket.send_multipart.assert_called_once_with(
        [mock_identity, b'', json.dumps(expected_response).encode()]
    )
    mock_logger.info.assert_any_call("No policy found for %s", mock.ANY)
    mock_logger.info.assert_any_call("Received read_db request")


def test_handle_requests_read_db_valid_policy(monkeypatch, tmp_path):
    """
    Test handling a 'read_db' request with a valid policy.
    This test ensures that the function sends the correct policy data in the response.
    """
    # Given: A 'read_db' request with a valid policy file
    mock_socket = MagicMock()
    mock_identity = b"client1"
    mock_message = {
        "type": "read_db",
        "body": {"program": "/path/to/program"}
    }
    program_hash = hashlib.sha256(
        "/path/to/program".encode()).hexdigest()  # Ensure hash matches
    policy_dir = tmp_path / program_hash
    policy_dir.mkdir()
    policy_file = policy_dir / "policy.json"
    # Valid policy content
    policy_file.write_text(json.dumps({"rules": {"allowed_syscalls": []}}))
    user_tool_main.REQUEST_QUEUE.put((mock_socket, mock_identity, mock_message))
    mock_logger = MagicMock()
    monkeypatch.setattr("user_tool.user_tool_main.LOGGER", mock_logger)
    monkeypatch.setattr("user_tool.user_tool_main.POLICIES_DIR", str(tmp_path))

    # When: The handle_requests function is called
    user_tool_main.handle_requests()

    # Then: The correct policy data should be sent back
    expected_response = {
        "status": "success",
        "data": {"allowed_syscalls": []}
    }
    mock_socket.send_multipart.assert_called_once_with(
        [mock_identity, b'', json.dumps(expected_response).encode()]
    )
    mock_logger.debug.assert_called_once_with(
        "Policy for %s: %s", program_hash, mock.ANY)


def test_zmq_listener(monkeypatch):
    """
    Test the zmq_listener function.
    This test ensures that the listener correctly processes valid and invalid messages.
    """
    # Given: A mock ZeroMQ context and socket
    mock_context = MagicMock()
    mock_socket = MagicMock()
    mock_context.socket.return_value = mock_socket
    monkeypatch.setattr("zmq.Context", lambda: mock_context)

    # And: Mock LOGGER and REQUEST_QUEUE
    mock_logger = MagicMock()
    monkeypatch.setattr("user_tool.user_tool_main.LOGGER", mock_logger)
    mock_request_queue = MagicMock()
    monkeypatch.setattr("user_tool.user_tool_main.REQUEST_QUEUE", mock_request_queue)

    # And: Valid and invalid messages
    valid_message = json.dumps({"type": "req_decision", "body": {}}).encode()
    invalid_message = b"Invalid JSON"
    mock_socket.recv_multipart.side_effect = [
        [b"client1", b"", valid_message],
        [b"client2", b"", invalid_message],
        zmq.ZMQError("Mocked error")
    ]

    # When: The zmq_listener function is called
    with patch("threading.Thread", lambda *args, **kwargs: None):  # Prevent threading issues
        try:
            user_tool_main.zmq_listener()
        except zmq.ZMQError:
            pass  # Expected due to mocked error

    # Then: Valid messages should be added to the queue
    mock_request_queue.put.assert_called_once_with(
        (mock_socket, b"client1", json.loads(valid_message)))

    # And: Invalid messages should log an error and send an error response
    mock_logger.error.assert_any_call("Failed to decode JSON message")
    mock_socket.send_multipart.assert_called_once_with(
        [b"client2", b"", json.dumps({"error": "Invalid JSON"}).encode()]
    )

    # And: The listener should log the ZeroMQ error with the correct exception object
    mock_logger.error.assert_any_call("ZeroMQ error: %s", mock.ANY)


def test_main_list_known_apps(monkeypatch):
    """
    Test the 'List Known Apps' option in the main menu.
    This test ensures that the function calls the appropriate policy manager method.
    """
    # Given: Mock user input and policy manager
    mock_logger = MagicMock()
    monkeypatch.setattr("user_tool.user_tool_main.LOGGER", mock_logger)
    mock_policy_manager = MagicMock()
    monkeypatch.setattr("user_tool.user_tool_main.policy_manager", mock_policy_manager)
    monkeypatch.setattr("user_tool.user_tool_main.user_interaction.non_blocking_input", lambda _: "1")
    monkeypatch.setattr("os.system", lambda _: None)  # Mock os.system to prevent clearing the console

    # Mock threading.Thread to prevent actual thread creation
    mock_thread = MagicMock()
    monkeypatch.setattr("threading.Thread", lambda *args, **kwargs: mock_thread)

    # When: The main function is called and the user selects option 1
    with patch("builtins.input", lambda _: None):  # Mock input to prevent blocking
        user_tool_main.main(test_mode=True)

    # Then: The policy manager's list_known_apps method should be called
    mock_policy_manager.list_known_apps.assert_called_once()
    mock_logger.info.assert_any_call("Listing known apps...")
    mock_thread.start.assert_called_once()  # Ensure the thread's start method was called


def test_main_delete_all_policies(monkeypatch):
    """
    Test the 'Delete All Policies' option in the main menu.
    This test ensures that the function calls the appropriate policy manager method.
    """
    # Given: Mock user input and policy manager
    mock_logger = MagicMock()
    monkeypatch.setattr("user_tool.user_tool_main.LOGGER", mock_logger)
    mock_policy_manager = MagicMock()
    monkeypatch.setattr("user_tool.user_tool_main.policy_manager", mock_policy_manager)
    monkeypatch.setattr("user_tool.user_tool_main.user_interaction.non_blocking_input", lambda _: "2")
    monkeypatch.setattr("os.system", lambda _: None)  # Mock os.system to prevent clearing the console

    # Mock threading.Thread to prevent actual thread creation
    mock_thread = MagicMock()
    monkeypatch.setattr("threading.Thread", lambda *args, **kwargs: mock_thread)

    # When: The main function is called and the user selects option 2
    with patch("builtins.input", lambda _: None):  # Mock input to prevent blocking
        user_tool_main.main(test_mode=True)

    # Then: The policy manager's delete_all_policies method should be called
    mock_policy_manager.delete_all_policies.assert_called_once()
    mock_logger.info.assert_any_call("Deleting all policies...")
    mock_thread.start.assert_called_once()  # Ensure the thread's start method was called


def test_main_exit(monkeypatch):
    """
    Test the 'Exit' option in the main menu.
    This test ensures that the function exits the loop when the user selects '3'.
    """
    # Given: Mock user input
    mock_logger = MagicMock()
    monkeypatch.setattr("user_tool.user_tool_main.LOGGER", mock_logger)
    monkeypatch.setattr("user_tool.user_tool_main.user_interaction.non_blocking_input", lambda _: "3")
    monkeypatch.setattr("os.system", lambda _: None)  # Mock os.system to prevent clearing the console

    # Mock threading.Thread to prevent actual thread creation
    mock_thread = MagicMock()
    monkeypatch.setattr("threading.Thread", lambda *args, **kwargs: mock_thread)

    # When: The main function is called and the user selects option 3
    with patch("builtins.input", lambda _: None):  # Mock input to prevent blocking
        user_tool_main.main()

    # Then: The logger should log the exit message
    mock_logger.info.assert_any_call("Exiting User Tool.")
    mock_thread.start.assert_called_once()  # Ensure the thread's start method was called
