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
from pathlib import Path


def test_handle_requests_valid_req_decision(monkeypatch):
    # Given
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
    monkeypatch.setattr("user_tool.user_tool_main.group_selector.get_group_for_syscall", lambda x: "TestGroup")
    monkeypatch.setattr("user_tool.user_tool_main.group_selector.get_syscalls_for_group", lambda group: [42])

    # When
    user_tool_main.handle_requests()

    # Then
    expected_response = {
        "status": "success",
        "data": {"decision": "ALLOW", "allowed_ids": [42]}
    }
    mock_socket.send_multipart.assert_called_once_with(
        [mock_identity, b'', json.dumps(expected_response).encode()]
    )
    mock_logger.info.assert_any_call(
        "Handling request for %s (hash: %s)", mock.ANY, mock.ANY)


def test_handle_requests_invalid_message_format(monkeypatch):
    # Given
    mock_socket = MagicMock()
    mock_identity = b"client1"
    mock_message = {"invalid": "message"}
    user_tool_main.REQUEST_QUEUE.put((mock_socket, mock_identity, mock_message))
    mock_logger = MagicMock()
    monkeypatch.setattr("user_tool.user_tool_main.LOGGER", mock_logger)

    # When
    user_tool_main.handle_requests()

    # Then
    expected_response = {
        "status": "error",
        "data": {"message": "Invalid message format"}
    }
    mock_socket.send_multipart.assert_called_once_with(
        [mock_identity, b'', json.dumps(expected_response).encode()]
    )
    mock_logger.error.assert_called_once_with("Invalid message format")


def test_handle_requests_read_db_no_policy(monkeypatch, tmp_path):
    # Given
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
    monkeypatch.setattr("user_tool.user_tool_main.group_selector.get_groups_structure", lambda x: {"A": [1], "B": [2]})
    monkeypatch.setattr("user_tool.user_tool_main.group_selector.get_syscalls_for_group", lambda group: [1] if group == "A" else [2])
    default_policy_path = Path(__file__).resolve().parent.parent / "user_tool" / "default.json"
    with open(default_policy_path, "r", encoding="UTF-8") as default_file:
        default_policy = json.load(default_file)

    # When
    user_tool_main.handle_requests()

    # Then
    expected_data = default_policy["rules"].copy()
    expected_data["blacklisted_ids"] = [1, 2]
    expected_response = {
        "status": "success",
        "data": expected_data
    }
    mock_socket.send_multipart.assert_called_once_with(
        [mock_identity, b'', json.dumps(expected_response).encode()]
    )
    mock_logger.info.assert_any_call("No policy found for %s", mock.ANY)
    mock_logger.info.assert_any_call("Received read_db request")


def test_handle_requests_read_db_valid_policy(monkeypatch, tmp_path):
    # Given
    mock_socket = MagicMock()
    mock_identity = b"client1"
    mock_message = {
        "type": "read_db",
        "body": {"program": "/path/to/program"}
    }
    program_hash = hashlib.sha256(
        "/path/to/program".encode()).hexdigest()
    policy_dir = tmp_path / program_hash
    policy_dir.mkdir()
    policy_file = policy_dir / "policy.json"
    policy_file.write_text(json.dumps({"rules": {"allowed_syscalls": [[42, ["foo"]]], "allowed_groups": ["A"]}}))
    user_tool_main.REQUEST_QUEUE.put((mock_socket, mock_identity, mock_message))
    mock_logger = MagicMock()
    monkeypatch.setattr("user_tool.user_tool_main.LOGGER", mock_logger)
    monkeypatch.setattr("user_tool.user_tool_main.POLICIES_DIR", str(tmp_path))
    monkeypatch.setattr("user_tool.user_tool_main.group_selector.get_groups_structure", lambda x: {"A": [1], "B": [2]})
    monkeypatch.setattr("user_tool.user_tool_main.group_selector.get_syscalls_for_group", lambda group: [1] if group == "A" else [2])
    default_policy_path = Path(__file__).resolve().parent.parent / "user_tool" / "default.json"
    with open(default_policy_path, "r", encoding="UTF-8") as default_file:
        default_policy = json.load(default_file)

    # When
    user_tool_main.handle_requests()

    # Then
    expected_rules = {
        "allowed_syscalls": default_policy["rules"]["allowed_syscalls"] + [[42, ["foo"]]],
        "denied_syscalls": [],
        "allowed_groups": ["A"],
        "blacklisted_ids": [2]
    }
    from collections import OrderedDict
    expected_rules_ordered = OrderedDict([
        ("allowed_syscalls", expected_rules["allowed_syscalls"]),
        ("denied_syscalls", expected_rules["denied_syscalls"]),
        ("allowed_groups", expected_rules["allowed_groups"]),
        ("blacklisted_ids", expected_rules["blacklisted_ids"]),
    ])
    expected_response = {
        "status": "success",
        "data": expected_rules_ordered
    }
    sent_args = mock_socket.send_multipart.call_args[0][0]
    actual_json = sent_args[2]
    assert json.loads(actual_json.decode()) == expected_response
    mock_logger.debug.assert_called_once_with(
        "Policy for %s: %s", program_hash, mock.ANY)


def test_zmq_listener(monkeypatch):
    # Given
    mock_context = MagicMock()
    mock_socket = MagicMock()
    mock_context.socket.return_value = mock_socket
    monkeypatch.setattr("zmq.Context", lambda: mock_context)
    mock_logger = MagicMock()
    monkeypatch.setattr("user_tool.user_tool_main.LOGGER", mock_logger)
    mock_request_queue = MagicMock()
    monkeypatch.setattr("user_tool.user_tool_main.REQUEST_QUEUE", mock_request_queue)
    valid_message = json.dumps({"type": "req_decision", "body": {}}).encode()
    invalid_message = b"Invalid JSON"
    mock_socket.recv_multipart.side_effect = [
        [b"client1", b"", valid_message],
        [b"client2", b"", invalid_message],
        zmq.ZMQError("Mocked error")
    ]

    # When
    with patch("threading.Thread", lambda *args, **kwargs: None):
        try:
            user_tool_main.zmq_listener()
        except zmq.ZMQError:
            pass

    # Then
    mock_request_queue.put.assert_called_once_with(
        (mock_socket, b"client1", json.loads(valid_message)))
    mock_logger.error.assert_any_call("Failed to decode JSON message")
    mock_socket.send_multipart.assert_called_once_with(
        [b"client2", b"", json.dumps({"error": "Invalid JSON"}).encode()]
    )
    mock_logger.error.assert_any_call("ZeroMQ error: %s", mock.ANY)


def test_main_list_known_apps(monkeypatch):
    # Given
    mock_logger = MagicMock()
    monkeypatch.setattr("user_tool.user_tool_main.LOGGER", mock_logger)
    mock_policy_manager = MagicMock()
    monkeypatch.setattr("user_tool.user_tool_main.policy_manager", mock_policy_manager)
    monkeypatch.setattr("user_tool.user_tool_main.user_interaction.non_blocking_input", lambda _: "1")
    monkeypatch.setattr("os.system", lambda _: None)
    mock_thread = MagicMock()
    monkeypatch.setattr("threading.Thread", lambda *args, **kwargs: mock_thread)

    # When
    with patch("builtins.input", lambda _: None):
        user_tool_main.main(test_mode=True)

    # Then
    mock_policy_manager.list_known_apps.assert_called_once()
    mock_logger.info.assert_any_call("Listing known apps...")
    mock_thread.start.assert_called_once()


def test_main_delete_all_policies(monkeypatch):
    # Given
    mock_logger = MagicMock()
    monkeypatch.setattr("user_tool.user_tool_main.LOGGER", mock_logger)
    mock_policy_manager = MagicMock()
    monkeypatch.setattr("user_tool.user_tool_main.policy_manager", mock_policy_manager)
    monkeypatch.setattr("user_tool.user_tool_main.user_interaction.non_blocking_input", lambda _: "2")
    monkeypatch.setattr("os.system", lambda _: None)
    mock_thread = MagicMock()
    monkeypatch.setattr("threading.Thread", lambda *args, **kwargs: mock_thread)

    # When
    with patch("builtins.input", lambda _: None):
        user_tool_main.main(test_mode=True)

    # Then
    mock_policy_manager.delete_all_policies.assert_called_once()
    mock_logger.info.assert_any_call("Deleting all policies...")
    mock_thread.start.assert_called_once()


def test_main_exit(monkeypatch):
    # Given
    mock_logger = MagicMock()
    monkeypatch.setattr("user_tool.user_tool_main.LOGGER", mock_logger)
    monkeypatch.setattr("user_tool.user_tool_main.user_interaction.non_blocking_input", lambda _: "3")
    monkeypatch.setattr("os.system", lambda _: None)
    mock_thread = MagicMock()
    monkeypatch.setattr("threading.Thread", lambda *args, **kwargs: mock_thread)

    # When
    with patch("builtins.input", lambda _: None):
        user_tool_main.main()

    # Then
    mock_logger.info.assert_any_call("Exiting User Tool.")
    mock_thread.start.assert_called_once()
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
