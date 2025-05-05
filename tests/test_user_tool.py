import pytest
import os
import json
from pathlib import Path
from user_tool.user_tool import list_known_apps

def test_list_known_apps_with_policies(tmp_path, monkeypatch, caplog):  # pragma: no cover
    # Setup: Create a mock POLICIES_DIR with valid policy files
    mock_policies_dir = tmp_path / "policies"
    mock_policies_dir.mkdir()
    app1_dir = mock_policies_dir / "app1"
    app1_dir.mkdir()
    (app1_dir / "policy.json").write_text(json.dumps({
        "metadata": {"process_name": "App1"},
        "rules": {}
    }))
    app2_dir = mock_policies_dir / "app2"
    app2_dir.mkdir()
    (app2_dir / "policy.json").write_text(json.dumps({
        "metadata": {"process_name": "App2"},
        "rules": {}
    }))

    # Monkeypatch POLICIES_DIR to point to the temporary directory
    monkeypatch.setattr("user_tool.user_tool.POLICIES_DIR", str(mock_policies_dir))

    # Call the function
    with caplog.at_level("INFO"):
        list_known_apps()

    # Verify output
    assert "Known applications with policies:" in caplog.text
    assert "- App1 (Hash: app1)" in caplog.text
    assert "- App2 (Hash: app2)" in caplog.text


def test_list_known_apps_no_policies_dir(monkeypatch, caplog):  # pragma: no cover
    # Monkeypatch POLICIES_DIR to a non-existent directory
    monkeypatch.setattr("user_tool.user_tool.POLICIES_DIR", "/non/existent/directory")

    # Call the function
    with caplog.at_level("INFO"):
        list_known_apps()

    # Verify output
    assert "No policies directory found." in caplog.text


def test_list_known_apps_empty_dir(tmp_path, monkeypatch, caplog):  # pragma: no cover
    # Setup: Create an empty mock POLICIES_DIR
    mock_policies_dir = tmp_path / "policies"
    mock_policies_dir.mkdir()

    # Monkeypatch POLICIES_DIR to point to the temporary directory
    monkeypatch.setattr("user_tool.user_tool.POLICIES_DIR", str(mock_policies_dir))

    # Call the function
    with caplog.at_level("INFO"):
        list_known_apps()

    # Verify output
    assert "No known applications with policies." in caplog.text


def test_list_known_apps_invalid_policy_file(tmp_path, monkeypatch, caplog):  # pragma: no cover
    # Setup: Create a mock POLICIES_DIR with an invalid policy file
    mock_policies_dir = tmp_path / "policies"
    mock_policies_dir.mkdir()
    app1_dir = mock_policies_dir / "app1"
    app1_dir.mkdir()
    (app1_dir / "policy.json").write_text("Invalid JSON")

    # Monkeypatch POLICIES_DIR to point to the temporary directory
    monkeypatch.setattr("user_tool.user_tool.POLICIES_DIR", str(mock_policies_dir))

    # Call the function
    with caplog.at_level("INFO"):
        list_known_apps()

    # Verify output
    assert "Known applications with policies:" in caplog.text
    assert "- app1 (Invalid policy file)" in caplog.text