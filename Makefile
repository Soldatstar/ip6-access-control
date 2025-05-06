# Variablen für Pfade und Befehle
VENV_DIR = env
PYTHON = python3
PIP = $(VENV_DIR)/bin/pip
ACTIVATE_LINUX = source $(VENV_DIR)/bin/activate
SHELL := /bin/bash
DEMOPROGRAM = demo/file-access
DEMOCPROGRAM = demo/file-access.c
SUPERVISOR_DIR = supervisor
USER_TOOL_DIR = user_tool
TEST_DIR = tests

# Hilfsnachricht
help:
	@echo "Verfügbare Befehle:"
	@echo "  make create: Erstellt ein virtuelles Environment und installiert Abhängigkeiten."
	@echo "  make delete: Löscht das virtuelle Environment."
	@echo "  make run: Aktiviert das virtuelle Environment und führt supervisor.py aus (Linux)."
	@echo "  make ut: Aktiviert das virtuelle Environment und führt user_tool.py aus (Linux)."
	@echo "  make test: Aktiviert das virtuelle Environment und führt die Tests aus (Linux)."
# Ziel zum Erstellen des virtuellen Environments und Installieren der Abhängigkeiten
create: 
	$(PYTHON) -m venv $(VENV_DIR) 
	$(ACTIVATE_LINUX)
	$(PIP) install -r requirements.txt
	gcc $(DEMOCPROGRAM) -o $(DEMOPROGRAM)

# Ziel zum Löschen des virtuellen Environments
delete:
	rm -rf $(VENV_DIR)
	-rm -f $(DEMOPROGRAM)
	rm -rf process-supervisor/
	rm -rf user_tool/__pycache__/
	rm -rf shared/__pycache__/
	rm -rf tests/__pycache__/
	rm -rf tests/.pytest_cache
	rm -rf .pytest_cache
	rm -rf __pycache__/
	rm -rf htmlcov/
	-rm -f .coverage
	
# Ziel zum Ausführen des Skripts (Linux)
run: 
	$(ACTIVATE_LINUX) && $(PYTHON) supervisor/supervisor.py $(DEMOPROGRAM)

ut:
	$(ACTIVATE_LINUX) && $(PYTHON) user_tool/user_tool_main.py

test:
	$(ACTIVATE_LINUX) && $(PYTHON) -m coverage run --source=$(SUPERVISOR_DIR),$(USER_TOOL_DIR),$(TEST_DIR) --omit=$(TEST_DIR)/* -m pytest -vv 
	$(ACTIVATE_LINUX) && $(PYTHON) -m coverage report 
	$(ACTIVATE_LINUX) && $(PYTHON) -m coverage html
.PHONY: help create delete run