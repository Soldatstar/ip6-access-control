# Variablen für Pfade und Befehle
VENV_DIR = env
PYTHON = python3
PIP = $(VENV_DIR)/bin/pip
ACTIVATE_LINUX = source $(VENV_DIR)/bin/activate
SHELL := /bin/bash
DEMOPROGRAM = demo/file-access
DEMOCPROGRAM = demo/file-access.c

# Hilfsnachricht
help:
	@echo "Verfügbare Befehle:"
	@echo "  make create: Erstellt ein virtuelles Environment und installiert Abhängigkeiten."
	@echo "  make delete: Löscht das virtuelle Environment."
	@echo "  make run: Aktiviert das virtuelle Environment und führt main.py aus (Linux)."

# Ziel zum Erstellen des virtuellen Environments und Installieren der Abhängigkeiten
create: 
	$(PYTHON) -m venv $(VENV_DIR) 
	$(ACTIVATE_LINUX)
	$(PIP) install -r requirements.txt
	gcc $(DEMOCPROGRAM) -o $(DEMOPROGRAM)

# Ziel zum Löschen des virtuellen Environments
delete:
	rm -rf $(VENV_DIR)
	rm $(DEMOPROGRAM)
	
# Ziel zum Ausführen des Skripts (Linux)
run: 
	$(ACTIVATE_LINUX) && $(PYTHON) supervisor/supervisor.py $(DEMOPROGRAM)


.PHONY: help create delete run