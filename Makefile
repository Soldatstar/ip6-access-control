# Variablen für Pfade und Befehle
VENV_DIR = env
PYTHON = python3
PIP = $(VENV_DIR)/bin/pip
ACTIVATE_LINUX = source $(VENV_DIR)/bin/activate
SHELL := /bin/bash
DEMOCOMMUNICATION = demo/communication
DEMOCCOMMUNICATION = demo/communication.c
DEMONORMALFILES = demo/normal-file
DEMOCNORMALFILES = demo/normal-file.c
DEMOCHILDP = demo/child-process
DEMOCCHILDP = demo/child-process.c
DEMO_BACKUP = demo/normal-file2
DEMOC_BACKUP = demo/normal-file2.c

SUPERVISOR_DIR = supervisor
USER_TOOL_DIR = user_tool
TEST_DIR = tests

# Hilfsnachricht
help:
	@echo "Verfügbare Befehle:"
	@echo "  make create: Erstellt ein virtuelles Environment und installiert Abhängigkeiten."
	@echo "  make delete: Löscht das virtuelle Environment."
	@echo "  make run: Aktiviert das virtuelle Environment und führt supervisor.py aus (Linux)."
	@echo "  make runv: Aktiviert das virtuelle Environment und führt supervisor.py im Debug-Modus aus (Linux)."
	@echo "  make ut: Aktiviert das virtuelle Environment und führt user_tool.py aus (Linux)."
	@echo "  make utv: Aktiviert das virtuelle Environment und führt user_tool.py im Debug-Modus aus (Linux)."
	@echo "  make test: Aktiviert das virtuelle Environment und führt die Tests aus (Linux)."
	@echo "  make pylint: Aktiviert das virtuelle Environment und führt pylint aus (Linux)."
	@echo "  make build: Aktiviert das virtuelle Environment und erstellt das Projekt (Linux)."
	@echo "  make plots: Erstellt Plots aus den Benchmark-Ergebnissen."

# Ziel zum Erstellen des virtuellen Environments und Installieren der Abhängigkeiten
create: 
	$(PYTHON) -m venv $(VENV_DIR) 
	$(ACTIVATE_LINUX)
	$(PIP) install -r requirements.txt
	gcc $(DEMOCCOMMUNICATION) -o $(DEMOCOMMUNICATION)
	gcc $(DEMOCNORMALFILES) -o $(DEMONORMALFILES)
	gcc $(DEMOC_BACKUP) -o $(DEMO_BACKUP)
	gcc $(DEMOCCHILDP) -o $(DEMOCHILDP)

# Ziel zum Löschen des virtuellen Environments
delete:
	rm -rf $(VENV_DIR)
	-rm -f $(DEMOCOMMUNICATION)
	-rm -f $(DEMONORMALFILES)
	-rm -f $(DEMOBACKUP)
	-rm -f $(DEMOCHILDP)
	rm -rf process-supervisor/
	rm -rf user_tool/__pycache__/
	rm -rf supervisor/__pycache__/
	rm -rf shared/__pycache__/
	rm -rf tests/__pycache__/
	rm -rf tests/.pytest_cache
	rm -rf .pytest_cache
	rm -rf __pycache__/
	rm -rf htmlcov/
	-rm -f .coverage
	rm -rf dist/
	rm -rf env/
	rm -rf ip6_access_control.egg-info
	
# Ziel zum Ausführen des Skripts (Linux)
run: 
	$(ACTIVATE_LINUX) && $(PYTHON) supervisor/supervisor.py $(DEMOCOMMUNICATION) --silent

run2: 
	$(ACTIVATE_LINUX) && $(PYTHON) supervisor/supervisor.py $(DEMONORMALFILES)	--silent

run3: 
	$(ACTIVATE_LINUX) && $(PYTHON) supervisor/supervisor.py $(DEMOCHILDP)	--silent

ut:
	$(ACTIVATE_LINUX) && $(PYTHON) user_tool/user_tool_main.py

utv:
	$(ACTIVATE_LINUX) && $(PYTHON) user_tool/user_tool_main.py --debug

test:
	$(ACTIVATE_LINUX) && $(PYTHON) -m coverage run --source=$(SUPERVISOR_DIR),$(USER_TOOL_DIR),$(TEST_DIR) --omit=$(TEST_DIR)/* -m pytest -vv 
	$(ACTIVATE_LINUX) && $(PYTHON) -m coverage report 
	$(ACTIVATE_LINUX) && $(PYTHON) -m coverage html

pylint:
	$(ACTIVATE_LINUX) && pylint $(shell git ls-files '*.py')

build:
	$(ACTIVATE_LINUX) && $(PYTHON) -m build

runv: 
	$(ACTIVATE_LINUX) && $(PYTHON) supervisor/supervisor.py $(DEMOCOMMUNICATION) --debug

run2v:
	$(ACTIVATE_LINUX) && $(PYTHON) supervisor/supervisor.py  $(DEMONORMALFILES)	--debug

run3v: 
	$(ACTIVATE_LINUX) && $(PYTHON) supervisor/supervisor.py $(DEMOCHILDP) --debug

# Plotting targets
plots: 
	@echo "Generating plots from benchmark results..."
	@mkdir -p benchmark/plotting/plots
	@cd benchmark/plotting && bash generate_plots.sh
	@echo "Plots generated in benchmark/plotting/plots/"

setup-plot-env:
	$(ACTIVATE_LINUX) && $(PIP) install matplotlib numpy scipy

.PHONY: help create delete run plots setup-plot-env