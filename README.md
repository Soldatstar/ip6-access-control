[![PyPI](https://img.shields.io/pypi/v/ip6-access-control)](https://pypi.org/project/ip6-access-control)
[![Python Versions](https://img.shields.io/pypi/pyversions/ip6-access-control)](https://pypi.org/project/ip6-access-control)
[![codecov](https://codecov.io/gh/Soldatstar/ip6-access-control/branch/main/graph/badge.svg)](https://codecov.io/gh/Soldatstar/ip6-access-control)
[![GitHub Actions test](https://github.com/soldatstar/ip6-access-control/actions/workflows/python-tests.yml/badge.svg)](https://github.com/Soldatstar/ip6-access-control/actions)
[![GitHub Actions build](https://github.com/soldatstar/ip6-access-control/actions/workflows/build-upload.yml/badge.svg)](https://github.com/Soldatstar/ip6-access-control/actions)
# 25FS_IMVS14: System zur feingranularen Ressourcen-Zugriffskontrolle unter Linux  
## IP6 Bachelorarbeit  

### Problematik

[Projektbeschreibung](Projektbeschreibung.pdf)  

Linux bietet verschiedene Mechanismen zur Kontrolle des Zugriffs auf Systemressourcen wie Dateien oder Netzwerkverbindungen (z. B. AppArmor, SELinux). Diese Mechanismen weisen jedoch folgende Schwächen auf:

- **Ungenauigkeit:** Die Regeln sind oft zu allgemein und erlauben keine feingranulare Zugriffskontrolle.
- **Komplexität:** Die Konfiguration erfordert spezialisiertes Wissen und ist statisch, d. h., sie passt sich nicht dynamisch an.
- **Mangelnde Benutzerinteraktion:** Benutzer werden nicht aktiv über Zugriffsversuche informiert und können diese nicht situativ erlauben oder verweigern.

### Lösung

[Projektvereinbarung](Projektvereinbarung.pdf)  

Linux Access Control ist ein benutzerfreundliches Werkzeug, das die Steuerung des Zugriffs von Programmen auf Ressourcen unter Linux ermöglicht. Es bietet:

1. **Überwachung:** Überwachung von Systemaufrufen, die Programme nutzen, um auf kritische Dateien zuzugreifen.
2. **Benutzerkontrolle:** Interaktive Abfragen, ob ein Zugriff erlaubt oder dauerhaft blockiert werden soll.
3. **Verständliche Kommunikation:** Übersetzung von Systemaufrufen und Parametern in leicht verständliche Fragen, um fundierte Entscheidungen zu ermöglichen.

### Benutzung  

#### Schnellstart (als geklonte Repository)
```bash
# Build-Prozess
make create # Erstellt eine Python-Umgebung und kompiliert den C-Code

# In zwei separaten Terminals ausführen:
make ut   # Startet das User-Tool und wartet auf Anfragen über ZMQ
make run  # Startet den Supervisor mit einer Demo für Datei-Zugriffe
```

#### Verfügbare Make-Befehle
```bash
# Setup und Verwaltung
make create       # Erstellt virtuelle Umgebung und kompiliert Demo-Programme
make delete       # Löscht die virtuelle Umgebung und alle temporären Dateien
make build        # Erstellt ein Python-Paket zur Veröffentlichung

# Anwendungsausführung
make ut           # Startet das User-Tool im normalen Modus
make utv          # Startet das User-Tool im Debug-Modus mit ausführlicher Protokollierung
make run          # Führt die Communication-Demo mit dem Supervisor aus
make run2         # Führt die Datei-Operationen-Demo mit dem Supervisor aus
make run3         # Führt die Child-Process-Demo mit dem Supervisor aus
make runv         # Führt die Demo im Debug-Modus aus (auch run2v, run3v verfügbar)

# Tests und Qualitätssicherung
make test         # Führt alle Tests mit Coverage-Bericht aus
make pylint       # Führt Pylint-Codeanalyse aus

# Benchmarking
make plots        # Generiert Plots aus Benchmark-Ergebnissen
make setup-plot-env # Installiert Abhängigkeiten für die Plot-Generierung
```

#### Schnellstart (als python Installation)
```bash
# Installieren Sie das Paket in einer Python-Umgebung
pip install ip6-access-control

# In zwei separaten Terminals ausführen:
user-tool               # Startet das User-Tool und wartet auf Anfragen über ZMQ
supervisor $(which ls)  # Startet den Supervisor mit dem absoluten Pfad des Programms (z. B. "ls")
```

### Benchmarking

Das Projekt enthält Tools zur Leistungsmessung des Access Control Systems. Benchmarks werden verwendet, um die Performance-Auswirkungen der Zugriffskontrolle zu messen und verschiedene Szenarien zu vergleichen.

#### Remote Benchmarks mit Ansible

Für konsistentere Ergebnisse wurden Benchmarks auf 2 Remote-Maschinen ausgeführt:

```bash
cd benchmark/ansible
# Vorbereitung der Remote-Umgebungen
ansible-playbook -i inventory.yml prepare-environment.yml

# Ausführen der Benchmarks auf allen Remote-Maschinen
ansible-playbook -i inventory.yml run_benchmark.yml

# Generieren von Plots aus den Ergebnissen
cd ..
make plots
```

#### Ergebnisanalyse

Die Benchmark-Ergebnisse werden in der `results/` Verzeichnis gespeichert und mit Matplotlib visualisiert:

- **Histogramme**: Zeigen die Verteilung der Ausführungszeiten
- **Liniendiagramme**: Zeigen Trends und potenzielle Performance-Abnahmen über mehrere Ausführungen
- **Box-Plots**: Vergleichen die Leistung zwischen verschiedenen Szenarien und Umgebungen

Die durchschnittlichen Ausführungszeiten werden in der Datei `average_times.log` protokolliert und können als schneller Vergleichspunkt verwendet werden.

```bash
# Anzeigen der durchschnittlichen Zeiten
cat benchmark/results/*/average_times.log
```


