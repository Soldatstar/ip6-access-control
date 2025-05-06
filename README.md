# 25FS_IMVS14: System zur feingranularen Ressourcen-Zugriffskontrolle unter Linux  
## IP6 Bachelorarbeit  

[![codecov](https://codecov.io/gh/Soldatstar/ip6-access-control/branch/main/graph/badge.svg)](https://codecov.io/gh/Soldatstar/ip6-access-control)

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

### 🛠️ Benutzung  

#### Schnellstart  
```bash
# Build-Prozess
make create # Erstellt eine Python-Umgebung und kompiliert den C-Code

# In zwei separaten Terminals ausführen:
make ut   # Startet das User-Tool und wartet auf Anfragen über ZMQ
make run  # Startet den Supervisor mit einer Demo für Datei-Zugriffe
```
