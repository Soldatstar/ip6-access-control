# Linux Access Control Tool

[![codecov](https://codecov.io/gh/Soldatstar/ip6-access-control/branch/main/graph/badge.svg)](https://codecov.io/gh/Soldatstar/ip6-access-control)

## Problematik:

Linux bietet Möglichkeiten zur Kontrolle des Zugriffs auf Systemressourcen wie Dateien oder Netzwerkverbindungen (z.B. AppArmor, SELinux). Allerdings haben diese vorhandenen Mechanismen folgende Nachteile:

* **Ungenauigkeit:**
Die bestehenden Regeln erlauben oft nur sehr allgemeine Zugriffsbeschränkungen.
* **Komplexität:**
Die Einrichtung dieser Regeln erfordert spezialisiertes Wissen, und die Konfiguration ist statisch, d.h., sie ändert sich nicht dynamisch, während das Programm läuft.
* **Mangelnde Benutzerinteraktion:**
Benutzer werden nicht aktiv über Zugriffsversuche informiert und haben keine Möglichkeit, diese in der jeweiligen Situation zu erlauben oder zu verbieten.

## Lösung:

Linux Access Control ist ein benutzerfreundliches Werkzeug, mit dem Sie den Zugriff von Programmen auf Ressourcen unter Linux steuern können.

1. **Überwachung:** Das Programm überwacht, welche Systemaufrufe Programme verwenden, um auf wichtige Dateien zuzugreifen.
2. **Benutzerkontrolle:** Wenn ein Programm versucht, auf eine kritische Datei zuzugreifen, werden Sie gefragt, ob dieser Zugriff erlaubt werden soll. Sie können den Zugriff erlauben oder dauerhaft für dieses Programm blockieren.
3. **Verständliche Fragen:** Die Systemaufrufe und ihre Parameter werden in einfache Fragen übersetzt, damit Sie leicht entscheiden können, ob der Zugriff sinnvoll ist.

## Benutzung:

Wird später beschrieben....