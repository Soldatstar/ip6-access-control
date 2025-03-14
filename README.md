
# 25FS_IMVS14: System zur feingranularen Ressourcen-Zugriffskontrolle unter Linux  
## IP6 Bachelorarbeit  

[Projektbeschreibung](25FS_IMVS14.pdf)  

### 📖 Projektzusammenfassung  
**Zielsetzung:**  
Entwicklung eines intuitiven Sicherheitssystems für Linux, das Endnutzern eine feingranulare Kontrolle über Programmzugriffe auf Systemressourcen (Dateien, Netzwerk, Hardware) ermöglicht. Durch Integration mit Linux Security Modules (LSM) wird eine benutzerfreundliche Abstraktionsebene über komplexe Mechanismen wie AppArmor, SELinux und eBPF geschaffen.

**Kernfunktionen:**  
- Echtzeit-Überwachung von Systemcalls  
- Interaktive Erlaubnisabfrage per User-Tool  
- Dynamische Regelgenerierung mit Lernmodus  
- Persistente Speicherung von Zugriffsprofilen  
- Sandboxing kritischer Anwendungen  

**Technologiestack:**  
| Kategorie         | Technologien                 |
|--------------------|-----------------------------|
| Sicherheitslayer  | eBPF, AppArmor, Linux LSM   |
| Systemprogramm.   | C, ...        |
| UI                | CLI-Tools ...         |
| Policy Management | JSON ...            |

**Herausforderungen:**  
✓ Balance zwischen Sicherheit und Usability  
✓ Low-Latency-Integration in Kernelprozesse  
✓ Behandlung von Race Conditions  
✓ Cross-Version-Kompatibilität der LSM  

---

## 🛠️ Benutzung  

### Workflow  
1. **Detektion:** Supervisor erkennt kritische Systemaufrufe (open, connect, etc.)  
2. **Intervention:** Prozess wird suspendiert bis zur Nutzerentscheidung  
3. **Dialog:** User-Tool zeigt kontextbezogene Anfrage mit Risikobewertung  
4. **Politik-Update:** Entscheidung wird regelbasiert persistiert  

### Schnellstart  
```bash
# Build-Prozess
cd scripts
make all      # Kompiliert alle Komponenten
make test     # Führt Demoszenario aus
```

