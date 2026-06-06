# Changelog

## Kurze Zusammenfassung

ssh-vault2 wurde zu einem umfassenderen Remote-Workspace erweitert. Neben SSH-Terminal und SFTP-Dateimanager enthält die Anwendung jetzt einen integrierten RDP-Arbeitsbereich, ein robusteres Terminal, ein ausgebautes Sync-/Vault-System, eine modernisierte Oberfläche, bessere Self-Hosting-Dokumentation und mehr Sicherheitsprüfungen.

Die wichtigsten Punkte:

- integrierter RDP-Viewer direkt in der Desktop-App
- SSH-Terminal mit stabilerem Rendering und Rechtsklick-Menü
- SFTP-Dateimanager mit mehr Dateioperationen und besserem Drag & Drop
- verschlüsselter lokaler Datensafe für Zugangsdaten
- optionaler verschlüsselter Sync über eigenen Server
- Kontoportal mit Registrierung, Tokens, TOTP und Adminfunktionen
- Self-Hosting-Server für Webseite, Downloads, Sync und Release-Feed
- sauberere Cross-Platform-Builds für Windows, Linux und macOS
- deutlich erweiterte Regressionstests und Sicherheitsprüfungen

---

## Ausführlicher Changelog-Bericht

### 1. Desktop-Workspace

#### Neu

- Hostverwaltung für SSH- und RDP-Ziele.
- Tabs für parallele Arbeitsbereiche.
- Klarere Trennung von Terminal, SFTP, RDP, Vault, Sync und Einstellungen.
- Mehr Plattform-Metadaten für Windows, Linux und macOS.

#### Verbessert/angepasst

- Oberfläche stärker auf tägliche Remote-Arbeit ausgerichtet.
- Hostliste, Tabs und Seitenleisten wurden kompakter und konsistenter gestaltet.
- Mehr UI-Zustände zeigen klare Empty-State- und Fehlertexte.

### 2. SSH-Terminal

#### Neu

- Eigenes Terminal-Kontextmenü:
  - Kopieren
  - Einfügen
  - Schließen
- Kopieren übernimmt die aktuelle Terminalauswahl in die Systemzwischenablage.
- Einfügen schreibt Text aus der Systemzwischenablage in die aktive SSH-Sitzung.
- Bessere Tab-Verwaltung für mehrere SSH-Sitzungen.

#### Verbessert/angepasst

- Stabileres PTY-Handling.
- Geordnete Verarbeitung von Terminal-Ausgabechunks.
- Besseres Verhalten bei Resize, Fullscreen-Terminalprogrammen und Alternate-Screen-Ausgaben.
- Weniger fehleranfälliges Terminal-Replay.
- Rechtsklick-Menü öffnet zuverlässig beim ersten Klick.

### 3. SFTP-Dateimanager

#### Neu

- Mehrere SFTP-Sitzungen parallel.
- Commander-Ansicht mit lokalem und entferntem Dateisystem.
- Upload und Download von Dateien und Ordnern.
- Drag & Drop aus dem Dateimanager.
- Erhalt leerer Ordner bei Ordnerübertragungen.
- Datei-/Ordner-Kontextmenü.
- Properties-Dialog mit Pfad, Größe, Zeiten, Besitzer, Gruppe, Rechten und Checksummen.
- Remote- und lokale Dateioperationen wie Umbenennen, Löschen, neuer Ordner und Aktualisieren.

#### Verbessert/angepasst

- Stabilere Pfadbehandlung.
- Besserer Umgang mit Symlinks und rekursiven Dateioperationen.
- Klarere Empty States, wenn keine SFTP-Sitzung aktiv ist.
- Verbesserte Fehlertexte bei fehlenden Rechten, Verbindungsproblemen und ungültigen Pfaden.

### 4. RDP-Arbeitsbereich

#### Neu

- Integrierte RDP-Sitzungen direkt in der Desktop-App.
- RDP-Tabs neben SSH- und SFTP-Arbeitsbereichen.
- Canvas-/WebGL-basierter Desktop-Viewer.
- Skalierungsmodi für verschiedene Fenstergrößen und Monitore.
- Maus- und Tastatureingabe innerhalb der RDP-Sitzung.
- Clipboard-Unterstützung.
- Datei- und Ordner-Drop in RDP-Sitzungen.
- Schutz gegen doppelt geöffnete Sitzungen für denselben Host.

#### Verbessert/angepasst

- RDP-Sitzungen sind in Hostverwaltung, Tabs und UI-Zustände integriert.
- Rendering wurde auf flüssigere Bildaktualisierung und weniger unnötige Neuzeichnungen ausgelegt.
- Fehlerzustände wie Verbindungsabbruch, leere Anzeige oder ungültige Zugangsdaten werden deutlicher dargestellt.

### 5. Vault und Zugangsdaten

#### Neu

- Lokaler verschlüsselter Datensafe für Passwörter und private Keys.
- Hostprofile können auf Vault-Einträge verweisen.
- Vault kann gesperrt und entsperrt werden.
- Optionaler Sync von Vault-Daten als verschlüsselter Blob.

#### Verbessert/angepasst

- Weniger Klartext im UI-Zustand.
- Bessere Redaction in Fehlermeldungen und Log-nahen UI-Texten.
- Export- und Importpfade behandeln Secrets vorsichtiger.

### 6. Sync und Kontoportal

#### Neu

- Self-hosted Kontoportal.
- Registrierung, Login und Logout.
- Admin-Freigabe für Konten.
- Sync-Token-Erzeugung und Token-Löschung.
- TOTP-Einrichtung und TOTP-Deaktivierung.
- Passwort-Reset-Unterstützung bei konfiguriertem SMTP.
- Import/Export eigener Kontodaten.
- Sync-API für verschlüsselte Clientdaten.

#### Verbessert/angepasst

- Sync-Fehler werden verständlicher dargestellt.
- Sync unterscheidet klarer zwischen gesperrtem Datensafe, Authentifizierungsfehlern, Netzwerkfehlern und Quota-Problemen.
- Server speichert Sync-Daten atomarer und mit Backup-/Quota-Logik.
- Adminbereich zeigt Nutzerstatus, Tokenstatus, TOTP und Sync-Zustand übersichtlicher.

### 7. Self-Hosting-Server

#### Neu

- Server liefert Webseite, Downloadbereich, Kontoportal, Dokus und Release-Feed.
- Dockerfile und Compose-Beispiel für eigene Deployments.
- Healthcheck unter `/healthz`.
- Release-API unter `/api/v1/releases`.
- Downloadauslieferung mit Checksummen.
- Registrierung kann auf `open`, `approval` oder `closed` gesetzt werden.

#### Verbessert/angepasst

- Server läuft im Docker-Beispiel ohne Root-Rechte.
- Container ist read-only mit temporärem `/tmp`.
- Capabilities werden reduziert.
- Reverse-Proxy-Betrieb ist dokumentiert.
- Backups, Updates und Fehlersuche sind dokumentiert.

### 8. Webseite und Dokumentation

#### Neu

- Startseite beschreibt SSH, SFTP, RDP, Vault und Sync gemeinsam.
- Quickstart erwähnt SSH-, SFTP- und RDP-Verbindungen.
- Desktop-Anleitung enthält einen eigenen RDP-Abschnitt.
- Server-Anleitung erklärt, dass der Server kein SSH- oder RDP-Gateway ist.
- Webseiten-Anleitung beschreibt Konto, Tokens, TOTP, Sync und Adminbereich.
- README verlinkt diesen Changelog.

#### Verbessert/angepasst

- Texte sind stärker auf Anwender und Self-Hoster zugeschnitten.
- Interne Test- oder Deploymentdetails wurden aus public-facing Dokumentation entfernt.
- Beispiele nutzen neutrale Domains und Platzhalter.

### 9. Build und Packaging

#### Neu

- Versionen werden konsistenter über App, Frontend, Installer, Linux-Pakete, macOS-Metadaten und Server geführt.
- Packaging-Konfigurationen für Windows, Linux und macOS wurden aktualisiert.
- Release-Artefakte können mit Checksummen und Signaturen veröffentlicht werden.

#### Verbessert/angepasst

- Build-Konfigurationen wurden auf plattformübergreifende Nutzung ausgerichtet.
- Server und Client sind klarer getrennt.
- Public-Repo nutzt eine nachvollziehbare `client/`- und `server/`-Struktur.

### 10. Sicherheit und Robustheit

#### Neu

- Zusätzliche Prüfungen für Pfadbehandlung, Symlinks und lokale Dateioperationen.
- Quota- und Retention-Logik für Sync-Daten.
- Schutz gegen Account-Enumeration in mehreren Auth-Pfaden.
- Verbesserte Cookie-/Origin-Prüfungen für Webkonto-APIs.

#### Verbessert/angepasst

- Weniger sensible Daten in Fehlermeldungen.
- Stärkere Eingabevalidierung für Sync, Auth und Dateioperationen.
- Sicherere Updateprüfung mit Größen-, Versions- und URL-Gates.
- Server-Defaults sind besser für Reverse-Proxy-Betrieb und Self-Hosting geeignet.

### 11. Tests und Qualitätssicherung

#### Neu

- Zusätzliche Regressionstests für Terminal, SFTP, RDP, Sync, Security und Website-Texte.
- Syntax- und Build-Gates für Server und Frontend.
- Checks für public-facing Dokumentation und Release-Metadaten.

#### Verbessert/angepasst

- Kritische UI-Texte werden stärker gegen Regressionen abgesichert.
- Server-APIs werden auf Authentifizierung, Quotas, Sync-Verhalten und Sicherheitsheader geprüft.
- Public-Export wird vor Veröffentlichung auf sensible Daten und unerwünschte Begriffe gescannt.
