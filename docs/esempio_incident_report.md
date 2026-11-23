# Incident Report – Accessi SSH anomali

- **Data analisi:** 20/11/2026 11:37
- **File analizzato:** `dati/auth_attacco.log`
- **Periodo coperto:** 11/11/2026 02:13 – 11/11/2026 19:08
- **Eventi SSH analizzati:** 709
- **Finestre IP/tempo analizzate:** 16 (finestre da 5 minuti)
- **Finestre anomale:** 6 (soglia punteggio 0.0, almeno 3 eventi sospetti per finestra)
- **Modello:** Isolation Forest addestrato su 2026-10-20 08:25:52 – 2026-11-09 19:01:45

## Sintesi

Rilevati **3 IP sospetti**. **1 con accesso riuscito dopo tentativi falliti: possibile compromissione.**

| Gravità | IP | Prima attività | Ultima attività | Falliti | Utenti provati | Accessi riusciti | Punteggio |
| --- | --- | --- | --- | --- | --- | --- | --- |
| CRITICA | `192.168.56.66` | 11/11 02:13:00 | 11/11 02:17:00 | 332 | 14 | 1 | -0.305 |
| ALTA | `10.0.2.15` | 11/11 15:02:00 | 11/11 15:10:48 | 25 | 25 | 0 | -0.305 |
| MEDIA | `192.168.56.77` | 11/11 11:40:00 | 11/11 11:41:39 | 0 | 0 | 0 | -0.186 |

*Punteggio: più è negativo, più il comportamento è lontano dalla normalità.*

## Dettaglio per IP

### 192.168.56.66 – gravità CRITICA

**Perché è anomalo:**

- IP mai visto durante l'addestramento
- 160 tentativi di login falliti (massimo normale: 2)
- 144 tentativi con utenti inesistenti (massimo normale: 0)
- 14 nomi utente diversi provati (massimo normale: 2)
- 153.28 eventi al minuto (massimo normale: 3.38)
- 100% di tentativi falliti (massimo normale: 50%)

**Utenti provati (i più frequenti):** root (33), pi (32), admin (29), user (28), www-data (27), support (25), ftp (22), ubuntu (22), postgres (22), utente2 (19)

**Accessi riusciti da questo IP:**

- 11/11 02:17:00 utente **utente2** con password

### 10.0.2.15 – gravità ALTA

**Perché è anomalo:**

- IP mai visto durante l'addestramento
- 9 tentativi di login falliti (massimo normale: 2)
- 8 tentativi con utenti inesistenti (massimo normale: 0)
- 9 nomi utente diversi provati (massimo normale: 2)
- 5.86 eventi al minuto (massimo normale: 3.38)
- 100% di tentativi falliti (massimo normale: 50%)

**Utenti provati (i più frequenti):** root (1), admin (1), administrator (1), test (1), user (1), ubuntu (1), dev (1), backup (1), mysql (1), nagios (1)

### 192.168.56.77 – gravità MEDIA

**Perché è anomalo:**

- IP mai visto durante l'addestramento
- 40 connessioni chiuse prima dell'autenticazione (massimo normale: 1)
- 24.24 eventi al minuto (massimo normale: 3.38)

**Utenti provati (i più frequenti):** nessuno: connessioni chiuse prima del login (probabile scansione)

## Azioni consigliate

1. Bloccare subito gli IP sospetti con lo script `blocca_ip.sh` generato insieme a questo report.
2. **Per gli IP con accesso riuscito:** cambiare subito la password o revocare la chiave/certificato dell'utente coinvolto, controllare `last`, `~/.bash_history`, crontab e processi attivi.
3. Verificare che `PasswordAuthentication no` sia attivo in `/etc/ssh/sshd_config` e usare solo chiavi o certificati SSH.
4. Valutare fail2ban o un limite di connessioni sul firewall (`iptables -m recent` o `-m hashlimit`) per la porta 22.
5. Consentire SSH solo dalla VPN o da IP di gestione noti.
