# Incident Report – Accessi SSH anomali

- **Data analisi:** 23/11/2026 15:37
- **File analizzato:** `dati/auth_attacco.log`
- **Periodo coperto:** 23/11/2026 15:02 – 23/11/2026 15:37
- **Eventi SSH analizzati:** 132
- **Finestre IP/tempo analizzate:** 18 (finestre da 1 minuti)
- **Finestre anomale:** 7 (soglia punteggio 0.0, almeno 3 eventi sospetti per finestra)
- **Modello:** Isolation Forest addestrato su 2026-10-20 10:38:40 – 2026-11-23 15:16:47

## Sintesi

Rilevati **2 IP sospetti**. **2 con accesso riuscito dopo tentativi falliti: possibile compromissione.**

| Gravità | IP | Prima attività | Ultima attività | Falliti | Utenti provati | Accessi riusciti | Punteggio |
| --- | --- | --- | --- | --- | --- | --- | --- |
| CRITICA | `200.0.0.5` | 23/11 15:26:13 | 23/11 15:29:06 | 15 | 7 | 1 | -0.302 |
| CRITICA | `200.0.0.3` | 23/11 15:02:45 | 23/11 15:37:43 | 34 | 6 | 1 | -0.284 |

*Punteggio: più è negativo, più il comportamento è lontano dalla normalità.*

## Dettaglio per IP

### 200.0.0.5 – gravità CRITICA

**Perché è anomalo:**

- 4 tentativi di login falliti (massimo normale: 2)
- 2 tentativi con utenti inesistenti (massimo normale: 1)
- 4 connessioni chiuse prima dell'autenticazione (massimo normale: 2)
- 2 nomi utente diversi provati (massimo normale: 1)
- 10 eventi al minuto (massimo normale: 4)
- 9 tentativi di login falliti (massimo normale: 2)

**Utenti provati (i più frequenti):** root (3), admin (3), test (3), oracle (3), ubuntu (3)

**Accessi riusciti da questo IP:**

- 23/11 15:28:29 utente **vittima** con password

### 200.0.0.3 – gravità CRITICA

**Perché è anomalo:**

- 11 tentativi di login falliti (massimo normale: 2)
- 4 tentativi con utenti inesistenti (massimo normale: 1)
- 2 nomi utente diversi provati (massimo normale: 1)
- 15 eventi al minuto (massimo normale: 4)
- 15 tentativi di login falliti (massimo normale: 2)
- 3 tentativi con utenti inesistenti (massimo normale: 1)

**Utenti provati (i più frequenti):** root (10), admin (10), test (5), ubuntu (5), vittima (4)

**Accessi riusciti da questo IP:**

- 23/11 15:02:45 utente **alessandro** con publickey
- 23/11 15:03:01 utente **alessandro** con publickey
- 23/11 15:03:16 utente **alessandro** con publickey
- 23/11 15:03:32 utente **alessandro** con publickey
- 23/11 15:03:47 utente **alessandro** con publickey
- 23/11 15:04:02 utente **alessandro** con publickey
- 23/11 15:04:17 utente **alessandro** con publickey
- 23/11 15:04:33 utente **alessandro** con publickey
- 23/11 15:04:48 utente **alessandro** con publickey
- 23/11 15:05:03 utente **alessandro** con publickey
- 23/11 15:05:19 utente **alessandro** con publickey
- 23/11 15:05:34 utente **alessandro** con publickey
- 23/11 15:05:49 utente **alessandro** con publickey
- 23/11 15:06:04 utente **alessandro** con publickey
- 23/11 15:06:20 utente **alessandro** con publickey
- 23/11 15:06:35 utente **alessandro** con publickey
- 23/11 15:06:50 utente **alessandro** con publickey
- 23/11 15:07:05 utente **alessandro** con publickey
- 23/11 15:07:21 utente **alessandro** con publickey
- 23/11 15:07:36 utente **alessandro** con publickey
- 23/11 15:07:51 utente **alessandro** con publickey
- 23/11 15:08:06 utente **alessandro** con publickey
- 23/11 15:08:22 utente **alessandro** con publickey
- 23/11 15:08:37 utente **alessandro** con publickey
- 23/11 15:08:52 utente **alessandro** con publickey
- 23/11 15:09:08 utente **alessandro** con publickey
- 23/11 15:09:23 utente **alessandro** con publickey
- 23/11 15:16:47 utente **root** con publickey
- 23/11 15:30:05 utente **root** con publickey
- 23/11 15:36:29 utente **vittima** con password
- 23/11 15:37:43 utente **root** con publickey

## Azioni consigliate

1. Bloccare subito gli IP sospetti con lo script `blocca_ip.sh` generato insieme a questo report.
2. **Per gli IP con accesso riuscito:** cambiare subito la password o revocare la chiave/certificato dell'utente coinvolto, controllare `last`, `~/.bash_history`, crontab e processi attivi.
3. Verificare che `PasswordAuthentication no` sia attivo in `/etc/ssh/sshd_config` e usare solo chiavi o certificati SSH.
4. Valutare fail2ban o un limite di connessioni sul firewall (`iptables -m recent` o `-m hashlimit`) per la porta 22.
5. Consentire SSH solo dalla VPN o da IP di gestione noti.
