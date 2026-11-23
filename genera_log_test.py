#!/usr/bin/env python3
"""
Genera log SSH simulati per provare il detector senza un laboratorio:
  dati/auth_normale.log  -> 21 giorni di accessi normali (per l'addestramento)
  dati/auth_attacco.log  -> 1 giorno normale + 3 attacchi:
       - brute force veloce da 192.168.56.66 (stile Hydra) con accesso riuscito finale
       - password spraying lento da 10.0.2.15
       - scansione/probing da 192.168.56.77

Uso:  python3 genera_log_test.py
"""

import random
from datetime import datetime, timedelta
from pathlib import Path

random.seed(7)
HOST = "target1"
UTENTI = ["utente", "utente1", "utente2", "utente3"]
IP_NORMALI = ["192.168.56.1", "192.168.56.10", "192.168.56.11", "192.168.56.12"]
DIZIONARIO = ["root", "admin", "test", "ubuntu", "oracle", "postgres", "user", "guest",
              "ftp", "pi", "support", "www-data", "git", "utente2"]
SPRAY = ["root", "admin", "administrator", "test", "user", "ubuntu", "dev", "backup",
         "mysql", "nagios", "jenkins", "deploy", "ansible", "operator", "sysadmin",
         "utente", "utente1", "utente2", "utente3", "guest", "demo", "info", "web", "sql", "ftpuser"]


def riga(ts, pid, msg):
    return f"{ts:%b} {ts.day:2d} {ts:%H:%M:%S} {HOST} sshd[{pid}]: {msg}"


def sessione_normale(ts):
    """Un login normale: chiave/certificato, a volte un errore prima."""
    ip, utente, pid = random.choice(IP_NORMALI), random.choice(UTENTI), random.randint(1000, 60000)
    porta = random.randint(40000, 65000)
    out = []
    if random.random() < 0.08:  # chiave non caricata al primo colpo
        out.append(riga(ts, pid, f"Connection closed by authenticating user {utente} {ip} port {porta} [preauth]"))
        ts += timedelta(seconds=random.randint(5, 40))
        pid, porta = pid + 1, porta + 1
    if random.random() < 0.05:  # password sbagliata una volta
        out.append(riga(ts, pid, f"Failed password for {utente} from {ip} port {porta} ssh2"))
        ts += timedelta(seconds=random.randint(2, 8))
    metodo = "publickey" if random.random() < 0.85 else "password"
    extra = " ssh2: ED25519-CERT SHA256:Xr3k9 ID utente (serial 0) CA ED25519 SHA256:CAkey" if metodo == "publickey" else " ssh2"
    out.append(riga(ts, pid, f"Accepted {metodo} for {utente} from {ip} port {porta}{extra}"))
    out.append(riga(ts, pid, f"pam_unix(sshd:session): session opened for user {utente}(uid=1000) by (uid=0)"))
    fine = ts + timedelta(minutes=random.randint(3, 90))
    out.append(riga(fine, pid, f"pam_unix(sshd:session): session closed for user {utente}"))
    return out


def giornata_normale(giorno):
    righe = []
    weekend = giorno.weekday() >= 5
    for _ in range(random.randint(2, 5) if weekend else random.randint(10, 22)):
        ts = giorno + timedelta(hours=random.uniform(8, 19.5))
        righe += sessione_normale(ts)
    return righe


def brute_force(inizio, successo=True):
    ip, righe, ts = "192.168.56.66", [], inizio
    for i in range(320):
        pid, porta = 20000 + i, 33000 + i
        utente = random.choice(DIZIONARIO)
        if utente in ("root", "utente2"):
            righe.append(riga(ts, pid, f"Failed password for {utente} from {ip} port {porta} ssh2"))
        else:
            righe.append(riga(ts, pid, f"Invalid user {utente} from {ip} port {porta}"))
            righe.append(riga(ts, pid, f"Failed password for invalid user {utente} from {ip} port {porta} ssh2"))
        ts += timedelta(seconds=random.uniform(0.3, 1.2))
    righe.append(riga(ts, 20999, f"message repeated 12 times: [ Failed password for root from {ip} port 34500 ssh2]"))
    if successo:
        ts += timedelta(seconds=2)
        righe.append(riga(ts, 21000, f"Accepted password for utente2 from {ip} port 34501 ssh2"))
        righe.append(riga(ts, 21000, "pam_unix(sshd:session): session opened for user utente2(uid=1002) by (uid=0)"))
    return righe


def password_spray(inizio):
    ip, righe, ts = "10.0.2.15", [], inizio
    for i, utente in enumerate(SPRAY):
        pid, porta = 40000 + i, 51000 + i
        if utente.startswith("utente") or utente == "root":
            righe.append(riga(ts, pid, f"Failed password for {utente} from {ip} port {porta} ssh2"))
        else:
            righe.append(riga(ts, pid, f"Invalid user {utente} from {ip} port {porta}"))
            righe.append(riga(ts, pid, f"Failed password for invalid user {utente} from {ip} port {porta} ssh2"))
        ts += timedelta(seconds=random.uniform(15, 30))
    return righe


def scansione(inizio):
    ip, righe, ts = "192.168.56.77", [], inizio
    for i in range(40):
        righe.append(riga(ts, 50000 + i, f"Connection closed by {ip} port {45000 + i} [preauth]"))
        ts += timedelta(seconds=random.uniform(1, 4))
    return righe


def ordina(righe):
    anno = datetime.now().year
    return sorted(righe, key=lambda r: datetime.strptime(f"{anno} {' '.join(r[:15].split())}", "%Y %b %d %H:%M:%S"))


def main():
    Path("dati").mkdir(exist_ok=True)
    anno = datetime.now().year
    inizio = datetime(anno, 10, 20)

    normale = []
    for d in range(21):
        normale += giornata_normale(inizio + timedelta(days=d))
    Path("dati/auth_normale.log").write_text("\n".join(ordina(normale)) + "\n")

    giorno = inizio + timedelta(days=22)
    attacco = giornata_normale(giorno)
    attacco += brute_force(giorno + timedelta(hours=2, minutes=13))
    attacco += password_spray(giorno + timedelta(hours=15, minutes=2))
    attacco += scansione(giorno + timedelta(hours=11, minutes=40))
    Path("dati/auth_attacco.log").write_text("\n".join(ordina(attacco)) + "\n")

    print("Creati: dati/auth_normale.log e dati/auth_attacco.log")


if __name__ == "__main__":
    main()
