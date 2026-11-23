# Guida al laboratorio

Questa guida spiega come provare il detector su VM reali: un server Ubuntu bersaglio, una VM attaccante e, se vuoi, il firewall iptables.

> **Attenzione:** gli attacchi vanno fatti **solo nel tuo laboratorio**, su macchine tue. Lanciare Hydra o Nmap contro sistemi di altri è un reato.

## Macchine

| Ruolo | Esempio | Cosa serve |
| --- | --- | --- |
| Bersaglio | Ubuntu Server (es. `target1`) | OpenSSH, Python 3 |
| Attaccante | Kali Linux, oppure Ubuntu con `sudo apt install hydra nmap` | Hydra, Nmap, netcat |
| Firewall (facoltativo) | la VM Ubuntu con iptables | per bloccare l'IP anche sul firewall |

Le VM devono vedersi in rete (rete host-only o NAT network) e il bersaglio deve poter scaricare i pacchetti Python.

## 1. Preparare il bersaglio

Se sul server hai disattivato il login con password (consigliato in produzione), Hydra non può provare password. Per il test usa **una VM di prova** e riattiva temporaneamente le password:

```bash
sudo nano /etc/ssh/sshd_config
#   PasswordAuthentication yes
# Su Ubuntu controlla anche i file in /etc/ssh/sshd_config.d/ (es. 50-cloud-init.conf)
sudo systemctl restart ssh
```

Crea un utente di prova con una password debole, che metterai nella lista di Hydra, per simulare una compromissione:

```bash
sudo adduser vittima          # password: estate2026
```

Installa il progetto:

```bash
sudo apt install -y python3-venv git
git clone https://github.com/<username>/ssh-anomaly-detector.git
cd ssh-anomaly-detector
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
mkdir -p dati
```

## 2. Raccogliere i log normali e addestrare

Usa il server normalmente per **almeno una o due settimane**: login dai tuoi PC, qualche errore di password, sessioni a orari diversi. Più dati normali ci sono, meno falsi allarmi.

```bash
sudo journalctl -u ssh --since "14 days ago" -o short > dati/auth_normale.log
# in alternativa: sudo cat /var/log/auth.log.1 /var/log/auth.log > dati/auth_normale.log
python3 detector.py addestra --log dati/auth_normale.log
```

Prima di addestrare controlla che in quel periodo **non ci siano attacchi**, altrimenti il modello li impara come normali.

> Non hai tempo di aspettare due settimane? Addestra sui log simulati (`python3 genera_log_test.py`) e usa il lab solo per la fase di attacco. Nel README specifica quale delle due hai fatto.

## 3. Lanciare gli attacchi dalla VM attaccante

Sostituisci `IP_BERSAGLIO` con l'IP del server. Prepara due piccole liste:

```bash
printf "root\nadmin\ntest\nubuntu\noracle\nguest\nvittima\n" > utenti.txt
printf "123456\npassword\nadmin\nqwerty\nroot\nubuntu\nestate2026\n" > password.txt
```

**Attacco 1 – brute force veloce** (deve risultare CRITICA, perché trova la password di `vittima`):

```bash
hydra -L utenti.txt -P password.txt -t 4 ssh://IP_BERSAGLIO
```

**Attacco 2 – password spraying lento** (una password su tanti utenti, con pause):

```bash
hydra -L utenti.txt -p Primavera2026! -c 20 ssh://IP_BERSAGLIO
```

**Attacco 3 – scansione:**

```bash
nmap -sV -p 22 IP_BERSAGLIO
for i in $(seq 1 30); do nc -w1 IP_BERSAGLIO 22 < /dev/null; done
```

Ideale: lancia gli attacchi da IP diversi (per esempio cambiando IP alla VM attaccante tra un attacco e l'altro), così nel report compaiono separati.

## 4. Analizzare

Sul bersaglio:

```bash
sudo journalctl -u ssh --since "today" -o short > dati/auth_test.log
python3 detector.py analizza --log dati/auth_test.log --grafico --whitelist IP_DEL_TUO_PC
```

Otterrai nella cartella `report/`:

- `incident_report_*.md` – il report dell'incidente;
- `grafico_*.png` – l'attività SSH per IP nel tempo;
- `finestre_*.csv` – tutti i punteggi, utili per capire il modello;
- `blocca_ip.sh` – le regole iptables per gli IP sospetti.

Se ci sono troppi falsi allarmi, aumenta `--min-eventi` o abbassa `--soglia` (per esempio `-0.05`). Se non rileva un attacco, fai il contrario.

## 5. Bloccare l'attaccante

```bash
sudo bash report/blocca_ip.sh
sudo iptables -L INPUT -n --line-numbers      # verifica la regola
```

Dalla VM attaccante `ssh vittima@IP_BERSAGLIO` ora resta appeso: l'IP è bloccato. Per toglierlo:

```bash
sudo iptables -D INPUT -s IP_ATTACCANTE -p tcp --dport 22 -j DROP
```

Sul firewall del lab puoi usare la regola `FORWARD` che trovi commentata nello script, così l'attaccante viene fermato prima di arrivare al server.

## 6. Chiudere il test

```bash
sudo deluser --remove-home vittima
sudo nano /etc/ssh/sshd_config      # di nuovo PasswordAuthentication no
sudo systemctl restart ssh
```

## 7. Documentare su GitHub

1. Fai uno screenshot del terminale durante l'attacco Hydra e del risultato di `detector.py analizza`.
2. Copia il grafico e il report del tuo test in `docs/` (sostituisci gli esempi simulati o aggiungili accanto).
3. Nel README aggiungi una sezione "Risultati nel laboratorio" con una tabella come quella dei log simulati.
4. Pubblica:

```bash
git add .
git commit -m "Test in laboratorio con Hydra e Nmap"
git push
```
