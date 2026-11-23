#!/usr/bin/env python3
"""
SSH Anomaly Detector
====================
Rileva accessi SSH anomali (brute force, password spraying, scansioni) nei log
di Ubuntu Server usando un modello di machine learning non supervisionato
(Isolation Forest).

Flusso:
  1. addestra  -> impara il comportamento "normale" da un log senza attacchi
  2. analizza  -> assegna un punteggio di anomalia a ogni IP in ogni finestra
                  di tempo, genera un Incident Report e uno script di blocco
                  iptables per gli IP sospetti

Esempi:
  python3 detector.py addestra --log dati/auth_normale.log
  python3 detector.py analizza --log dati/auth_attacco.log --grafico
"""

import argparse
import json
import re
import subprocess
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

# --------------------------------------------------------------------------
# 1. PARSING DEI LOG
# --------------------------------------------------------------------------

# Formato classico syslog:   "Nov 20 10:15:01 server sshd[1234]: ..."
RE_SYSLOG = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2}) \S+ "
    r"sshd(?:-session)?\[\d+\]: (?P<msg>.*)$"
)
# Formato ISO (Ubuntu 24.04): "2026-11-20T10:15:01.123456+01:00 server sshd[1234]: ..."
RE_ISO = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:?\d{2}|Z)?) \S+ "
    r"sshd(?:-session)?\[\d+\]: (?P<msg>.*)$"
)
# rsyslog a volte compatta le righe uguali: "message repeated 5 times: [ ... ]"
RE_RIPETUTO = re.compile(r"^message repeated (\d+) times: \[ ?(.*?) ?\]$")

# Eventi SSH riconosciuti: (tipo, regex)
EVENTI = [
    ("riuscito", re.compile(
        r"^Accepted (?P<metodo>\S+) for (?P<user>\S+) from (?P<ip>\S+) port \d+")),
    ("fallito", re.compile(
        r"^Failed (?P<metodo>\S+) for (?:invalid user )?(?P<user>\S*) from (?P<ip>\S+) port \d+")),
    ("utente_inesistente", re.compile(
        r"^Invalid user (?P<user>\S*) ?from (?P<ip>\S+)")),
    ("preauth", re.compile(
        r"^(?:Connection closed|Disconnected) by (?:authenticating |invalid )?user "
        r"(?P<user>\S+) (?P<ip>\S+) port \d+ \[preauth\]")),
    # Connessioni aperte e chiuse senza login: tipiche di scansioni (nmap, netcat, bot)
    ("preauth", re.compile(
        r"^(?:Connection closed|Disconnected) by (?P<ip>[0-9a-fA-F.:]+) port \d+(?: \[preauth\])?$")),
    ("preauth", re.compile(r"^Did not receive identification string from (?P<ip>[0-9a-fA-F.:]+)")),
    ("preauth", re.compile(r"^banner exchange: Connection from (?P<ip>[0-9a-fA-F.:]+) port \d+")),
    ("preauth", re.compile(r"^Unable to negotiate with (?P<ip>[0-9a-fA-F.:]+) port \d+")),
]


def leggi_timestamp(testo, anno):
    """Converte il timestamp del log in datetime (senza fuso orario)."""
    if testo[0].isdigit():
        return datetime.fromisoformat(testo.replace("Z", "+00:00")).replace(tzinfo=None)
    return datetime.strptime(f"{anno} {' '.join(testo.split())}", "%Y %b %d %H:%M:%S")


def parse_log(percorso, anno=None):
    """Legge un file auth.log e restituisce un DataFrame con un evento SSH per riga."""
    anno = anno or datetime.now().year
    righe = []
    with open(percorso, encoding="utf-8", errors="replace") as f:
        for riga in f:
            m = RE_ISO.match(riga.strip()) or RE_SYSLOG.match(riga.strip())
            if not m:
                continue
            msg, ripetizioni = m.group("msg"), 1
            r = RE_RIPETUTO.match(msg)
            if r:
                ripetizioni, msg = int(r.group(1)), r.group(2)
            for tipo, regex in EVENTI:
                e = regex.match(msg)
                if e:
                    d = e.groupdict()
                    ts = leggi_timestamp(m.group("ts"), anno)
                    for _ in range(ripetizioni):
                        righe.append({
                            "ts": ts,
                            "ip": d["ip"],
                            "utente": d.get("user") or "-",
                            "tipo": tipo,
                            "metodo": d.get("metodo") or "-",
                        })
                    break
    return pd.DataFrame(righe, columns=["ts", "ip", "utente", "tipo", "metodo"])


# --------------------------------------------------------------------------
# 2. FEATURE ENGINEERING
# --------------------------------------------------------------------------

FEATURE = [
    "tentativi_falliti",
    "utenti_inesistenti",
    "chiusure_preauth",
    "accessi_riusciti",
    "utenti_distinti",
    "eventi_al_minuto",
    "tasso_fallimento",
    "fuori_orario",
]

DESCRIZIONI = {
    "tentativi_falliti": "tentativi di login falliti",
    "utenti_inesistenti": "tentativi con utenti inesistenti",
    "chiusure_preauth": "connessioni chiuse prima dell'autenticazione",
    "accessi_riusciti": "accessi riusciti",
    "utenti_distinti": "nomi utente diversi provati",
    "eventi_al_minuto": "eventi al minuto",
    "tasso_fallimento": "percentuale di fallimenti",
    "fuori_orario": "attività fuori orario",
}


def calcola_feature(eventi, finestra_min, inizio_orario=7, fine_orario=21):
    """Raggruppa gli eventi per IP e finestra di tempo e calcola le feature."""
    if eventi.empty:
        return pd.DataFrame(columns=["ip", "finestra"] + FEATURE)
    ev = eventi.copy()
    ev["finestra"] = ev["ts"].dt.floor(f"{finestra_min}min")
    righe = []
    for (ip, fin), g in ev.groupby(["ip", "finestra"]):
        conteggi = g["tipo"].value_counts()
        falliti = int(conteggi.get("fallito", 0))
        riusciti = int(conteggi.get("riuscito", 0))
        durata_min = max((g["ts"].max() - g["ts"].min()).total_seconds() / 60, 1.0)
        ora = fin.hour
        righe.append({
            "ip": ip,
            "finestra": fin,
            "tentativi_falliti": falliti,
            "utenti_inesistenti": int(conteggi.get("utente_inesistente", 0)),
            "chiusure_preauth": int(conteggi.get("preauth", 0)),
            "accessi_riusciti": riusciti,
            "utenti_distinti": g.loc[g["utente"] != "-", "utente"].nunique(),
            "eventi_al_minuto": round(len(g) / durata_min, 2),
            "tasso_fallimento": round(falliti / (falliti + riusciti), 2) if falliti + riusciti else 0.0,
            "fuori_orario": int(not (inizio_orario <= ora < fine_orario)),
        })
    return pd.DataFrame(righe)


def matrice(df):
    """Trasforma le feature per il modello: log(1+x) sui conteggi per ridurre gli estremi."""
    X = df[FEATURE].astype(float).copy()
    for col in FEATURE:
        if col not in ("tasso_fallimento", "fuori_orario"):
            X[col] = np.log1p(X[col])
    return X


# --------------------------------------------------------------------------
# 3. ADDESTRAMENTO
# --------------------------------------------------------------------------

def addestra(args):
    eventi = parse_log(args.log, args.anno)
    if eventi.empty:
        sys.exit(f"Nessun evento SSH trovato in {args.log}. Controlla il file.")
    feat = calcola_feature(eventi, args.finestra)
    print(f"Eventi SSH letti: {len(eventi)}  |  finestre IP/tempo: {len(feat)}")
    if len(feat) < 20:
        print("ATTENZIONE: meno di 20 finestre di addestramento. Il modello funziona, "
              "ma raccogli più giorni di log normali per risultati più affidabili.")

    modello = IsolationForest(n_estimators=200, contamination="auto", random_state=42)
    modello.fit(matrice(feat))

    pacchetto = {
        "modello": modello,
        "finestra_min": args.finestra,
        "max_normali": feat[FEATURE].max().to_dict(),
        "media_normali": feat[FEATURE].mean().round(2).to_dict(),
        "ip_conosciuti": sorted(eventi["ip"].unique()),
        "utenti_conosciuti": sorted(eventi.loc[eventi["tipo"] == "riuscito", "utente"].unique()),
        "periodo": [str(eventi["ts"].min()), str(eventi["ts"].max())],
    }
    Path(args.modello).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pacchetto, args.modello)
    print(f"Modello salvato in {args.modello}")
    print(f"IP visti come normali: {', '.join(pacchetto['ip_conosciuti'])}")


# --------------------------------------------------------------------------
# 4. ANALISI, REPORT E BLOCCO
# --------------------------------------------------------------------------

def motivazioni(riga, pacchetto):
    """Spiega in italiano perché una finestra è anomala, rispetto ai dati normali."""
    out = []
    if riga["ip"] not in pacchetto["ip_conosciuti"]:
        out.append("IP mai visto durante l'addestramento")
    for col in FEATURE:
        val, max_n = riga[col], pacchetto["max_normali"].get(col, 0)
        if col == "fuori_orario":
            if val and not max_n:
                out.append("attività fuori orario, mai vista nei dati normali")
        elif col == "tasso_fallimento":
            if val > max_n and val >= 0.5:
                out.append(f"{val:.0%} di tentativi falliti (massimo normale: {max_n:.0%})")
        elif val > max_n and val > 0:
            out.append(f"{val:g} {DESCRIZIONI[col]} (massimo normale: {max_n:g})")
    return out or ["combinazione di valori insolita"]


def gravita(info):
    if info["accessi_riusciti"] > 0 and info["tentativi_falliti"] > 0:
        return "CRITICA"
    if info["tentativi_falliti"] + info["utenti_inesistenti"] >= 20:
        return "ALTA"
    return "MEDIA"


def scrivi_report(percorso, args, pacchetto, eventi, feat, sospetti):
    ora = datetime.now().strftime("%d/%m/%Y %H:%M")
    n_anom = int(feat["anomala"].sum())
    L = []
    L.append("# Incident Report – Accessi SSH anomali\n")
    L.append(f"- **Data analisi:** {ora}")
    L.append(f"- **File analizzato:** `{args.log}`")
    L.append(f"- **Periodo coperto:** {eventi['ts'].min():%d/%m/%Y %H:%M} – {eventi['ts'].max():%d/%m/%Y %H:%M}")
    L.append(f"- **Eventi SSH analizzati:** {len(eventi)}")
    L.append(f"- **Finestre IP/tempo analizzate:** {len(feat)} (finestre da {pacchetto['finestra_min']} minuti)")
    L.append(f"- **Finestre anomale:** {n_anom} (soglia punteggio {args.soglia}, "
             f"almeno {args.min_eventi} eventi sospetti per finestra)")
    L.append(f"- **Modello:** Isolation Forest addestrato su {pacchetto['periodo'][0]} – {pacchetto['periodo'][1]}\n")

    L.append("## Sintesi\n")
    if not sospetti:
        L.append("Nessun comportamento anomalo rilevato. Non sono necessarie azioni.\n")
    else:
        critici = [s for s in sospetti if s["gravita"] == "CRITICA"]
        L.append(f"Rilevati **{len(sospetti)} IP sospetti**. "
                 + (f"**{len(critici)} con accesso riuscito dopo tentativi falliti: possibile compromissione.**"
                    if critici else "Nessun accesso riuscito da IP sospetti.") + "\n")
        L.append("| Gravità | IP | Prima attività | Ultima attività | Falliti | Utenti provati | Accessi riusciti | Punteggio |")
        L.append("| --- | --- | --- | --- | --- | --- | --- | --- |")
        for s in sospetti:
            L.append(f"| {s['gravita']} | `{s['ip']}` | {s['inizio']:%d/%m %H:%M:%S} | {s['fine']:%d/%m %H:%M:%S} "
                     f"| {s['tentativi_falliti']} | {s['utenti_distinti']} | {s['accessi_riusciti']} | {s['punteggio']:.3f} |")
        L.append("\n*Punteggio: più è negativo, più il comportamento è lontano dalla normalità.*\n")

        L.append("## Dettaglio per IP\n")
        for s in sospetti:
            L.append(f"### {s['ip']} – gravità {s['gravita']}\n")
            L.append("**Perché è anomalo:**\n")
            for m in s["motivi"]:
                L.append(f"- {m}")
            utenti = (", ".join(f"{u} ({n})" for u, n in s["top_utenti"])
                      or "nessuno: connessioni chiuse prima del login (probabile scansione)")
            L.append(f"\n**Utenti provati (i più frequenti):** {utenti}\n")
            if s["riusciti"]:
                L.append("**Accessi riusciti da questo IP:**\n")
                for r in s["riusciti"]:
                    L.append(f"- {r}")
                L.append("")

    L.append("## Azioni consigliate\n")
    if sospetti:
        L.append("1. Bloccare subito gli IP sospetti con lo script `blocca_ip.sh` generato insieme a questo report.")
        if any(s["gravita"] == "CRITICA" for s in sospetti):
            L.append("2. **Per gli IP con accesso riuscito:** cambiare subito la password o revocare la chiave/certificato "
                     "dell'utente coinvolto, controllare `last`, `~/.bash_history`, crontab e processi attivi.")
        L.append("3. Verificare che `PasswordAuthentication no` sia attivo in `/etc/ssh/sshd_config` "
                 "e usare solo chiavi o certificati SSH.")
        L.append("4. Valutare fail2ban o un limite di connessioni sul firewall "
                 "(`iptables -m recent` o `-m hashlimit`) per la porta 22.")
        L.append("5. Consentire SSH solo dalla VPN o da IP di gestione noti.")
    else:
        L.append("- Continuare il monitoraggio periodico.")
    Path(percorso).write_text("\n".join(L) + "\n", encoding="utf-8")


def scrivi_script_blocco(percorso, ips):
    righe = [
        "#!/bin/bash",
        "# Script generato da SSH Anomaly Detector: blocca gli IP sospetti.",
        "# Su questo server:   sudo bash blocca_ip.sh",
        "# Sul firewall (VM con iptables) usa invece le regole FORWARD commentate.",
        "set -e",
    ]
    for ip in ips:
        righe.append(f"iptables -C INPUT -s {ip} -p tcp --dport 22 -j DROP 2>/dev/null || "
                     f"iptables -I INPUT -s {ip} -p tcp --dport 22 -j DROP")
        righe.append(f"# iptables -I FORWARD -s {ip} -j DROP")
    righe.append('echo "IP bloccati: ' + " ".join(ips) + '"')
    Path(percorso).write_text("\n".join(righe) + "\n", encoding="utf-8")
    Path(percorso).chmod(0o755)


def grafico(percorso, eventi, sospetti):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    import matplotlib.dates as mdates

    # Una riga per IP: i pallini sono i tentativi falliti al minuto (più grandi = più tentativi),
    # i triangoli verdi gli accessi riusciti. Rosso = IP segnalato dal modello.
    ip_sosp = [s["ip"] for s in sospetti]
    altri = [ip for ip in eventi["ip"].value_counts().index if ip not in ip_sosp]
    ordine_ip = ip_sosp + altri
    fig, ax = plt.subplots(figsize=(11, 1.2 + 0.45 * len(ordine_ip)))
    neg = eventi[eventi["tipo"].isin(["fallito", "preauth"])].copy()
    neg["minuto"] = neg["ts"].dt.floor("1min")
    conteggi = neg.groupby(["ip", "minuto"]).size().reset_index(name="n")
    for ip in ordine_ip:
        y = len(ordine_ip) - 1 - ordine_ip.index(ip)
        c = conteggi[conteggi["ip"] == ip]
        ax.scatter(c["minuto"], [y] * len(c), s=np.clip(12 + 3 * c["n"], 12, 600),
                   color="#E45756" if ip in ip_sosp else "#9AA5B1", alpha=0.6, linewidths=0)
        ok = eventi[(eventi["ip"] == ip) & (eventi["tipo"] == "riuscito")]
        ax.scatter(ok["ts"], [y] * len(ok), marker="^", s=40, color="#2E9E5B", zorder=3)
    ax.set_yticks(range(len(ordine_ip)))
    ax.set_yticklabels([f"{ip}  (SOSPETTO)" if ip in ip_sosp else ip for ip in reversed(ordine_ip)])
    for lbl in ax.get_yticklabels():
        if "SOSPETTO" in lbl.get_text():
            lbl.set_color("#C0392B")
    ax.set_ylim(-0.6, len(ordine_ip) - 0.4)
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%d/%m %H:%M"))
    ax.set_title("Attività SSH per IP – cerchi: tentativi falliti al minuto, triangoli verdi: accessi riusciti",
                 fontsize=10, loc="left")
    ax.grid(axis="x", alpha=0.2)
    ax.spines[["top", "right", "left"]].set_visible(False)
    ax.tick_params(axis="y", length=0)
    fig.autofmt_xdate()
    fig.tight_layout()
    fig.savefig(percorso, dpi=150)
    plt.close(fig)


def analizza(args):
    if not Path(args.modello).exists():
        sys.exit(f"Modello {args.modello} non trovato. Esegui prima: python3 detector.py addestra --log <log_normale>")
    pacchetto = joblib.load(args.modello)
    eventi = parse_log(args.log, args.anno)
    if eventi.empty:
        sys.exit(f"Nessun evento SSH trovato in {args.log}.")

    feat = calcola_feature(eventi, pacchetto["finestra_min"])
    feat["punteggio"] = pacchetto["modello"].decision_function(matrice(feat)).round(4)
    # Il modello dice QUANTO una finestra è insolita; il filtro anti-rumore evita
    # di segnalare un utente che ha solo sbagliato password una volta.
    feat["eventi_sospetti"] = feat["tentativi_falliti"] + feat["utenti_inesistenti"] + feat["chiusure_preauth"]
    feat["anomala"] = (feat["punteggio"] < args.soglia) & (feat["eventi_sospetti"] >= args.min_eventi)

    whitelist = set(args.whitelist or [])
    sospetti = []
    for ip, g in feat[feat["anomala"]].groupby("ip"):
        if ip in whitelist:
            continue
        ev_ip = eventi[eventi["ip"] == ip]
        somma = g[["tentativi_falliti", "utenti_inesistenti", "accessi_riusciti"]].sum()
        peggiore = g.loc[g["punteggio"].idxmin()]
        motivi = []
        for _, riga in g.sort_values("punteggio").iterrows():
            for m in motivazioni(riga, pacchetto):
                if m not in motivi:
                    motivi.append(m)
        info = {
            "ip": ip,
            "inizio": ev_ip["ts"].min(),
            "fine": ev_ip["ts"].max(),
            "tentativi_falliti": int(somma["tentativi_falliti"]),
            "utenti_inesistenti": int(somma["utenti_inesistenti"]),
            "accessi_riusciti": int(somma["accessi_riusciti"]),
            "utenti_distinti": ev_ip.loc[ev_ip["utente"] != "-", "utente"].nunique(),
            "punteggio": float(peggiore["punteggio"]),
            "motivi": motivi[:6],
            # "Invalid user X" e "Failed password for invalid user X" sono lo stesso tentativo:
            # contiamo solo le righe "Failed" (o le altre, se non ce ne sono)
            "top_utenti": Counter(
                (ev_ip.loc[ev_ip["tipo"] == "fallito", "utente"] if somma["tentativi_falliti"]
                 else ev_ip.loc[(ev_ip["tipo"] != "riuscito") & (ev_ip["utente"] != "-"), "utente"])
            ).most_common(10),
            "riusciti": [f"{r.ts:%d/%m %H:%M:%S} utente **{r.utente}** con {r.metodo}"
                         for r in ev_ip[ev_ip["tipo"] == "riuscito"].itertuples()],
        }
        info["gravita"] = gravita(info)
        sospetti.append(info)
    ordine = {"CRITICA": 0, "ALTA": 1, "MEDIA": 2}
    sospetti.sort(key=lambda s: (ordine[s["gravita"]], s["punteggio"]))

    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report = out / f"incident_report_{stamp}.md"
    scrivi_report(report, args, pacchetto, eventi, feat, sospetti)
    feat.to_csv(out / f"finestre_{stamp}.csv", index=False)

    # Riepilogo a terminale
    print(f"Eventi analizzati: {len(eventi)}  |  finestre: {len(feat)}  |  anomale: {int(feat['anomala'].sum())}")
    if sospetti:
        print("\nIP SOSPETTI:")
        for s in sospetti:
            print(f"  [{s['gravita']:7}] {s['ip']:<16} falliti={s['tentativi_falliti']:<5} "
                  f"utenti={s['utenti_distinti']:<3} riusciti={s['accessi_riusciti']}  punteggio={s['punteggio']:.3f}")
        script = out / "blocca_ip.sh"
        scrivi_script_blocco(script, [s["ip"] for s in sospetti])
        print(f"\nScript di blocco: {script}")
    else:
        print("\nNessun IP sospetto.")
    print(f"Report: {report}")

    if args.grafico:
        png = out / f"grafico_{stamp}.png"
        grafico(png, eventi, sospetti)
        print(f"Grafico: {png}")

    if args.applica and sospetti:
        print("\nApplico il blocco con iptables (servono i permessi di root)...")
        subprocess.run(["bash", str(out / "blocca_ip.sh")], check=False)

    if args.json:
        print(json.dumps([{k: str(v) if isinstance(v, (pd.Timestamp, datetime)) else v
                           for k, v in s.items()} for s in sospetti], ensure_ascii=False, indent=2))


# --------------------------------------------------------------------------
# 5. COMANDI
# --------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(description="Rileva accessi SSH anomali con Isolation Forest.")
    sub = p.add_subparsers(dest="comando", required=True)

    a = sub.add_parser("addestra", help="Addestra il modello su un log senza attacchi")
    a.add_argument("--log", required=True, help="File auth.log con traffico normale")
    a.add_argument("--modello", default="modello/modello.joblib")
    a.add_argument("--finestra", type=int, default=5, help="Durata finestra in minuti (default 5)")
    a.add_argument("--anno", type=int, help="Anno dei log in formato syslog (default: anno corrente)")
    a.set_defaults(func=addestra)

    z = sub.add_parser("analizza", help="Analizza un log e genera il report")
    z.add_argument("--log", required=True, help="File auth.log da analizzare")
    z.add_argument("--modello", default="modello/modello.joblib")
    z.add_argument("--output", default="report", help="Cartella di output (default: report)")
    z.add_argument("--soglia", type=float, default=0.0,
                   help="Soglia del punteggio: sotto questo valore la finestra è anomala (default 0)")
    z.add_argument("--min-eventi", type=int, default=3,
                   help="Filtro anti-rumore: eventi sospetti minimi in una finestra per segnalarla (default 3)")
    z.add_argument("--whitelist", nargs="*", help="IP da non segnalare mai (es. il PC di amministrazione)")
    z.add_argument("--grafico", action="store_true", help="Crea anche un grafico PNG")
    z.add_argument("--applica", action="store_true", help="Applica subito il blocco iptables (root)")
    z.add_argument("--json", action="store_true", help="Stampa gli IP sospetti anche in JSON")
    z.add_argument("--anno", type=int, help="Anno dei log in formato syslog (default: anno corrente)")
    z.set_defaults(func=analizza)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
