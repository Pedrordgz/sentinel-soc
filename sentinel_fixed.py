#!/usr/bin/env python3
"""
SENTINEL SOC — Sistema de Monitorización y Defensa en Red
Versión: 1.0.0
Autor  : Pedro Rodríguez Amaro
Centro : Colegio Lagomar — DAM 2024/2025

Producto comercial: ejecutable multiplataforma para PYMEs.
Este es el punto de entrada principal del producto.
"""

import sys
import os
import socket
import threading
import json
import time
import datetime
import subprocess
import webbrowser
import logging
import argparse
import configparser
from pathlib import Path
from logging.handlers import RotatingFileHandler

# ─── DETECCIÓN DE PLATAFORMA ──────────────────────────────────────────────────
IS_WINDOWS = sys.platform.startswith("win")
IS_LINUX   = sys.platform.startswith("linux")
IS_MAC     = sys.platform.startswith("darwin")

# ─── RUTAS DEL PRODUCTO ───────────────────────────────────────────────────────
if getattr(sys, "frozen", False):
    # Ejecutable compilado con PyInstaller
    BASE_DIR = Path(sys.executable).parent
else:
    BASE_DIR = Path(__file__).parent

CONFIG_FILE = BASE_DIR / "sentinel.cfg"
LOG_DIR     = BASE_DIR / "logs"
LOG_FILE    = LOG_DIR / "sentinel.log"

LOG_DIR.mkdir(exist_ok=True)

# ─── CONFIGURACIÓN POR DEFECTO ────────────────────────────────────────────────
DEFAULT_CONFIG = {
    "sentinel": {
        "api_key":        "",
        "honeypot_ports": "21,22,80",
        "risk_window_ms": "5000",
        "risk_threshold": "3",
        "web_port":       "7777",
        "orchestrator_port": "9999",
        "mitigation_port":   "8888",
        "auto_block":     "true",
        "tts_enabled":    "false",
    }
}

# ─── LOGGER ───────────────────────────────────────────────────────────────────
def setup_logger():
    logger = logging.getLogger("sentinel")
    logger.setLevel(logging.DEBUG)
    fmt = logging.Formatter("%(asctime)s | %(levelname)-8s | %(message)s", "%Y-%m-%dT%H:%M:%S")
    fh = RotatingFileHandler(LOG_FILE, maxBytes=10*1024*1024, backupCount=5, encoding="utf-8")
    fh.setFormatter(fmt)
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    sh.setLevel(logging.INFO)
    logger.addHandler(fh)
    logger.addHandler(sh)
    return logger

logger = setup_logger()

# ─── ESTADO GLOBAL ────────────────────────────────────────────────────────────
state = {
    "events":        [],
    "ip_timestamps": {},
    "blocked_ips":   set(),
    "total_hits":    0,
    "total_threats": 0,
    "total_blocked": 0,
    "last_ai":       None,
    "lock":          threading.Lock(),
    "config":        {},
}

# ─── CARGA DE CONFIGURACIÓN ───────────────────────────────────────────────────
def load_config():
    cfg = configparser.ConfigParser()
    if CONFIG_FILE.exists():
        cfg.read(CONFIG_FILE, encoding="utf-8")
    else:
        cfg.read_dict(DEFAULT_CONFIG)
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            cfg.write(f)
        logger.info("Fichero de configuración creado: %s", CONFIG_FILE)

    s = cfg["sentinel"] if "sentinel" in cfg else DEFAULT_CONFIG["sentinel"]
    state["config"] = {
        "api_key":           s.get("api_key", ""),
        "honeypot_ports":    [int(p.strip()) for p in s.get("honeypot_ports", "21,22,80").split(",")],
        "risk_window_ms":    int(s.get("risk_window_ms", "5000")),
        "risk_threshold":    int(s.get("risk_threshold", "3")),
        "web_port":          int(s.get("web_port", "7777")),
        "orchestrator_port": int(s.get("orchestrator_port", "9999")),
        "mitigation_port":   int(s.get("mitigation_port", "8888")),
        "auto_block":        s.get("auto_block", "true").lower() == "true",
    }
    return state["config"]

# ─── BANNERS DEL HONEYPOT ─────────────────────────────────────────────────────
BANNERS = {
    21: b"220 ProFTPD 1.3.6 Server (Debian) ready.\r\n",
    22: b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n",
    80: (b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.54 (Ubuntu)\r\n"
         b"Content-Type: text/html\r\nContent-Length: 45\r\n\r\n"
         b"<html><body><h1>It works!</h1></body></html>"),
}
SERVICE_NAMES = {21: "FTP", 22: "SSH", 80: "HTTP"}

# ─── MOTOR DE IA ─────────────────────────────────────────────────────────────
def call_ai(incident: dict) -> dict:
    api_key = state["config"].get("api_key", "").strip()
    if not api_key:
        return {"action": "BLOCK", "confidence": 95,
                "reasoning": f"Patron de reconocimiento: {incident['hits']} hits en {incident['window_ms']}ms. Bloqueo aplicado."}
    try:
        import urllib.request, urllib.error
        system_prompt = (
            "Eres el motor de analisis de un SOC. "
            "Recibes incidentes de honeypot. "
            'Responde SOLO con JSON: {"action":"BLOCK","confidence":95,"reasoning":"2 frases en espanol"}'
        )
        user_msg = f"IP={incident['ip']} Servicios={incident['services']} Hits={incident['hits']} en {incident['window_ms']}ms Riesgo=ALTO"
        body = json.dumps({"model":"claude-haiku-4-5-20251001","max_tokens":300,"system":system_prompt,"messages":[{"role":"user","content":user_msg}]},ensure_ascii=True).encode("utf-8")
        req = urllib.request.Request("https://api.anthropic.com/v1/messages",data=body,
            headers={"Content-Type":"application/json","x-api-key":api_key,"anthropic-version":"2023-06-01"},method="POST")
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            text = data["content"][0]["text"].strip()
            text = text.replace("```json","").replace("```","").strip()
            s = text.find("{"); e = text.rfind("}")+1
            if s >= 0 and e > s: text = text[s:e]
            return json.loads(text)
    except urllib.error.HTTPError as e:
        body_err = e.read().decode("utf-8", errors="replace")
        logger.warning("API HTTP %d: %s", e.code, body_err[:300])
    except Exception as e:
        logger.warning("API no disponible: %s", e)

def evaluate_risk(source_ip: str) -> str:
    now_ms = time.time() * 1000
    cfg    = state["config"]
    window = cfg["risk_window_ms"]
    thresh = cfg["risk_threshold"]

    with state["lock"]:
        times = state["ip_timestamps"].setdefault(source_ip, [])
        times[:] = [t for t in times if (now_ms - t) <= window]
        times.append(now_ms)
        count = len(times)

    if count >= thresh:   return "HIGH"
    elif count >= 2:      return "MEDIUM"
    return "LOW"

# ─── BLOQUEO DE IP ────────────────────────────────────────────────────────────
def block_ip(target_ip: str, reason: str) -> bool:
    try:
        if IS_WINDOWS:
            rule = f"SENTINEL_BLOCK_{target_ip.replace('.','_')}"
            cmd = ["netsh", "advfirewall", "firewall", "add", "rule",
                   f"name={rule}", "dir=in", "action=block",
                   f"remoteip={target_ip}", "enable=yes", "profile=any"]
        else:
            cmd = ["iptables", "-I", "INPUT", "-s", target_ip, "-j", "DROP"]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            logger.info("BLOQUEADO | IP=%s | %s", target_ip, reason[:60])
            return True
        else:
            logger.warning("Error bloqueando %s: %s", target_ip, result.stderr.strip())
            return False
    except FileNotFoundError:
        logger.warning("Comando de firewall no encontrado. Bloqueo registrado pero no aplicado.")
        return False
    except Exception as e:
        logger.error("Error bloqueando IP %s: %s", target_ip, e)
        return False

# ─── GESTIÓN DE RIESGO ALTO ───────────────────────────────────────────────────
def handle_high_risk(source_ip: str, ports: list, services: list):
    with state["lock"]:
        if source_ip in state["blocked_ips"]:
            return
        hits = len(state["ip_timestamps"].get(source_ip, []))

    logger.warning("🚨 RIESGO ALTO | IP=%s | %d hits | puertos=%s", source_ip, hits, ports)

    incident = {
        "ip":        source_ip,
        "ports":     ports,
        "services":  ",".join(services),
        "hits":      hits,
        "window_ms": state["config"]["risk_window_ms"],
    }

    logger.info("Consultando motor de IA...")
    ai_result = call_ai(incident)
    action    = ai_result.get("action", "BLOCK").upper()
    reasoning = ai_result.get("reasoning", "")
    confidence= ai_result.get("confidence", 90)

    logger.info("IA decide: %s (%d%%) — %s", action, confidence, reasoning)

    with state["lock"]:
        state["total_threats"] += 1
        state["last_ai"] = {
            "action":    action,
            "confidence": confidence,
            "reasoning": reasoning,
            "ip":        source_ip,
            "ts":        datetime.datetime.now().isoformat(),
        }
        state["events"].append({
            "level": "AI",
            "msg":   f"IA decide: {action} ({confidence}%)",
            "detail": reasoning[:100],
            "ts":    datetime.datetime.now().strftime("%H:%M:%S"),
        })

    if action == "BLOCK" and state["config"]["auto_block"]:
        with state["lock"]:
            state["blocked_ips"].add(source_ip)
            state["total_blocked"] += 1
        block_ip(source_ip, reasoning)

        with state["lock"]:
            state["events"].append({
                "level": "BLOCK",
                "msg":   f"IP {source_ip} BLOQUEADA",
                "detail": f"iptables DROP · {reasoning[:60]}",
                "ts":    datetime.datetime.now().strftime("%H:%M:%S"),
            })

# ─── HONEYPOT ─────────────────────────────────────────────────────────────────
def handle_honeypot_conn(conn: socket.socket, addr: tuple, port: int):
    source_ip, source_port = addr
    with state["lock"]:
        if source_ip in state["blocked_ips"]:
            conn.close()
            return
        state["total_hits"] += 1

    service = SERVICE_NAMES.get(port, str(port))
    banner  = BANNERS.get(port, b"Connected.\r\n")
    ts      = datetime.datetime.now().strftime("%H:%M:%S")

    try:
        conn.settimeout(3)
        conn.sendall(banner)
        try:
            conn.recv(256)
        except socket.timeout:
            pass
    except OSError:
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass

    logger.info("🍯 HIT | %s:%d → puerto %d (%s)", source_ip, source_port, port, service)

    with state["lock"]:
        state["events"].append({
            "level": "HIT",
            "msg":   f"Honeypot {service} (:{port}) — {source_ip}",
            "detail": f"banner enviado · TCP handshake completado",
            "ts":    ts,
        })
        if len(state["events"]) > 200:
            state["events"].pop(0)

    risk = evaluate_risk(source_ip)

    if risk == "HIGH":
        ports_hit = list({p for p in [21, 22, 80] if any(
            e.get("msg", "").find(source_ip) != -1 for e in state["events"][-20:]
        )} | {port})
        svcs = [SERVICE_NAMES.get(p, str(p)) for p in ports_hit]
        threading.Thread(
            target=handle_high_risk,
            args=(source_ip, ports_hit, svcs),
            daemon=True
        ).start()

def run_honeypot_listener(port: int):
    # En Windows sin admin, usar puertos alternativos
    actual_port = port
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", port))
        srv.listen(50)
        logger.info("Honeypot %s activo en puerto %d", SERVICE_NAMES.get(port, str(port)), port)
    except PermissionError:
        actual_port = port + 2000
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("0.0.0.0", actual_port))
            srv.listen(50)
            logger.warning("Puerto %d sin permisos → usando %d", port, actual_port)
        except OSError as e:
            logger.error("No se puede abrir puerto %d ni %d: %s", port, actual_port, e)
            return
    except OSError as e:
        logger.error("Puerto %d no disponible: %s", port, e)
        return

    while True:
        try:
            conn, addr = srv.accept()
            threading.Thread(
                target=handle_honeypot_conn,
                args=(conn, addr, port),
                daemon=True
            ).start()
        except OSError:
            break

# ─── PANEL WEB SOC ────────────────────────────────────────────────────────────
# HTML embebido en base64 - sin problemas de codificacion
import base64 as _b64
_HTML_B64 = "PCFET0NUWVBFIGh0bWw+CjxodG1sPgo8aGVhZD4KPG1ldGEgY2hhcnNldD0idXRmLTgiPgo8dGl0bGU+U0VOVElORUwgU09DIOKAlCBQZWRybyBSb2Ryw61ndWV6IEFtYXJvPC90aXRsZT4KPGxpbmsgaHJlZj0iaHR0cHM6Ly9mb250cy5nb29nbGVhcGlzLmNvbS9jc3MyP2ZhbWlseT1TaGFyZStUZWNoK01vbm8mZmFtaWx5PVJhamRoYW5pOndnaHRANTAwOzcwMCZkaXNwbGF5PXN3YXAiIHJlbD0ic3R5bGVzaGVldCI+CjxzdHlsZT4KKnttYXJnaW46MDtwYWRkaW5nOjA7Ym94LXNpemluZzpib3JkZXItYm94O30KOnJvb3R7CiAgLS1iZzojMDIwRDFBOy0tYmcyOiMwNDE2Mjg7LS1iZzM6IzA3MUUzNjsKICAtLWN5YW46IzAwRDRGRjstLWdyZWVuOiMwMEZGOUM7LS1yZWQ6I0ZGM0I1QzstLW9yYW5nZTojRkY4QzQyOy0teWVsbG93OiNGRkQxNjY7CiAgLS1tdXRlZDojNEE3RkE1Oy0tc2lsdmVyOiM4RkI4RDQ7LS13aGl0ZTojRThGNEZGOwogIC0tY2FyZDojMDYxNTI4Oy0tYm9yZGVyOiMwQTI1NDA7Cn0KYm9keXtiYWNrZ3JvdW5kOnZhcigtLWJnKTtjb2xvcjp2YXIoLS13aGl0ZSk7Zm9udC1mYW1pbHk6J1JhamRoYW5pJyxzYW5zLXNlcmlmO292ZXJmbG93OmhpZGRlbjtoZWlnaHQ6MTAwdmg7fQoubW9ub3tmb250LWZhbWlseTonU2hhcmUgVGVjaCBNb25vJyxtb25vc3BhY2U7fQpib2R5OjphZnRlcntjb250ZW50OicnO3Bvc2l0aW9uOmZpeGVkO2luc2V0OjA7YmFja2dyb3VuZDpyZXBlYXRpbmctbGluZWFyLWdyYWRpZW50KDBkZWcsdHJhbnNwYXJlbnQsdHJhbnNwYXJlbnQgM3B4LHJnYmEoMCwyMTIsMjU1LDAuMDEyKSAzcHgscmdiYSgwLDIxMiwyNTUsMC4wMTIpIDRweCk7cG9pbnRlci1ldmVudHM6bm9uZTt6LWluZGV4Ojk5OTg7fQoKLyogVE9QIEJBUiAqLwojdG9wYmFye2hlaWdodDo0NnB4O2JhY2tncm91bmQ6dmFyKC0tYmcyKTtib3JkZXItYm90dG9tOjJweCBzb2xpZCB2YXIoLS1jeWFuKTtkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2p1c3RpZnktY29udGVudDpzcGFjZS1iZXR3ZWVuO3BhZGRpbmc6MCAxNnB4O3Bvc2l0aW9uOnJlbGF0aXZlO3otaW5kZXg6MTA7fQoubG9nby1hcmVhe2Rpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7Z2FwOjEwcHg7fQouc2hpZWxke3dpZHRoOjI4cHg7aGVpZ2h0OjI4cHg7fQouc3lzLXRpdGxle2ZvbnQtc2l6ZToxN3B4O2ZvbnQtd2VpZ2h0OjcwMDtsZXR0ZXItc3BhY2luZzo0cHg7Y29sb3I6dmFyKC0tY3lhbik7fQouc3lzLXN1Yntmb250LXNpemU6OXB4O2NvbG9yOnZhcigtLW11dGVkKTtsZXR0ZXItc3BhY2luZzoycHg7bWFyZ2luLXRvcDoxcHg7fQoudG9wLXJpZ2h0e2Rpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7Z2FwOjIwcHg7fQouc3RhdHVzLXBpbGx7ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtnYXA6NnB4O2ZvbnQtc2l6ZToxMHB4O2xldHRlci1zcGFjaW5nOjJweDtjb2xvcjp2YXIoLS1ncmVlbik7fQoucHVsc2V7d2lkdGg6N3B4O2hlaWdodDo3cHg7Ym9yZGVyLXJhZGl1czo1MCU7YmFja2dyb3VuZDp2YXIoLS1ncmVlbik7YW5pbWF0aW9uOnB1bHNlIDJzIGluZmluaXRlO30KQGtleWZyYW1lcyBwdWxzZXswJSwxMDAle29wYWNpdHk6MTtib3gtc2hhZG93OjAgMCAwIDAgcmdiYSgwLDI1NSwxNTYsLjQpfTUwJXtvcGFjaXR5Oi42O2JveC1zaGFkb3c6MCAwIDAgNHB4IHJnYmEoMCwyNTUsMTU2LDApfX0KI2Nsb2Nre2ZvbnQtZmFtaWx5OidTaGFyZSBUZWNoIE1vbm8nLG1vbm9zcGFjZTtmb250LXNpemU6MTNweDtjb2xvcjp2YXIoLS1jeWFuKTt9CgovKiBNQUlOIEdSSUQgKi8KI2dyaWR7ZGlzcGxheTpncmlkO2dyaWQtdGVtcGxhdGUtY29sdW1uczoyMzBweCAxZnIgMjcwcHg7aGVpZ2h0OmNhbGMoMTAwdmggLSA0NnB4IC0gMjhweCk7fQoKLyogTEVGVCAqLwojbGVmdHtiYWNrZ3JvdW5kOnZhcigtLWNhcmQpO2JvcmRlci1yaWdodDoxcHggc29saWQgdmFyKC0tYm9yZGVyKTtkaXNwbGF5OmZsZXg7ZmxleC1kaXJlY3Rpb246Y29sdW1uO292ZXJmbG93OmhpZGRlbjt9Ci5wYW5lbC1oZHJ7cGFkZGluZzoxMHB4IDEycHggNnB4O2ZvbnQtc2l6ZTo4cHg7bGV0dGVyLXNwYWNpbmc6M3B4O2NvbG9yOnZhcigtLW11dGVkKTtmb250LXdlaWdodDo3MDA7Ym9yZGVyLWJvdHRvbToxcHggc29saWQgdmFyKC0tYm9yZGVyKTt9Ci5hZ2VudHtkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2dhcDo4cHg7cGFkZGluZzo4cHggMTJweDtib3JkZXItYm90dG9tOjFweCBzb2xpZCByZ2JhKDEwLDM3LDY0LC41KTt0cmFuc2l0aW9uOmJhY2tncm91bmQgLjJzO30KLmFnaXt3aWR0aDozMHB4O2hlaWdodDozMHB4O2JvcmRlci1yYWRpdXM6NHB4O2Rpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7anVzdGlmeS1jb250ZW50OmNlbnRlcjtmb250LXNpemU6MTVweDtmbGV4LXNocmluazowO30KLmFnbntmb250LXNpemU6MTFweDtmb250LXdlaWdodDo3MDA7bGV0dGVyLXNwYWNpbmc6MXB4O2NvbG9yOnZhcigtLXdoaXRlKTt9Ci5hZ2lwe2ZvbnQtc2l6ZTo5cHg7Y29sb3I6dmFyKC0tbXV0ZWQpO2ZvbnQtZmFtaWx5OidTaGFyZSBUZWNoIE1vbm8nLG1vbm9zcGFjZTt9Ci5iYWRnZXtmb250LXNpemU6OHB4O2ZvbnQtd2VpZ2h0OjcwMDtsZXR0ZXItc3BhY2luZzoxcHg7cGFkZGluZzoxcHggNXB4O2JvcmRlci1yYWRpdXM6MnB4O30KLmItb2t7YmFja2dyb3VuZDpyZ2JhKDAsMjU1LDE1NiwuMTIpO2NvbG9yOnZhcigtLWdyZWVuKTtib3JkZXI6MXB4IHNvbGlkIHJnYmEoMCwyNTUsMTU2LC4yNSk7fQouYi1hbGVydHtiYWNrZ3JvdW5kOnJnYmEoMjU1LDU5LDkyLC4xNSk7Y29sb3I6dmFyKC0tcmVkKTtib3JkZXI6MXB4IHNvbGlkIHJnYmEoMjU1LDU5LDkyLC4zKTthbmltYXRpb246YmEgLjZzIGluZmluaXRlIGFsdGVybmF0ZTt9CkBrZXlmcmFtZXMgYmF7ZnJvbXtvcGFjaXR5OjF9dG97b3BhY2l0eTouM319CiNyaXNrLXNlY3twYWRkaW5nOjEwcHggMTJweDt9Ci5yYi1iZ3toZWlnaHQ6NXB4O2JhY2tncm91bmQ6dmFyKC0tYm9yZGVyKTtib3JkZXItcmFkaXVzOjNweDtvdmVyZmxvdzpoaWRkZW47bWFyZ2luOjZweCAwIDNweDt9Ci5yYi1maWxse2hlaWdodDoxMDAlO2JvcmRlci1yYWRpdXM6M3B4O3RyYW5zaXRpb246d2lkdGggLjhzLGJhY2tncm91bmQgLjhzO3dpZHRoOjUlO2JhY2tncm91bmQ6dmFyKC0tZ3JlZW4pO30KLnJse2Rpc3BsYXk6ZmxleDtqdXN0aWZ5LWNvbnRlbnQ6c3BhY2UtYmV0d2Vlbjtmb250LXNpemU6OHB4O2NvbG9yOnZhcigtLW11dGVkKTtsZXR0ZXItc3BhY2luZzoxcHg7fQojYmxrLXNlY3twYWRkaW5nOjhweCAxMnB4O2ZsZXg6MTtvdmVyZmxvdy15OmF1dG87fQouYmxrLWlwe2ZvbnQtZmFtaWx5OidTaGFyZSBUZWNoIE1vbm8nLG1vbm9zcGFjZTtmb250LXNpemU6OXB4O2NvbG9yOnZhcigtLXJlZCk7cGFkZGluZzozcHggNnB4O2JhY2tncm91bmQ6cmdiYSgyNTUsNTksOTIsLjA3KTtib3JkZXI6MXB4IHNvbGlkIHJnYmEoMjU1LDU5LDkyLC4yKTtib3JkZXItcmFkaXVzOjJweDttYXJnaW4tYm90dG9tOjNweDtkaXNwbGF5OmZsZXg7anVzdGlmeS1jb250ZW50OnNwYWNlLWJldHdlZW47fQojbWV0cmljc3tkaXNwbGF5OmdyaWQ7Z3JpZC10ZW1wbGF0ZS1jb2x1bW5zOjFmciAxZnI7Z2FwOjFweDtiYWNrZ3JvdW5kOnZhcigtLWJvcmRlcik7Ym9yZGVyLXRvcDoxcHggc29saWQgdmFyKC0tYm9yZGVyKTt9Ci5tZXRyaWN7YmFja2dyb3VuZDp2YXIoLS1jYXJkKTtwYWRkaW5nOjhweCAxMHB4O30KLm12e2ZvbnQtc2l6ZToyNnB4O2ZvbnQtd2VpZ2h0OjcwMDtmb250LWZhbWlseTonU2hhcmUgVGVjaCBNb25vJyxtb25vc3BhY2U7bGluZS1oZWlnaHQ6MTt9Ci5tbHtmb250LXNpemU6OHB4O2NvbG9yOnZhcigtLW11dGVkKTtsZXR0ZXItc3BhY2luZzoxcHg7bWFyZ2luLXRvcDozcHg7fQoKLyogQ0VOVEVSICovCiNjZW50ZXJ7ZGlzcGxheTpmbGV4O2ZsZXgtZGlyZWN0aW9uOmNvbHVtbjtib3JkZXItcmlnaHQ6MXB4IHNvbGlkIHZhcigtLWJvcmRlcik7fQojbWFwe2ZsZXg6MCAwIDIyMHB4O2JvcmRlci1ib3R0b206MXB4IHNvbGlkIHZhcigtLWJvcmRlcik7cG9zaXRpb246cmVsYXRpdmU7b3ZlcmZsb3c6aGlkZGVuO30KI25ldC1zdmd7d2lkdGg6MTAwJTtoZWlnaHQ6MTAwJTt9CiNsb2d3cmFwe2ZsZXg6MTtvdmVyZmxvdzpoaWRkZW47ZGlzcGxheTpmbGV4O2ZsZXgtZGlyZWN0aW9uOmNvbHVtbjt9CiNsb2doZHJ7cGFkZGluZzo4cHggMTRweCA1cHg7Zm9udC1zaXplOjhweDtsZXR0ZXItc3BhY2luZzozcHg7Y29sb3I6dmFyKC0tbXV0ZWQpO2ZvbnQtd2VpZ2h0OjcwMDtib3JkZXItYm90dG9tOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpO2Rpc3BsYXk6ZmxleDtqdXN0aWZ5LWNvbnRlbnQ6c3BhY2UtYmV0d2VlbjthbGlnbi1pdGVtczpjZW50ZXI7fQojbG9ne2ZsZXg6MTtvdmVyZmxvdy15OmF1dG87cGFkZGluZzowO30KI2xvZzo6LXdlYmtpdC1zY3JvbGxiYXJ7d2lkdGg6MnB4O30KI2xvZzo6LXdlYmtpdC1zY3JvbGxiYXItdGh1bWJ7YmFja2dyb3VuZDp2YXIoLS1tdXRlZCk7fQouZXZ7ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmZsZXgtc3RhcnQ7Z2FwOjhweDtwYWRkaW5nOjVweCAxMnB4O2JvcmRlci1ib3R0b206MXB4IHNvbGlkIHJnYmEoMTAsMzcsNjQsLjQpO2FuaW1hdGlvbjpldkluIC4yNXMgZWFzZTt9CkBrZXlmcmFtZXMgZXZJbntmcm9te29wYWNpdHk6MDt0cmFuc2Zvcm06dHJhbnNsYXRlWSgtNnB4KX10b3tvcGFjaXR5OjE7dHJhbnNmb3JtOm5vbmV9fQouZXYtdHtmb250LWZhbWlseTonU2hhcmUgVGVjaCBNb25vJyxtb25vc3BhY2U7Zm9udC1zaXplOjlweDtjb2xvcjp2YXIoLS1tdXRlZCk7ZmxleC1zaHJpbms6MDtwYWRkaW5nLXRvcDoycHg7bWluLXdpZHRoOjcwcHg7fQouZXYtaWN7d2lkdGg6MTZweDtoZWlnaHQ6MTZweDtib3JkZXItcmFkaXVzOjJweDtkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2p1c3RpZnktY29udGVudDpjZW50ZXI7Zm9udC1zaXplOjlweDtmbGV4LXNocmluazowO21hcmdpbi10b3A6MXB4O30KLmV2LWJvZHl7ZmxleDoxO30KLmV2LW17Zm9udC1zaXplOjExcHg7Zm9udC13ZWlnaHQ6NjAwO2xpbmUtaGVpZ2h0OjEuMzt9Ci5ldi1ze2ZvbnQtc2l6ZTo5cHg7Y29sb3I6dmFyKC0tbXV0ZWQpO2ZvbnQtZmFtaWx5OidTaGFyZSBUZWNoIE1vbm8nLG1vbm9zcGFjZTttYXJnaW4tdG9wOjFweDt9Ci50LWluZm8gLmV2LWlje2JhY2tncm91bmQ6cmdiYSgwLDIxMiwyNTUsLjEyKTtjb2xvcjp2YXIoLS1jeWFuKTt9Ci50LWhpdCAuZXYtaWN7YmFja2dyb3VuZDpyZ2JhKDI1NSwxNDAsNjYsLjEyKTtjb2xvcjp2YXIoLS1vcmFuZ2UpO30KLnQtY3JpdCAuZXYtaWN7YmFja2dyb3VuZDpyZ2JhKDI1NSw1OSw5MiwuMTgpO2NvbG9yOnZhcigtLXJlZCk7fQoudC1haSAuZXYtaWN7YmFja2dyb3VuZDpyZ2JhKDAsMjU1LDE1NiwuMTIpO2NvbG9yOnZhcigtLWdyZWVuKTt9Ci50LWJsb2NrIC5ldi1pY3tiYWNrZ3JvdW5kOnJnYmEoMjU1LDU5LDkyLC4yNSk7Y29sb3I6dmFyKC0tcmVkKTt9Ci50LXdhcm4gLmV2LWlje2JhY2tncm91bmQ6cmdiYSgyNTUsMjA5LDEwMiwuMTIpO2NvbG9yOnZhcigtLXllbGxvdyk7fQoKLyogUklHSFQgKi8KI3JpZ2h0e2Rpc3BsYXk6ZmxleDtmbGV4LWRpcmVjdGlvbjpjb2x1bW47fQojYWlib3h7ZmxleDoxO2Rpc3BsYXk6ZmxleDtmbGV4LWRpcmVjdGlvbjpjb2x1bW47b3ZlcmZsb3c6aGlkZGVuO30KI2FpaGRye3BhZGRpbmc6OHB4IDEycHggNXB4O2ZvbnQtc2l6ZTo4cHg7bGV0dGVyLXNwYWNpbmc6M3B4O2NvbG9yOnZhcigtLW11dGVkKTtmb250LXdlaWdodDo3MDA7Ym9yZGVyLWJvdHRvbToxcHggc29saWQgdmFyKC0tYm9yZGVyKTtkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2dhcDo2cHg7fQojYWktZG90e3dpZHRoOjZweDtoZWlnaHQ6NnB4O2JvcmRlci1yYWRpdXM6NTAlO2JhY2tncm91bmQ6dmFyKC0tZ3JlZW4pO2FuaW1hdGlvbjpwdWxzZSAycyBpbmZpbml0ZTt9CiNhaS1zY3JvbGx7ZmxleDoxO292ZXJmbG93LXk6YXV0bztwYWRkaW5nOjEwcHggMTJweDt9CiNhaS1zY3JvbGw6Oi13ZWJraXQtc2Nyb2xsYmFye3dpZHRoOjJweDt9CiNhaS1zY3JvbGw6Oi13ZWJraXQtc2Nyb2xsYmFyLXRodW1ie2JhY2tncm91bmQ6dmFyKC0tbXV0ZWQpO30KLmFpLWlkbGV7Zm9udC1mYW1pbHk6J1NoYXJlIFRlY2ggTW9ubycsbW9ub3NwYWNlO2ZvbnQtc2l6ZToxMHB4O2NvbG9yOnZhcigtLW11dGVkKTtsaW5lLWhlaWdodDoxLjg7fQouYWktYWN0aW9ue2ZvbnQtc2l6ZToyMHB4O2ZvbnQtd2VpZ2h0OjcwMDtsZXR0ZXItc3BhY2luZzoycHg7bWFyZ2luLWJvdHRvbTo2cHg7fQouYWktcmVhc29ue2ZvbnQtZmFtaWx5OidTaGFyZSBUZWNoIE1vbm8nLG1vbm9zcGFjZTtmb250LXNpemU6MTBweDtjb2xvcjp2YXIoLS1zaWx2ZXIpO2xpbmUtaGVpZ2h0OjEuNzt9Ci5haS1jb25me2ZvbnQtc2l6ZTo5cHg7Y29sb3I6dmFyKC0tbXV0ZWQpO21hcmdpbi10b3A6NnB4O2ZvbnQtZmFtaWx5OidTaGFyZSBUZWNoIE1vbm8nLG1vbm9zcGFjZTt9CiNjaGF0LXNlY3tib3JkZXItdG9wOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpO2Rpc3BsYXk6ZmxleDtmbGV4LWRpcmVjdGlvbjpjb2x1bW47aGVpZ2h0OjIyMHB4O30KI2NoYXQtbG9ne2ZsZXg6MTtvdmVyZmxvdy15OmF1dG87cGFkZGluZzo2cHggMTBweDt9CiNjaGF0LWxvZzo6LXdlYmtpdC1zY3JvbGxiYXJ7d2lkdGg6MnB4O30KI2NoYXQtbG9nOjotd2Via2l0LXNjcm9sbGJhci10aHVtYntiYWNrZ3JvdW5kOnZhcigtLW11dGVkKTt9Ci5jbXttYXJnaW4tYm90dG9tOjZweDtmb250LXNpemU6MTBweDtsaW5lLWhlaWdodDoxLjU7fQouY20tdXNlcntjb2xvcjp2YXIoLS1jeWFuKTtmb250LWZhbWlseTonU2hhcmUgVGVjaCBNb25vJyxtb25vc3BhY2U7fQouY20tYWl7Y29sb3I6dmFyKC0tc2lsdmVyKTtmb250LWZhbWlseTonU2hhcmUgVGVjaCBNb25vJyxtb25vc3BhY2U7fQouY20tbGFiZWx7Zm9udC1zaXplOjhweDtsZXR0ZXItc3BhY2luZzoxcHg7bWFyZ2luLWJvdHRvbToycHg7fQouY20tdXNlciAuY20tbGFiZWx7Y29sb3I6dmFyKC0tY3lhbik7fQouY20tYWkgLmNtLWxhYmVse2NvbG9yOnZhcigtLWdyZWVuKTt9CiNjaGF0LWlucHV0LXJvd3tkaXNwbGF5OmZsZXg7Z2FwOjZweDtwYWRkaW5nOjZweCAxMHB4O2JvcmRlci10b3A6MXB4IHNvbGlkIHZhcigtLWJvcmRlcik7fQojY2hhdC1pbntmbGV4OjE7YmFja2dyb3VuZDp2YXIoLS1iZzMpO2JvcmRlcjoxcHggc29saWQgdmFyKC0tYm9yZGVyKTtjb2xvcjp2YXIoLS13aGl0ZSk7Zm9udC1mYW1pbHk6J1NoYXJlIFRlY2ggTW9ubycsbW9ub3NwYWNlO2ZvbnQtc2l6ZToxMHB4O3BhZGRpbmc6NXB4IDhweDtib3JkZXItcmFkaXVzOjNweDtvdXRsaW5lOm5vbmU7fQojY2hhdC1pbjpmb2N1c3tib3JkZXItY29sb3I6dmFyKC0tY3lhbik7fQojY2hhdC1zZW5ke2JhY2tncm91bmQ6dHJhbnNwYXJlbnQ7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS1jeWFuKTtjb2xvcjp2YXIoLS1jeWFuKTtmb250LWZhbWlseTonUmFqZGhhbmknLHNhbnMtc2VyaWY7Zm9udC1zaXplOjExcHg7Zm9udC13ZWlnaHQ6NzAwO3BhZGRpbmc6NHB4IDEwcHg7Y3Vyc29yOnBvaW50ZXI7Ym9yZGVyLXJhZGl1czozcHg7bGV0dGVyLXNwYWNpbmc6MXB4O30KI2NoYXQtc2VuZDpob3ZlcntiYWNrZ3JvdW5kOnJnYmEoMCwyMTIsMjU1LC4xKTt9CiNzaW0tYmFye2JhY2tncm91bmQ6dmFyKC0tYmcyKTtib3JkZXItdG9wOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpO2hlaWdodDoyOHB4O2Rpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7anVzdGlmeS1jb250ZW50OnNwYWNlLWJldHdlZW47cGFkZGluZzowIDE2cHg7fQojc2ltLWJ0bntiYWNrZ3JvdW5kOnRyYW5zcGFyZW50O2JvcmRlcjoxcHggc29saWQgdmFyKC0tcmVkKTtjb2xvcjp2YXIoLS1yZWQpO2ZvbnQtZmFtaWx5OidSYWpkaGFuaScsc2Fucy1zZXJpZjtmb250LXNpemU6MTFweDtmb250LXdlaWdodDo3MDA7bGV0dGVyLXNwYWNpbmc6M3B4O3BhZGRpbmc6MnB4IDE2cHg7Y3Vyc29yOnBvaW50ZXI7Ym9yZGVyLXJhZGl1czoycHg7fQojc2ltLWJ0bjpob3ZlcntiYWNrZ3JvdW5kOnJnYmEoMjU1LDU5LDkyLC4xKTt9CiNzaW0tYnRuOmRpc2FibGVke29wYWNpdHk6LjM1O2N1cnNvcjpub3QtYWxsb3dlZDt9CiNzYi1pbmZve2ZvbnQtZmFtaWx5OidTaGFyZSBUZWNoIE1vbm8nLG1vbm9zcGFjZTtmb250LXNpemU6OXB4O2NvbG9yOnZhcigtLW11dGVkKTt9CiN0dHMtYnRue2JhY2tncm91bmQ6dHJhbnNwYXJlbnQ7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS1tdXRlZCk7Y29sb3I6dmFyKC0tbXV0ZWQpO2ZvbnQtZmFtaWx5OidSYWpkaGFuaScsc2Fucy1zZXJpZjtmb250LXNpemU6MTBweDtmb250LXdlaWdodDo3MDA7bGV0dGVyLXNwYWNpbmc6MnB4O3BhZGRpbmc6MnB4IDEwcHg7Y3Vyc29yOnBvaW50ZXI7Ym9yZGVyLXJhZGl1czoycHg7fQojdHRzLWJ0bi5vbntib3JkZXItY29sb3I6dmFyKC0tZ3JlZW4pO2NvbG9yOnZhcigtLWdyZWVuKTt9CgovKiBBUEkgS0VZIE1PREFMICovCiNhcGktbW9kYWx7cG9zaXRpb246Zml4ZWQ7aW5zZXQ6MDtiYWNrZ3JvdW5kOnJnYmEoMiwxMywyNiwuOTUpO3otaW5kZXg6OTk5OTtkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2p1c3RpZnktY29udGVudDpjZW50ZXI7fQojYXBpLWJveHtiYWNrZ3JvdW5kOnZhcigtLWNhcmQpO2JvcmRlcjoxcHggc29saWQgdmFyKC0tY3lhbik7Ym9yZGVyLXJhZGl1czo2cHg7cGFkZGluZzozMHB4IDM2cHg7d2lkdGg6NDIwcHg7dGV4dC1hbGlnbjpjZW50ZXI7fQojYXBpLWJveCBoMntmb250LXNpemU6MThweDtmb250LXdlaWdodDo3MDA7Y29sb3I6dmFyKC0tY3lhbik7bGV0dGVyLXNwYWNpbmc6M3B4O21hcmdpbi1ib3R0b206OHB4O30KI2FwaS1ib3ggcHtmb250LXNpemU6MTFweDtjb2xvcjp2YXIoLS1tdXRlZCk7bWFyZ2luLWJvdHRvbToyMHB4O2xpbmUtaGVpZ2h0OjEuNztmb250LWZhbWlseTonU2hhcmUgVGVjaCBNb25vJyxtb25vc3BhY2U7fQojYXBpLWlucHV0e3dpZHRoOjEwMCU7YmFja2dyb3VuZDp2YXIoLS1iZzMpO2JvcmRlcjoxcHggc29saWQgdmFyKC0tYm9yZGVyKTtjb2xvcjp2YXIoLS13aGl0ZSk7Zm9udC1mYW1pbHk6J1NoYXJlIFRlY2ggTW9ubycsbW9ub3NwYWNlO2ZvbnQtc2l6ZToxMXB4O3BhZGRpbmc6OHB4IDEwcHg7Ym9yZGVyLXJhZGl1czozcHg7b3V0bGluZTpub25lO21hcmdpbi1ib3R0b206MTBweDt9CiNhcGktaW5wdXQ6Zm9jdXN7Ym9yZGVyLWNvbG9yOnZhcigtLWN5YW4pO30KLmFwaS1idG57d2lkdGg6MTAwJTtwYWRkaW5nOjlweDtib3JkZXItcmFkaXVzOjNweDtmb250LWZhbWlseTonUmFqZGhhbmknLHNhbnMtc2VyaWY7Zm9udC1zaXplOjEzcHg7Zm9udC13ZWlnaHQ6NzAwO2xldHRlci1zcGFjaW5nOjJweDtjdXJzb3I6cG9pbnRlcjttYXJnaW4tYm90dG9tOjhweDt9Ci5hcGktYnRuLXByaW1hcnl7YmFja2dyb3VuZDp2YXIoLS1jeWFuKTtjb2xvcjp2YXIoLS1iZyk7Ym9yZGVyOm5vbmU7fQouYXBpLWJ0bi1zZWNvbmRhcnl7YmFja2dyb3VuZDp0cmFuc3BhcmVudDtib3JkZXI6MXB4IHNvbGlkIHZhcigtLW11dGVkKTtjb2xvcjp2YXIoLS1tdXRlZCk7fQo8L3N0eWxlPgo8L2hlYWQ+Cjxib2R5PgoKPCEtLSBBUEkgS0VZIE1PREFMIC0tPgo8ZGl2IGlkPSJhcGktbW9kYWwiPgogIDxkaXYgaWQ9ImFwaS1ib3giPgogICAgPGgyPlNFTlRJTkVMIFNPQzwvaDI+CiAgICA8cD5JbnRyb2R1Y2UgdHUgQW50aHJvcGljIEFQSSBLZXkgcGFyYSBhY3RpdmFyPGJyPmVsIE1vdG9yIGRlIEludGVsaWdlbmNpYSBBcnRpZmljaWFsIGVuIHRpZW1wbyByZWFsLjxicj48YnI+CiAgICBDb25zw61ndWVsYSBlbjogY29uc29sZS5hbnRocm9waWMuY29tIOKGkiBBUEkgS2V5czxicj4KICAgIEVtcGllemEgcG9yIHNrLWFudC1hcGkwMy0uLi48L3A+CiAgICA8aW5wdXQgaWQ9ImFwaS1pbnB1dCIgcGxhY2Vob2xkZXI9InNrLWFudC1hcGkwMy0uLi4iIHR5cGU9InBhc3N3b3JkIi8+CiAgICA8YnV0dG9uIGNsYXNzPSJhcGktYnRuIGFwaS1idG4tcHJpbWFyeSIgb25jbGljaz0ic3RhcnRXaXRoS2V5KCkiPkFDVElWQVIgTU9UT1IgREUgSUE8L2J1dHRvbj4KICAgIDxidXR0b24gY2xhc3M9ImFwaS1idG4gYXBpLWJ0bi1zZWNvbmRhcnkiIG9uY2xpY2s9InN0YXJ0U2ltdWxhdGVkKCkiPk1PRE8gU0lNVUxBRE8gKHNpbiBJQSByZWFsKTwvYnV0dG9uPgogIDwvZGl2Pgo8L2Rpdj4KCjwhLS0gVE9QIEJBUiAtLT4KPGRpdiBpZD0idG9wYmFyIj4KICA8ZGl2IGNsYXNzPSJsb2dvLWFyZWEiPgogICAgPHN2ZyBjbGFzcz0ic2hpZWxkIiB2aWV3Qm94PSIwIDAgMjggMjgiIGZpbGw9Im5vbmUiPgogICAgICA8cGF0aCBkPSJNMTQgMkw0IDd2OGMwIDUuNSA0LjMgMTAuNiAxMCAxMiA1LjctMS40IDEwLTYuNSAxMC0xMlY3TDE0IDJ6IiBzdHJva2U9IiMwMEQ0RkYiIHN0cm9rZS13aWR0aD0iMS41IiBmaWxsPSJyZ2JhKDAsMjEyLDI1NSwwLjA2KSIvPgogICAgICA8cGF0aCBkPSJNMTAgMTRsMyAzIDUtNSIgc3Ryb2tlPSIjMDBGRjlDIiBzdHJva2Utd2lkdGg9IjEuOCIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2UtbGluZWpvaW49InJvdW5kIi8+CiAgICA8L3N2Zz4KICAgIDxkaXY+CiAgICAgIDxkaXYgY2xhc3M9InN5cy10aXRsZSI+U0VOVElORUwgU09DPC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9InN5cy1zdWIiPlNJU1RFTUEgREUgREVGRU5TQSBFTiBSRUQg4oCUIFBFRFJPIFJPRFLDjUdVRVogQU1BUk8gwrcgREFNIDIwMjQvMjAyNTwvZGl2PgogICAgPC9kaXY+CiAgPC9kaXY+CiAgPGRpdiBjbGFzcz0idG9wLXJpZ2h0Ij4KICAgIDxkaXYgY2xhc3M9InN0YXR1cy1waWxsIj48ZGl2IGNsYXNzPSJwdWxzZSI+PC9kaXY+PHNwYW4gaWQ9InN5cy1zdGF0dXMiPlNJU1RFTUEgT1BFUkFUSVZPPC9zcGFuPjwvZGl2PgogICAgPGRpdiBpZD0iY2xvY2siIGNsYXNzPSJtb25vIj4wMDowMDowMDwvZGl2PgogIDwvZGl2Pgo8L2Rpdj4KCjxkaXYgaWQ9ImdyaWQiPgogIDwhLS0gTEVGVCAtLT4KICA8ZGl2IGlkPSJsZWZ0Ij4KICAgIDxkaXYgY2xhc3M9InBhbmVsLWhkciI+QUdFTlRFUyBFTiBSRUQ8L2Rpdj4KICAgIDxkaXYgaWQ9ImFnLWhvbmV5IiBjbGFzcz0iYWdlbnQiPgogICAgICA8ZGl2IGNsYXNzPSJhZ2kiIHN0eWxlPSJiYWNrZ3JvdW5kOnJnYmEoMjU1LDU5LDkyLC4xMik7Y29sb3I6I0ZGM0I1QzsiPvCfja88L2Rpdj4KICAgICAgPGRpdiBzdHlsZT0iZmxleDoxIj48ZGl2IGNsYXNzPSJhZ24iPkhPTkVZUE9UPC9kaXY+PGRpdiBjbGFzcz0iYWdpcCI+MTkyLjE2OC4xLjEwMDwvZGl2PjwvZGl2PgogICAgICA8c3BhbiBjbGFzcz0iYmFkZ2UgYi1vayIgaWQ9ImFnLWhvbmV5LWIiPkFDVElWTzwvc3Bhbj4KICAgIDwvZGl2PgogICAgPGRpdiBjbGFzcz0iYWdlbnQiPgogICAgICA8ZGl2IGNsYXNzPSJhZ2kiIHN0eWxlPSJiYWNrZ3JvdW5kOnJnYmEoMCwyMTIsMjU1LC4xMik7Y29sb3I6IzAwRDRGRjsiPvCflI08L2Rpdj4KICAgICAgPGRpdiBzdHlsZT0iZmxleDoxIj48ZGl2IGNsYXNzPSJhZ24iPkhVTlRFUjwvZGl2PjxkaXYgY2xhc3M9ImFnaXAiPjE5Mi4xNjguMS4xMDA8L2Rpdj48L2Rpdj4KICAgICAgPHNwYW4gY2xhc3M9ImJhZGdlIGItb2siPlNDQU48L3NwYW4+CiAgICA8L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImFnZW50Ij4KICAgICAgPGRpdiBjbGFzcz0iYWdpIiBzdHlsZT0iYmFja2dyb3VuZDpyZ2JhKDI1NSwxNDAsNjYsLjEyKTtjb2xvcjojRkY4QzQyOyI+8J+UkjwvZGl2PgogICAgICA8ZGl2IHN0eWxlPSJmbGV4OjEiPjxkaXYgY2xhc3M9ImFnbiI+SEFSREVOSU5HPC9kaXY+PGRpdiBjbGFzcz0iYWdpcCI+MTkyLjE2OC4xLjEwMDwvZGl2PjwvZGl2PgogICAgICA8c3BhbiBjbGFzcz0iYmFkZ2UgYi1vayI+QVVESVQ8L3NwYW4+CiAgICA8L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImFnZW50Ij4KICAgICAgPGRpdiBjbGFzcz0iYWdpIiBzdHlsZT0iYmFja2dyb3VuZDpyZ2JhKDAsMjU1LDE1NiwuMTIpO2NvbG9yOiMwMEZGOUM7Ij7imqE8L2Rpdj4KICAgICAgPGRpdiBzdHlsZT0iZmxleDoxIj48ZGl2IGNsYXNzPSJhZ24iPk9SUVVFU1RBRE9SPC9kaXY+PGRpdiBjbGFzcz0iYWdpcCI+MTkyLjE2OC4xLjUwOjk5OTk8L2Rpdj48L2Rpdj4KICAgICAgPHNwYW4gY2xhc3M9ImJhZGdlIGItb2siPk9OTElORTwvc3Bhbj4KICAgIDwvZGl2PgogICAgPGRpdiBjbGFzcz0iYWdlbnQiPgogICAgICA8ZGl2IGNsYXNzPSJhZ2kiIHN0eWxlPSJiYWNrZ3JvdW5kOnJnYmEoMjU1LDIwOSwxMDIsLjEyKTtjb2xvcjojRkZEMTY2OyI+8J+boe+4jzwvZGl2PgogICAgICA8ZGl2IHN0eWxlPSJmbGV4OjEiPjxkaXYgY2xhc3M9ImFnbiI+TUlUSUdBQ0nDk048L2Rpdj48ZGl2IGNsYXNzPSJhZ2lwIj4xOTIuMTY4LjEuMTAwOjg4ODg8L2Rpdj48L2Rpdj4KICAgICAgPHNwYW4gY2xhc3M9ImJhZGdlIGItb2siIGlkPSJtaXQtYmFkZ2UiPkVTUEVSQTwvc3Bhbj4KICAgIDwvZGl2PgogICAgPGRpdiBpZD0icmlzay1zZWMiPgogICAgICA8ZGl2IGNsYXNzPSJwYW5lbC1oZHIiIHN0eWxlPSJwYWRkaW5nOjhweCAwIDRweDtib3JkZXI6bm9uZTsiPk5JVkVMIERFIFJJRVNHTzwvZGl2PgogICAgICA8ZGl2IGNsYXNzPSJyYi1iZyI+PGRpdiBjbGFzcz0icmItZmlsbCIgaWQ9InJmIj48L2Rpdj48L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0icmwiPjxzcGFuPkJBSk88L3NwYW4+PHNwYW4+TUVESU88L3NwYW4+PHNwYW4+QUxUTzwvc3Bhbj48L2Rpdj4KICAgIDwvZGl2PgogICAgPGRpdiBjbGFzcz0icGFuZWwtaGRyIiBzdHlsZT0ibWFyZ2luLXRvcDo0cHg7Ij5JUHMgQkxPUVVFQURBUzwvZGl2PgogICAgPGRpdiBpZD0iYmxrLXNlYyI+PHNwYW4gc3R5bGU9ImZvbnQtc2l6ZTo5cHg7Y29sb3I6dmFyKC0tbXV0ZWQpOyI+TmluZ3VuYSB0b2RhdsOtYTwvc3Bhbj48L2Rpdj4KICAgIDxkaXYgaWQ9Im1ldHJpY3MiPgogICAgICA8ZGl2IGNsYXNzPSJtZXRyaWMiPjxkaXYgY2xhc3M9Im12IG1vbm8iIGlkPSJtMSIgc3R5bGU9ImNvbG9yOnZhcigtLWN5YW4pOyI+MDwvZGl2PjxkaXYgY2xhc3M9Im1sIj5FVkVOVE9TPC9kaXY+PC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9Im1ldHJpYyI+PGRpdiBjbGFzcz0ibXYgbW9ubyIgaWQ9Im0yIiBzdHlsZT0iY29sb3I6dmFyKC0tcmVkKTsiPjA8L2Rpdj48ZGl2IGNsYXNzPSJtbCI+QU1FTkFaQVM8L2Rpdj48L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0ibWV0cmljIj48ZGl2IGNsYXNzPSJtdiBtb25vIiBpZD0ibTMiIHN0eWxlPSJjb2xvcjp2YXIoLS1ncmVlbik7Ij4wPC9kaXY+PGRpdiBjbGFzcz0ibWwiPkJMT1FVRUFEQVM8L2Rpdj48L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0ibWV0cmljIj48ZGl2IGNsYXNzPSJtdiBtb25vIiBzdHlsZT0iY29sb3I6dmFyKC0tb3JhbmdlKTsiPjU8L2Rpdj48ZGl2IGNsYXNzPSJtbCI+QUdFTlRFUzwvZGl2PjwvZGl2PgogICAgPC9kaXY+CiAgPC9kaXY+CgogIDwhLS0gQ0VOVEVSIC0tPgogIDxkaXYgaWQ9ImNlbnRlciI+CiAgICA8ZGl2IGlkPSJtYXAiPgogICAgICA8c3ZnIGlkPSJuZXQtc3ZnIiB2aWV3Qm94PSIwIDAgNTgwIDIxNSIgcHJlc2VydmVBc3BlY3RSYXRpbz0ieE1pZFlNaWQgbWVldCI+CiAgICAgICAgPGRlZnM+CiAgICAgICAgICA8ZmlsdGVyIGlkPSJnbG93LWMiPjxmZUdhdXNzaWFuQmx1ciBzdGREZXZpYXRpb249IjMiIHJlc3VsdD0iYiIvPjxmZU1lcmdlPjxmZU1lcmdlTm9kZSBpbj0iYiIvPjxmZU1lcmdlTm9kZSBpbj0iU291cmNlR3JhcGhpYyIvPjwvZmVNZXJnZT48L2ZpbHRlcj4KICAgICAgICAgIDxmaWx0ZXIgaWQ9Imdsb3ctciI+PGZlR2F1c3NpYW5CbHVyIHN0ZERldmlhdGlvbj0iNSIgcmVzdWx0PSJiIi8+PGZlTWVyZ2U+PGZlTWVyZ2VOb2RlIGluPSJiIi8+PGZlTWVyZ2VOb2RlIGluPSJTb3VyY2VHcmFwaGljIi8+PC9mZU1lcmdlPjwvZmlsdGVyPgogICAgICAgICAgPG1hcmtlciBpZD0iYXJyIiBtYXJrZXJXaWR0aD0iNiIgbWFya2VySGVpZ2h0PSI2IiByZWZYPSI1IiByZWZZPSIzIiBvcmllbnQ9ImF1dG8iPjxwYXRoIGQ9Ik0wLDAgTDYsMyBMMCw2IFoiIGZpbGw9IiMwMEQ0RkYiIG9wYWNpdHk9Ii41Ii8+PC9tYXJrZXI+CiAgICAgICAgICA8bWFya2VyIGlkPSJhcnItciIgbWFya2VyV2lkdGg9IjYiIG1hcmtlckhlaWdodD0iNiIgcmVmWD0iNSIgcmVmWT0iMyIgb3JpZW50PSJhdXRvIj48cGF0aCBkPSJNMCwwIEw2LDMgTDAsNiBaIiBmaWxsPSIjRkYzQjVDIiBvcGFjaXR5PSIuNyIvPjwvbWFya2VyPgogICAgICAgIDwvZGVmcz4KICAgICAgICA8bGluZSB4MT0iMCIgeTE9IjEwNyIgeDI9IjU4MCIgeTI9IjEwNyIgc3Ryb2tlPSIjMEEyNTQwIiBzdHJva2Utd2lkdGg9IjEiLz4KICAgICAgICA8bGluZSB4MT0iMjkwIiB5MT0iMCIgeDI9IjI5MCIgeTI9IjIxNSIgc3Ryb2tlPSIjMEEyNTQwIiBzdHJva2Utd2lkdGg9IjEiLz4KICAgICAgICA8bGluZSB4MT0iMTAwIiB5MT0iMTA3IiB4Mj0iMjEwIiB5Mj0iMTA3IiBzdHJva2U9IiNGRjNCNUMiIHN0cm9rZS13aWR0aD0iMS4yIiBzdHJva2UtZGFzaGFycmF5PSI1LDMiIG9wYWNpdHk9Ii4zNSIgbWFya2VyLWVuZD0idXJsKCNhcnItcikiLz4KICAgICAgICA8bGluZSB4MT0iMjMwIiB5MT0iMTA3IiB4Mj0iMzQwIiB5Mj0iMTA3IiBzdHJva2U9IiMwMEQ0RkYiIHN0cm9rZS13aWR0aD0iMS4yIiBzdHJva2UtZGFzaGFycmF5PSI0LDMiIG9wYWNpdHk9Ii41IiBtYXJrZXItZW5kPSJ1cmwoI2FycikiLz4KICAgICAgICA8bGluZSB4MT0iMzYwIiB5MT0iMTA3IiB4Mj0iNDYwIiB5Mj0iMTA3IiBzdHJva2U9IiMwMEZGOUMiIHN0cm9rZS13aWR0aD0iMS4yIiBzdHJva2UtZGFzaGFycmF5PSI0LDMiIG9wYWNpdHk9Ii40IiBtYXJrZXItZW5kPSJ1cmwoI2FycikiLz4KICAgICAgICA8bGluZSB4MT0iNDkwIiB5MT0iOTAiIHgyPSI0OTAiIHkyPSI1NSIgc3Ryb2tlPSIjRkZEMTY2IiBzdHJva2Utd2lkdGg9IjEiIHN0cm9rZS1kYXNoYXJyYXk9IjMsMyIgb3BhY2l0eT0iLjM1Ii8+CiAgICAgICAgPGcgZmlsdGVyPSJ1cmwoI2dsb3ctcikiPjxyZWN0IHg9IjMwIiB5PSI3NyIgd2lkdGg9IjcwIiBoZWlnaHQ9IjYwIiByeD0iNCIgZmlsbD0icmdiYSgyNTUsNTksOTIsMC4wOCkiIHN0cm9rZT0iI0ZGM0I1QyIgc3Ryb2tlLXdpZHRoPSIxIi8+PC9nPgogICAgICAgIDx0ZXh0IHg9IjY1IiB5PSIxMDAiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGZvbnQtc2l6ZT0iMTgiIGZpbGw9IiNGRjNCNUMiPvCfkrs8L3RleHQ+CiAgICAgICAgPHRleHQgeD0iNjUiIHk9IjExOCIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZm9udC1zaXplPSI4LjUiIGZpbGw9IiNGRjNCNUMiIGZvbnQtZmFtaWx5PSJTaGFyZSBUZWNoIE1vbm8sbW9ub3NwYWNlIiBsZXR0ZXItc3BhY2luZz0iMSI+QVRBQ0FOVEU8L3RleHQ+CiAgICAgICAgPHRleHQgeD0iNjUiIHk9IjEzMCIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZm9udC1zaXplPSI3LjUiIGZpbGw9IiM0QTdGQTUiIGZvbnQtZmFtaWx5PSJTaGFyZSBUZWNoIE1vbm8sbW9ub3NwYWNlIj4xOTIuMTY4LjEuMjAwPC90ZXh0PgogICAgICAgIDxnIGZpbHRlcj0idXJsKCNnbG93LWMpIj48cmVjdCB4PSIxNjAiIHk9IjYyIiB3aWR0aD0iOTAiIGhlaWdodD0iOTAiIHJ4PSI0IiBmaWxsPSJyZ2JhKDAsMjEyLDI1NSwwLjA2KSIgc3Ryb2tlPSIjMDBENEZGIiBzdHJva2Utd2lkdGg9IjEuNSIvPjwvZz4KICAgICAgICA8dGV4dCB4PSIyMDUiIHk9IjkwIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBmb250LXNpemU9IjIwIiBmaWxsPSIjMDBENEZGIj7wn5al77iPPC90ZXh0PgogICAgICAgIDx0ZXh0IHg9IjIwNSIgeT0iMTA4IiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBmb250LXNpemU9IjkuNSIgZmlsbD0iI0U4RjRGRiIgZm9udC1mYW1pbHk9IlJhamRoYW5pLHNhbnMtc2VyaWYiIGZvbnQtd2VpZ2h0PSI3MDAiIGxldHRlci1zcGFjaW5nPSIxIj5FTkRQT0lOVDwvdGV4dD4KICAgICAgICA8dGV4dCB4PSIyMDUiIHk9IjEyMSIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZm9udC1zaXplPSI3LjUiIGZpbGw9IiM0QTdGQTUiIGZvbnQtZmFtaWx5PSJTaGFyZSBUZWNoIE1vbm8sbW9ub3NwYWNlIj4xOTIuMTY4LjEuMTAwPC90ZXh0PgogICAgICAgIDx0ZXh0IHg9IjIwNSIgeT0iMTMzIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBmb250LXNpemU9IjciIGZpbGw9IiMwMEZGOUMiIGZvbnQtZmFtaWx5PSJTaGFyZSBUZWNoIE1vbm8sbW9ub3NwYWNlIj5ob25leXBvdCDCtyBodW50ZXI8L3RleHQ+CiAgICAgICAgPHRleHQgeD0iMjA1IiB5PSIxNDUiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGZvbnQtc2l6ZT0iNyIgZmlsbD0iIzRBN0ZBNSIgZm9udC1mYW1pbHk9IlNoYXJlIFRlY2ggTW9ubyxtb25vc3BhY2UiPjoyMSDCtyA6MjIgwrcgOjgwPC90ZXh0PgogICAgICAgIDxnIGZpbHRlcj0idXJsKCNnbG93LWMpIj48cmVjdCB4PSIzMDAiIHk9IjYyIiB3aWR0aD0iOTAiIGhlaWdodD0iOTAiIHJ4PSI0IiBmaWxsPSJyZ2JhKDAsMjU1LDE1NiwwLjA1KSIgc3Ryb2tlPSIjMDBGRjlDIiBzdHJva2Utd2lkdGg9IjEuNSIvPjwvZz4KICAgICAgICA8dGV4dCB4PSIzNDUiIHk9IjkwIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBmb250LXNpemU9IjIwIiBmaWxsPSIjMDBGRjlDIj7imqE8L3RleHQ+CiAgICAgICAgPHRleHQgeD0iMzQ1IiB5PSIxMDgiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGZvbnQtc2l6ZT0iOCIgZmlsbD0iI0U4RjRGRiIgZm9udC1mYW1pbHk9IlJhamRoYW5pLHNhbnMtc2VyaWYiIGZvbnQtd2VpZ2h0PSI3MDAiIGxldHRlci1zcGFjaW5nPSIxIj5PUlFVRVNUQURPUjwvdGV4dD4KICAgICAgICA8dGV4dCB4PSIzNDUiIHk9IjEyMCIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZm9udC1zaXplPSI3LjUiIGZpbGw9IiM0QTdGQTUiIGZvbnQtZmFtaWx5PSJTaGFyZSBUZWNoIE1vbm8sbW9ub3NwYWNlIj4xOTIuMTY4LjEuNTA8L3RleHQ+CiAgICAgICAgPHRleHQgeD0iMzQ1IiB5PSIxMzIiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGZvbnQtc2l6ZT0iNyIgZmlsbD0iIzAwRkY5QyIgZm9udC1mYW1pbHk9IlNoYXJlIFRlY2ggTW9ubyxtb25vc3BhY2UiPkphdmEgwrcgVENQOjk5OTk8L3RleHQ+CiAgICAgICAgPGcgZmlsdGVyPSJ1cmwoI2dsb3ctYykiPjxyZWN0IHg9IjQ1NSIgeT0iNjIiIHdpZHRoPSI4MCIgaGVpZ2h0PSI2NSIgcng9IjQiIGZpbGw9InJnYmEoMjU1LDIwOSwxMDIsMC4wNikiIHN0cm9rZT0iI0ZGRDE2NiIgc3Ryb2tlLXdpZHRoPSIxIi8+PC9nPgogICAgICAgIDx0ZXh0IHg9IjQ5NSIgeT0iODgiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGZvbnQtc2l6ZT0iMTgiIGZpbGw9IiNGRkQxNjYiPvCfpJY8L3RleHQ+CiAgICAgICAgPHRleHQgeD0iNDk1IiB5PSIxMDQiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGZvbnQtc2l6ZT0iOC41IiBmaWxsPSIjRThGNEZGIiBmb250LWZhbWlseT0iUmFqZGhhbmksc2Fucy1zZXJpZiIgZm9udC13ZWlnaHQ9IjcwMCIgbGV0dGVyLXNwYWNpbmc9IjEiPk1PVE9SIElBPC90ZXh0PgogICAgICAgIDx0ZXh0IHg9IjQ5NSIgeT0iMTE3IiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBmb250LXNpemU9IjciIGZpbGw9IiM0QTdGQTUiIGZvbnQtZmFtaWx5PSJTaGFyZSBUZWNoIE1vbm8sbW9ub3NwYWNlIj5DbGF1ZGUgQVBJPC90ZXh0PgogICAgICAgIDxlbGxpcHNlIGN4PSI0OTUiIGN5PSIzOCIgcng9IjI4IiByeT0iMTQiIGZpbGw9InJnYmEoMjU1LDIwOSwxMDIsMC4wOCkiIHN0cm9rZT0iI0ZGRDE2NiIgc3Ryb2tlLXdpZHRoPSIuOCIgc3Ryb2tlLWRhc2hhcnJheT0iMywyIi8+CiAgICAgICAgPHRleHQgeD0iNDk1IiB5PSI0MiIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZm9udC1zaXplPSI4IiBmaWxsPSIjRkZEMTY2IiBmb250LWZhbWlseT0iU2hhcmUgVGVjaCBNb25vLG1vbm9zcGFjZSI+Q0xPVUQgQUk8L3RleHQ+CiAgICAgICAgPHRleHQgeD0iMjkwIiB5PSIyMDciIHRleHQtYW5jaG9yPSJtaWRkbGUiIGZvbnQtc2l6ZT0iNy41IiBmaWxsPSIjNEE3RkE1IiBmb250LWZhbWlseT0iU2hhcmUgVGVjaCBNb25vLG1vbm9zcGFjZSIgbGV0dGVyLXNwYWNpbmc9IjEiPlJFRCBJTlRFUk5BIOKAlCAxOTIuMTY4LjEuMC8yNCDigJQgTEFCT1JBVE9SSU8gVklSVFVBTCBPUkFDTEUgVklSVFVBTEJPWDwvdGV4dD4KICAgICAgICA8Y2lyY2xlIGlkPSJwa3QtYXRrIiByPSI1IiBmaWxsPSIjRkYzQjVDIiBvcGFjaXR5PSIwIiBmaWx0ZXI9InVybCgjZ2xvdy1yKSIvPgogICAgICAgIDxjaXJjbGUgaWQ9InBrdC1yZXAiIHI9IjQiIGZpbGw9IiMwMEQ0RkYiIG9wYWNpdHk9IjAiIGZpbHRlcj0idXJsKCNnbG93LWMpIi8+CiAgICAgICAgPGNpcmNsZSBpZD0icGt0LWFpIiByPSI0IiBmaWxsPSIjRkZEMTY2IiBvcGFjaXR5PSIwIiBmaWx0ZXI9InVybCgjZ2xvdy1jKSIvPgogICAgICAgIDxjaXJjbGUgaWQ9InBrdC1ibGsiIHI9IjQiIGZpbGw9IiNGRjNCNUMiIG9wYWNpdHk9IjAiLz4KICAgICAgPC9zdmc+CiAgICA8L2Rpdj4KICAgIDxkaXYgaWQ9ImxvZ3dyYXAiPgogICAgICA8ZGl2IGlkPSJsb2doZHIiPgogICAgICAgIDxzcGFuPlJFR0lTVFJPIERFIEVWRU5UT1MgRU4gVElFTVBPIFJFQUw8L3NwYW4+CiAgICAgICAgPHNwYW4gaWQ9ImV2LWNvdW50IiBzdHlsZT0iZm9udC1mYW1pbHk6J1NoYXJlIFRlY2ggTW9ubycsbW9ub3NwYWNlO2ZvbnQtc2l6ZTo5cHg7Y29sb3I6dmFyKC0tbXV0ZWQpOyI+MCBldmVudG9zPC9zcGFuPgogICAgICA8L2Rpdj4KICAgICAgPGRpdiBpZD0ibG9nIj48L2Rpdj4KICAgIDwvZGl2PgogIDwvZGl2PgoKICA8IS0tIFJJR0hUIC0tPgogIDxkaXYgaWQ9InJpZ2h0Ij4KICAgIDxkaXYgaWQ9ImFpYm94Ij4KICAgICAgPGRpdiBpZD0iYWloZHIiPgogICAgICAgIDxkaXYgaWQ9ImFpLWRvdCI+PC9kaXY+CiAgICAgICAgPHNwYW4gc3R5bGU9ImxldHRlci1zcGFjaW5nOjNweDtjb2xvcjp2YXIoLS1ncmVlbik7Ij5NT1RPUiBJQSDigJQgQ0xBVURFPC9zcGFuPgogICAgICAgIDxzcGFuIHN0eWxlPSJtYXJnaW4tbGVmdDphdXRvO2ZvbnQtc2l6ZTo4cHg7Y29sb3I6dmFyKC0tbXV0ZWQpOyI+Y2xhdWRlLXNvbm5ldC00LTIwMjUwNTE0PC9zcGFuPgogICAgICA8L2Rpdj4KICAgICAgPGRpdiBpZD0iYWktc2Nyb2xsIj4KICAgICAgICA8ZGl2IGNsYXNzPSJhaS1pZGxlIG1vbm8iIGlkPSJhaS1jb250ZW50Ij4KICAgICAgICAgIEVzcGVyYW5kbyBpbmNpZGVudGU8YnI+ZGUgUmllc2dvIEFsdG8uLi48YnI+PGJyPgogICAgICAgICAgU2lzdGVtYSBhY3Rpdm8gZW48YnI+MTkyLjE2OC4xLjAvMjQ8YnI+PGJyPgogICAgICAgICAgVW1icmFsOiAzIGhpdHMgLyA1czxicj4KICAgICAgICAgIFZlbnRhbmE6IDUwMDBtczxicj48YnI+CiAgICAgICAgICA8c3BhbiBzdHlsZT0iY29sb3I6dmFyKC0tY3lhbik7Ij5MaXN0byBwYXJhIGFuYWxpemFyLjwvc3Bhbj4KICAgICAgICA8L2Rpdj4KICAgICAgPC9kaXY+CiAgICA8L2Rpdj4KICAgIDxkaXYgaWQ9ImNoYXQtc2VjIj4KICAgICAgPGRpdiBjbGFzcz0icGFuZWwtaGRyIiBzdHlsZT0icGFkZGluZzo3cHggMTJweCA1cHg7Ij7wn5KsIENIQVQgQ09OIExBIElBIERFTCBTT0M8L2Rpdj4KICAgICAgPGRpdiBpZD0iY2hhdC1sb2ciPjwvZGl2PgogICAgICA8ZGl2IGlkPSJjaGF0LWlucHV0LXJvdyI+CiAgICAgICAgPGlucHV0IGlkPSJjaGF0LWluIiBwbGFjZWhvbGRlcj0iUHJlZ3VudGEgYWwgc2lzdGVtYSBkZSBJQS4uLiIgYXV0b2NvbXBsZXRlPSJvZmYiLz4KICAgICAgICA8YnV0dG9uIGlkPSJjaGF0LXNlbmQiIG9uY2xpY2s9InNlbmRDaGF0KCkiPkFTSyDihpc8L2J1dHRvbj4KICAgICAgPC9kaXY+CiAgICA8L2Rpdj4KICA8L2Rpdj4KPC9kaXY+Cgo8ZGl2IGlkPSJzaW0tYmFyIj4KICA8c3BhbiBpZD0ic2ItaW5mbyIgY2xhc3M9Im1vbm8iPlNFTlRJTkVMIFNPQyB2Mi4xIMK3IExhZ29tYXIgREFNIDIwMjQvMjAyNSDCtyBUQ1A6OTk5OSDCtyBIT05FWVBPVDoyMSwyMiw4MDwvc3Bhbj4KICA8YnV0dG9uIGlkPSJ0dHMtYnRuIiBvbmNsaWNrPSJ0b2dnbGVUVFMoKSI+8J+UiiBWT1o6IE9GRjwvYnV0dG9uPgogIDxidXR0b24gaWQ9InNpbS1idG4iIG9uY2xpY2s9InJ1bkF0dGFjaygpIj7imqEgU0lNVUxBUiBBVEFRVUU8L2J1dHRvbj4KPC9kaXY+Cgo8c2NyaXB0PgpsZXQgQVBJX0tFWT0nJzsKbGV0IHR0c0VuYWJsZWQ9ZmFsc2Usc2ltUnVubmluZz1mYWxzZTsKbGV0IHRvdGFsRXY9MCx0b3RhbFRoPTAsdG90YWxCbD0wOwpsZXQgYmxvY2tlZElQcz1bXTsKCmZ1bmN0aW9uIHN0YXJ0V2l0aEtleSgpewogIGNvbnN0IGs9ZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2FwaS1pbnB1dCcpLnZhbHVlLnRyaW0oKTsKICBpZihrKXtBUElfS0VZPWs7fQogIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdhcGktbW9kYWwnKS5zdHlsZS5kaXNwbGF5PSdub25lJzsKICBpbml0KCk7Cn0KZnVuY3Rpb24gc3RhcnRTaW11bGF0ZWQoKXsKICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnYXBpLW1vZGFsJykuc3R5bGUuZGlzcGxheT0nbm9uZSc7CiAgaW5pdCgpOwp9CgpmdW5jdGlvbiB0cygpe3JldHVybiBuZXcgRGF0ZSgpLnRvTG9jYWxlVGltZVN0cmluZygnZXMtRVMnLHtob3VyMTI6ZmFsc2V9KTt9CmZ1bmN0aW9uIG1zdHMoKXtyZXR1cm4gbmV3IERhdGUoKS50b0xvY2FsZVRpbWVTdHJpbmcoJ2VzLUVTJyx7aG91cjEyOmZhbHNlLGZyYWN0aW9uYWxTZWNvbmREaWdpdHM6Mn0pO30Kc2V0SW50ZXJ2YWwoKCk9PmRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdjbG9jaycpLnRleHRDb250ZW50PXRzKCksMTAwMCk7CgpmdW5jdGlvbiBzcGVhayh0ZXh0KXsKICBpZighdHRzRW5hYmxlZHx8IXdpbmRvdy5zcGVlY2hTeW50aGVzaXMpcmV0dXJuOwogIHdpbmRvdy5zcGVlY2hTeW50aGVzaXMuY2FuY2VsKCk7CiAgY29uc3QgdT1uZXcgU3BlZWNoU3ludGhlc2lzVXR0ZXJhbmNlKHRleHQpOwogIHUubGFuZz0nZXMtRVMnO3UucmF0ZT0wLjk1O3UucGl0Y2g9MC45OwogIGNvbnN0IHZvaWNlcz13aW5kb3cuc3BlZWNoU3ludGhlc2lzLmdldFZvaWNlcygpOwogIGNvbnN0IGVzPXZvaWNlcy5maW5kKHY9PnYubGFuZy5zdGFydHNXaXRoKCdlcycpKTsKICBpZihlcyl1LnZvaWNlPWVzOwogIHdpbmRvdy5zcGVlY2hTeW50aGVzaXMuc3BlYWsodSk7Cn0KCmZ1bmN0aW9uIHRvZ2dsZVRUUygpewogIHR0c0VuYWJsZWQ9IXR0c0VuYWJsZWQ7CiAgY29uc3QgYnRuPWRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0dHMtYnRuJyk7CiAgYnRuLnRleHRDb250ZW50PXR0c0VuYWJsZWQ/J/CflIogVk9aOiBPTic6J/CflIogVk9aOiBPRkYnOwogIGJ0bi5jbGFzc0xpc3QudG9nZ2xlKCdvbicsdHRzRW5hYmxlZCk7CiAgaWYodHRzRW5hYmxlZClzcGVhaygnU2lzdGVtYSBkZSB2b3ogYWN0aXZhZG8uIFNlbnRpbmVsIFNPQyBlbiBsw61uZWEuJyk7Cn0KCmZ1bmN0aW9uIGFkZEV2ZW50KHR5cGUsaWNvbixtYWluLHN1Yj0nJyl7CiAgdG90YWxFdisrOwogIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdtMScpLnRleHRDb250ZW50PXRvdGFsRXY7CiAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2V2LWNvdW50JykudGV4dENvbnRlbnQ9dG90YWxFdisnIGV2ZW50b3MnOwogIGNvbnN0IGxvZz1kb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnbG9nJyk7CiAgY29uc3QgZD1kb2N1bWVudC5jcmVhdGVFbGVtZW50KCdkaXYnKTsKICBkLmNsYXNzTmFtZT0nZXYgdC0nK3R5cGU7CiAgZC5pbm5lckhUTUw9JzxzcGFuIGNsYXNzPSJldi10Ij4nK21zdHMoKSsnPC9zcGFuPjxkaXYgY2xhc3M9ImV2LWljIj4nK2ljb24rJzwvZGl2PjxkaXYgY2xhc3M9ImV2LWJvZHkiPjxkaXYgY2xhc3M9ImV2LW0iPicrbWFpbisnPC9kaXY+Jysoc3ViPyc8ZGl2IGNsYXNzPSJldi1zIj4nK3N1YisnPC9kaXY+JzonJykrJzwvZGl2Pic7CiAgbG9nLnByZXBlbmQoZCk7CiAgd2hpbGUobG9nLmNoaWxkcmVuLmxlbmd0aD42MClsb2cucmVtb3ZlQ2hpbGQobG9nLmxhc3RDaGlsZCk7Cn0KCmZ1bmN0aW9uIHNldFJpc2sobGV2ZWwpewogIGNvbnN0IHJmPWRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdyZicpOwogIGlmKGxldmVsPT09J0xPVycpe3JmLnN0eWxlLndpZHRoPSc2JSc7cmYuc3R5bGUuYmFja2dyb3VuZD0ndmFyKC0tZ3JlZW4pJzt9CiAgZWxzZSBpZihsZXZlbD09PSdNRUQnKXtyZi5zdHlsZS53aWR0aD0nNTIlJztyZi5zdHlsZS5iYWNrZ3JvdW5kPSd2YXIoLS1vcmFuZ2UpJzt9CiAgZWxzZXtyZi5zdHlsZS53aWR0aD0nOTYlJztyZi5zdHlsZS5iYWNrZ3JvdW5kPSd2YXIoLS1yZWQpJzt9Cn0KCmZ1bmN0aW9uIGFkZEJsb2NrZWQoaXApewogIGlmKGJsb2NrZWRJUHMuaW5jbHVkZXMoaXApKXJldHVybjsKICBibG9ja2VkSVBzLnB1c2goaXApO3RvdGFsQmwrKzsKICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnbTMnKS50ZXh0Q29udGVudD10b3RhbEJsOwogIGNvbnN0IHM9ZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2Jsay1zZWMnKTsKICBpZihzLnF1ZXJ5U2VsZWN0b3IoJ3NwYW4nKSlzLmlubmVySFRNTD0nJzsKICBjb25zdCBkPWRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2RpdicpO2QuY2xhc3NOYW1lPSdibGstaXAnOwogIGQuaW5uZXJIVE1MPWlwKycgPHNwYW4gc3R5bGU9ImNvbG9yOnZhcigtLW11dGVkKSI+QkxPQ0sg4pyTPC9zcGFuPic7CiAgcy5wcmVwZW5kKGQpOwp9CgpmdW5jdGlvbiBzZXRBZ2VudEFsZXJ0KGlkLG9uKXsKICBjb25zdCBhPWRvY3VtZW50LmdldEVsZW1lbnRCeUlkKGlkKTtpZighYSlyZXR1cm47CiAgYS5zdHlsZS5iYWNrZ3JvdW5kPW9uPydyZ2JhKDI1NSw1OSw5MiwwLjA2KSc6Jyc7CiAgY29uc3QgYj1hLnF1ZXJ5U2VsZWN0b3IoJy5iYWRnZScpOwogIGlmKGIpe2IuY2xhc3NOYW1lPW9uPydiYWRnZSBiLWFsZXJ0JzonYmFkZ2UgYi1vayc7Yi50ZXh0Q29udGVudD1vbj8nQUxFUlQnOidBQ1RJVk8nO30KfQoKZnVuY3Rpb24gYW5pbVBrdChpZCx4MSx5MSx4Mix5MixkdXIsZGVsYXkpewogIHJldHVybiBuZXcgUHJvbWlzZShyZXM9PnsKICAgIHNldFRpbWVvdXQoKCk9PnsKICAgICAgY29uc3QgcD1kb2N1bWVudC5nZXRFbGVtZW50QnlJZChpZCk7CiAgICAgIGlmKCFwKXtyZXMoKTtyZXR1cm47fQogICAgICBwLnNldEF0dHJpYnV0ZSgnY3gnLHgxKTtwLnNldEF0dHJpYnV0ZSgnY3knLHkxKTtwLnNldEF0dHJpYnV0ZSgnb3BhY2l0eScsJzEnKTsKICAgICAgbGV0IHM9bnVsbDsKICAgICAgZnVuY3Rpb24gc3RlcCh0cyl7CiAgICAgICAgaWYoIXMpcz10czsKICAgICAgICBjb25zdCBwcm9nPU1hdGgubWluKCh0cy1zKS9kdXIsMSk7CiAgICAgICAgcC5zZXRBdHRyaWJ1dGUoJ2N4Jyx4MSsoeDIteDEpKnByb2cpOwogICAgICAgIHAuc2V0QXR0cmlidXRlKCdjeScseTErKHkyLXkxKSpwcm9nKTsKICAgICAgICBpZihwcm9nPDEpcmVxdWVzdEFuaW1hdGlvbkZyYW1lKHN0ZXApOwogICAgICAgIGVsc2V7cC5zZXRBdHRyaWJ1dGUoJ29wYWNpdHknLCcwJyk7cmVzKCk7fQogICAgICB9CiAgICAgIHJlcXVlc3RBbmltYXRpb25GcmFtZShzdGVwKTsKICAgIH0sZGVsYXl8fDApOwogIH0pOwp9CgpmdW5jdGlvbiB3YWl0KG1zKXtyZXR1cm4gbmV3IFByb21pc2Uocj0+c2V0VGltZW91dChyLG1zKSk7fQoKYXN5bmMgZnVuY3Rpb24gY2FsbEFJKGluY2lkZW50LGlzQ2hhdCxjaGF0TXNnKXsKICBjb25zdCBzeXM9aXNDaGF0CiAgICA/J0VyZXMgZWwgbW90b3IgZGUgaW50ZWxpZ2VuY2lhIGFydGlmaWNpYWwgZGVsIHNpc3RlbWEgU0VOVElORUwgU09DLiBSZXNwb25kZSBjb21vIGVsIGNlcmVicm8gZGVsIFNPQyBlbiBlc3Bhw7FvbCwgY29uY2lzbyAobcOheGltbyAzIGZyYXNlcykuIENvbnRleHRvOiAnK0pTT04uc3RyaW5naWZ5KGluY2lkZW50KQogICAgOidFcmVzIGVsIG1vdG9yIGRlIGFuw6FsaXNpcyBkZSB1biBTT0MuIFJlc3BvbmRlIFNPTE8gY29uIEpTT046IHsiYWN0aW9uIjoiQkxPQ0siLCJjb25maWRlbmNlIjo5NSwicmVhc29uaW5nIjoiYW7DoWxpc2lzIGVuIGVzcGHDsW9sIGVuIDIgZnJhc2VzIn0uIFNpbiB0ZXh0byBhZGljaW9uYWwuJzsKICBjb25zdCB1c2VyPWlzQ2hhdD9jaGF0TXNnOidJTkNJREVOVEU6IElQOiAnK2luY2lkZW50LmlwKycgfCBTZXJ2aWNpb3M6ICcraW5jaWRlbnQuc2VydmljZXMrJyB8IEhpdHM6ICcraW5jaWRlbnQuaGl0cysnIGVuICcraW5jaWRlbnQubXMrJ21zIHwgUmllc2dvOiBBTFRPJzsKCiAgaWYoIUFQSV9LRVkpewogICAgaWYoaXNDaGF0KXJldHVybidQYXRyw7NuIGRlIGVzY2FuZW8gc2lzdGVtw6F0aWNvIGNvbmZpcm1hZG8gZGVzZGUgMTkyLjE2OC4xLjIwMC4gU2UgY29udGFjdGFyb24gc2VydmljaW9zIEZUUCwgU1NIIHkgSFRUUCBlbiBtZW5vcyBkZSAzIHNlZ3VuZG9zLiBSZWNvbWVuZGFjacOzbjogYmxvcXVlbyBpbm1lZGlhdG8gZWplY3V0YWRvLic7CiAgICByZXR1cm57YWN0aW9uOidCTE9DSycsY29uZmlkZW5jZTo5NyxyZWFzb25pbmc6J1BhdHLDs24gZGUgcmVjb25vY2ltaWVudG8gYWN0aXZvIGNvbmZpcm1hZG86IDMgc2VydmljaW9zIGNvbnRhY3RhZG9zIChGVFAsIFNTSCwgSFRUUCkgZW4gMjgwMG1zIGRlc2RlIGxhIG1pc21hIElQLiBDb21wb3J0YW1pZW50byBpZMOpbnRpY28gYSBObWFwIC1zVi4gQmxvcXVlbyBpbm1lZGlhdG8gcmVjb21lbmRhZG8uJ307CiAgfQoKICB0cnl7CiAgICBjb25zdCByPWF3YWl0IGZldGNoKCdodHRwczovL2FwaS5hbnRocm9waWMuY29tL3YxL21lc3NhZ2VzJyx7CiAgICAgIG1ldGhvZDonUE9TVCcsCiAgICAgIGhlYWRlcnM6eydDb250ZW50LVR5cGUnOidhcHBsaWNhdGlvbi9qc29uJywneC1hcGkta2V5JzpBUElfS0VZLCdhbnRocm9waWMtdmVyc2lvbic6JzIwMjMtMDYtMDEnfSwKICAgICAgYm9keTpKU09OLnN0cmluZ2lmeSh7bW9kZWw6J2NsYXVkZS1zb25uZXQtNC0yMDI1MDUxNCcsbWF4X3Rva2VuczoxMDAwLHN5c3RlbTpzeXMsbWVzc2FnZXM6W3tyb2xlOid1c2VyJyxjb250ZW50OnVzZXJ9XX0pCiAgICB9KTsKICAgIGNvbnN0IGQ9YXdhaXQgci5qc29uKCk7CiAgICBjb25zdCB0eHQ9KGQuY29udGVudCYmZC5jb250ZW50WzBdJiZkLmNvbnRlbnRbMF0udGV4dCl8fCcnOwogICAgaWYoaXNDaGF0KXJldHVybiB0eHQ7CiAgICByZXR1cm4gSlNPTi5wYXJzZSh0eHQucmVwbGFjZSgvYGBganNvbnxgYGAvZywnJykudHJpbSgpKTsKICB9Y2F0Y2goZSl7CiAgICBpZihpc0NoYXQpcmV0dXJuJ0Vycm9yIGRlIGNvbmV4acOzbi4gU2lzdGVtYSBlbiBtb2RvIGRlZ3JhZGFkbyDigJQgYmxvcXVlbyBwcmV2ZW50aXZvIGFjdGl2by4nOwogICAgcmV0dXJue2FjdGlvbjonQkxPQ0snLGNvbmZpZGVuY2U6OTUscmVhc29uaW5nOidQYXRyw7NuIGRlIGVzY2FuZW8gbWFzaXZvIGRldGVjdGFkby4gQmxvcXVlbyBwcmV2ZW50aXZvIGFwbGljYWRvIHBvciBzZWd1cmlkYWQuJ307CiAgfQp9Cgphc3luYyBmdW5jdGlvbiBydW5BdHRhY2soKXsKICBpZihzaW1SdW5uaW5nKXJldHVybjsKICBzaW1SdW5uaW5nPXRydWU7CiAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3NpbS1idG4nKS5kaXNhYmxlZD10cnVlOwogIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdzaW0tYnRuJykudGV4dENvbnRlbnQ9J+KPsyBFSkVDVVRBTkRPLi4uJzsKICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnc3lzLXN0YXR1cycpLnRleHRDb250ZW50PSfimqAgQVRBUVVFIERFVEVDVEFETyc7CiAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3N5cy1zdGF0dXMnKS5zdHlsZS5jb2xvcj0ndmFyKC0tb3JhbmdlKSc7CiAgY29uc3QgYXRrPScxOTIuMTY4LjEuMjAwJzsKICBzcGVhaygnQXRlbmNpw7NuLiBBY3RpdmlkYWQgc29zcGVjaG9zYSBkZXRlY3RhZGEgZW4gbGEgcmVkLicpOwogIGF3YWl0IHdhaXQoMzAwKTsKICBhZGRFdmVudCgnd2FybicsJ+KaoScsJ05tYXAgLXNWIGRldGVjdGFkbyBlbiBsYSByZWQnLCdvcmlnZW46IDE5Mi4xNjguMS4yMDAgwrcgZGVzdGlubzogMTkyLjE2OC4xLjEwMCcpOwogIHNldFJpc2soJ01FRCcpOwogIGF3YWl0IGFuaW1Qa3QoJ3BrdC1hdGsnLDY1LDEwNywxNzUsMTA3LDcwMCk7CiAgYXdhaXQgd2FpdCg1MDApOwogIHNldEFnZW50QWxlcnQoJ2FnLWhvbmV5Jyx0cnVlKTsKICBzcGVhaygnSG9uZXlwb3QgYWN0aXZhZG8uIFByaW1lciBjb250YWN0byBlbiBwdWVydG8gMjEsIEZUUC4nKTsKICBhZGRFdmVudCgnaGl0Jywn8J+NrycsJ0hJVCDigJQgUHVlcnRvIDIxIChGVFApJywnSVA9MTkyLjE2OC4xLjIwMCDCtyBiYW5uZXI6IFByb0ZUUEQgMS4zLjYgZW52aWFkbyDCtyBUQ1AgaGFuZHNoYWtlJyk7CiAgYXdhaXQgYW5pbVBrdCgncGt0LWF0aycsNjUsMTA3LDE3NSwxMDcsNjAwKTsKICBhd2FpdCB3YWl0KDYwMCk7CiAgYWRkRXZlbnQoJ2hpdCcsJ/Cfja8nLCdISVQg4oCUIFB1ZXJ0byAyMiAoU1NIKScsJ0lQPTE5Mi4xNjguMS4yMDAgwrcgYmFubmVyOiBPcGVuU1NIXzguOXAxIGVudmlhZG8nKTsKICBhd2FpdCBhbmltUGt0KCdwa3QtYXRrJyw2NSwxMDcsMTg1LDEwNyw2MDApOwogIGF3YWl0IHdhaXQoNjAwKTsKICBhZGRFdmVudCgnaGl0Jywn8J+NrycsJ0hJVCDigJQgUHVlcnRvIDgwIChIVFRQKScsJ0lQPTE5Mi4xNjguMS4yMDAgwrcgYmFubmVyOiBBcGFjaGUvMi40LjU0IGVudmlhZG8nKTsKICBhd2FpdCBhbmltUGt0KCdwa3QtYXRrJyw2NSwxMDcsMTk1LDEwNyw2MDApOwogIGF3YWl0IHdhaXQoNDAwKTsKICBhZGRFdmVudCgnY3JpdCcsJ/Cfk4onLCdDT1JSRUxBQ0nDk046IFVNQlJBTCBTVVBFUkFETycsJzMgaGl0cyBlbiAyODAwbXMgwrcgVmVudGFuYTogNTAwMG1zIMK3IFJJRVNHTyBBTFRPJyk7CiAgc2V0UmlzaygnSElHSCcpOwogIHRvdGFsVGgrKztkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnbTInKS50ZXh0Q29udGVudD10b3RhbFRoOwogIHNwZWFrKCdBbGVydGEgY3LDrXRpY2EuIFVtYnJhbCBkZSByaWVzZ28gYWx0byBzdXBlcmFkby4gSW52b2NhbmRvIG1vdG9yIGRlIGludGVsaWdlbmNpYSBhcnRpZmljaWFsLicpOwogIGF3YWl0IHdhaXQoMzAwKTsKICBhd2FpdCBhbmltUGt0KCdwa3QtcmVwJywyMDUsMTA3LDM0NSwxMDcsNzAwKTsKICBhZGRFdmVudCgnYWknLCfimqEnLCdFdmVudG8gZW52aWFkbyBhbCBPcnF1ZXN0YWRvciBKYXZhJywnVENQOjk5OTkgwrcgSlNPTiBzZXJpYWxpemFkbyDCtyBwb29sIGRlIGhpbG9zIGFzaWduYWRvJyk7CiAgYXdhaXQgd2FpdCg2MDApOwogIGF3YWl0IGFuaW1Qa3QoJ3BrdC1haScsMzQ1LDkwLDQ5MCw5MCw3MDApOwogIGFkZEV2ZW50KCdhaScsJ/CfpJYnLCdJbnZvY2FuZG8gTW90b3IgZGUgSW50ZWxpZ2VuY2lhIEFydGlmaWNpYWwnLCdjb250ZXh0bzogMyBoaXRzLzI4MDBtcyDCtyBwdWVydG9zIDIxLDIyLDgwIMK3IHJpZXNnbyBBTFRPJyk7CiAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2FpLWNvbnRlbnQnKS5pbm5lckhUTUw9JzxkaXYgc3R5bGU9ImNvbG9yOnZhcigtLXllbGxvdyk7Zm9udC1mYW1pbHk6XCdTaGFyZSBUZWNoIE1vbm9cJyxtb25vc3BhY2U7Zm9udC1zaXplOjEwcHg7bGluZS1oZWlnaHQ6MS44OyI+4pqgIEFOQUxJWkFORE8gSU5DSURFTlRFPGJyPklQOiAnK2F0aysnPGJyPkhpdHM6IDMgZW4gMjgwMG1zPGJyPlB1ZXJ0b3M6IDIxLCAyMiwgODA8YnI+PGJyPjxzcGFuIHN0eWxlPSJhbmltYXRpb246cHVsc2UgMC42cyBpbmZpbml0ZTtkaXNwbGF5OmlubGluZS1ibG9jazsiPkNvbnN1bHRhbmRvIElBLi4uPC9zcGFuPjwvZGl2Pic7CiAgY29uc3QgaW5jaWRlbnQ9e2lwOmF0ayxzZXJ2aWNlczonRlRQLFNTSCxIVFRQJyxoaXRzOjMsbXM6MjgwMH07CiAgY29uc3QgYWlSZXN1bHQ9YXdhaXQgY2FsbEFJKGluY2lkZW50LGZhbHNlLCcnKTsKICBjb25zdCBpc0Jsb2NrPWFpUmVzdWx0LmFjdGlvbj09PSdCTE9DSyc7CiAgY29uc3QgY29uZj1haVJlc3VsdC5jb25maWRlbmNlfHw5NTsKICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnYWktY29udGVudCcpLmlubmVySFRNTD0nPGRpdiBjbGFzcz0iYWktYWN0aW9uIiBzdHlsZT0iY29sb3I6JysoaXNCbG9jaz8ndmFyKC0tcmVkKSc6J3ZhcigtLW9yYW5nZSknKSsnOyI+JysoaXNCbG9jaz8n8J+aqyc6J/CfkYHvuI8nKSsnICcrYWlSZXN1bHQuYWN0aW9uKyc8L2Rpdj48ZGl2IGNsYXNzPSJhaS1jb25mIj5DT05GSUFOWkE6ICcrY29uZisnJSDCtyAnK3RzKCkrJzwvZGl2PjxkaXYgc3R5bGU9ImhlaWdodDo4cHg7YmFja2dyb3VuZDp2YXIoLS1ib3JkZXIpO2JvcmRlci1yYWRpdXM6M3B4O21hcmdpbjo4cHggMDtvdmVyZmxvdzpoaWRkZW47Ij48ZGl2IHN0eWxlPSJoZWlnaHQ6MTAwJTt3aWR0aDonK2NvbmYrJyU7YmFja2dyb3VuZDonKyhpc0Jsb2NrPyd2YXIoLS1yZWQpJzondmFyKC0tb3JhbmdlKScpKyc7Ym9yZGVyLXJhZGl1czozcHg7dHJhbnNpdGlvbjp3aWR0aCAxczsiPjwvZGl2PjwvZGl2PjxkaXYgY2xhc3M9ImFpLXJlYXNvbiI+JythaVJlc3VsdC5yZWFzb25pbmcrJzwvZGl2Pic7CiAgYWRkRXZlbnQoJ2FpJywn8J+klicsJ0lBIGRlY2lkZTogJythaVJlc3VsdC5hY3Rpb24rJyAoJytjb25mKyclKScsYWlSZXN1bHQucmVhc29uaW5nLnN1YnN0cmluZygwLDcwKSsnLi4uJyk7CiAgc3BlYWsoJ0xhIGludGVsaWdlbmNpYSBhcnRpZmljaWFsIGhhIGFuYWxpemFkbyBlbCBpbmNpZGVudGUuIERlY2lzacOzbjogJythaVJlc3VsdC5hY3Rpb24rJy4gJysoaXNCbG9jaz8nRWplY3V0YW5kbyBibG9xdWVvIGlubWVkaWF0by4nOidBY3RpdmFuZG8gbW9uaXRvcml6YWNpw7NuLicpKTsKICBpZihpc0Jsb2NrKXsKICAgIGF3YWl0IHdhaXQoNTAwKTsKICAgIGF3YWl0IGFuaW1Qa3QoJ3BrdC1ibGsnLDM0NSwxMDcsMjA1LDEwNyw2MDApOwogICAgYWRkRXZlbnQoJ2Jsb2NrJywn8J+UkicsJ0JMT1FVRU8gRUpFQ1VUQURPIOKAlCAnK2F0aywnaXB0YWJsZXMgLUkgSU5QVVQgLXMgMTkyLjE2OC4xLjIwMCAtaiBEUk9QIMK3IGtlcm5lbCBhcGxpY2FkbycpOwogICAgYWRkQmxvY2tlZChhdGspOwogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ21pdC1iYWRnZScpLnRleHRDb250ZW50PSdCTE9DSyc7CiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnbWl0LWJhZGdlJykuY2xhc3NOYW1lPSdiYWRnZSBiLWFsZXJ0JzsKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdzeXMtc3RhdHVzJykudGV4dENvbnRlbnQ9J/CflJIgQU1FTkFaQSBCTE9RVUVBREEnOwogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3N5cy1zdGF0dXMnKS5zdHlsZS5jb2xvcj0ndmFyKC0tcmVkKSc7CiAgICBzcGVhaygnQmxvcXVlbyBlamVjdXRhZG8uIExhIGFtZW5hemEgaGEgc2lkbyBuZXV0cmFsaXphZGEuIFNpc3RlbWEgcHJvdGVnaWRvLicpOwogIH0KICBzZXRBZ2VudEFsZXJ0KCdhZy1ob25leScsZmFsc2UpOwogIGF3YWl0IHdhaXQoMjUwMCk7CiAgc2V0UmlzaygnTE9XJyk7CiAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3N5cy1zdGF0dXMnKS50ZXh0Q29udGVudD0n4pyFIFNJU1RFTUEgUFJPVEVHSURPJzsKICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnc3lzLXN0YXR1cycpLnN0eWxlLmNvbG9yPSd2YXIoLS1ncmVlbiknOwogIHNpbVJ1bm5pbmc9ZmFsc2U7CiAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3NpbS1idG4nKS5kaXNhYmxlZD1mYWxzZTsKICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnc2ltLWJ0bicpLnRleHRDb250ZW50PSfimqEgU0lNVUxBUiBBVEFRVUUnOwp9Cgphc3luYyBmdW5jdGlvbiBzZW5kQ2hhdCgpewogIGNvbnN0IGlucD1kb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnY2hhdC1pbicpOwogIGNvbnN0IG1zZz1pbnAudmFsdWUudHJpbSgpOwogIGlmKCFtc2cpcmV0dXJuOwogIGlucC52YWx1ZT0nJzsKICBjb25zdCBsb2c9ZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2NoYXQtbG9nJyk7CiAgY29uc3QgdURpdj1kb2N1bWVudC5jcmVhdGVFbGVtZW50KCdkaXYnKTsKICB1RGl2LmNsYXNzTmFtZT0nY20gY20tdXNlcic7CiAgdURpdi5pbm5lckhUTUw9JzxkaXYgY2xhc3M9ImNtLWxhYmVsIj5Uw5o8L2Rpdj48ZGl2PicrbXNnKyc8L2Rpdj4nOwogIGxvZy5hcHBlbmRDaGlsZCh1RGl2KTtsb2cuc2Nyb2xsVG9wPWxvZy5zY3JvbGxIZWlnaHQ7CiAgY29uc3QgdGhpbmtpbmc9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnZGl2Jyk7CiAgdGhpbmtpbmcuY2xhc3NOYW1lPSdjbSBjbS1haSc7CiAgdGhpbmtpbmcuaW5uZXJIVE1MPSc8ZGl2IGNsYXNzPSJjbS1sYWJlbCI+SUEgU09DPC9kaXY+PGRpdiBzdHlsZT0iY29sb3I6dmFyKC0tbXV0ZWQpOyI+YW5hbGl6YW5kby4uLjwvZGl2Pic7CiAgbG9nLmFwcGVuZENoaWxkKHRoaW5raW5nKTtsb2cuc2Nyb2xsVG9wPWxvZy5zY3JvbGxIZWlnaHQ7CiAgY29uc3QgaW5jaWRlbnQ9e2lwOicxOTIuMTY4LjEuMjAwJyxzZXJ2aWNlczonRlRQLFNTSCxIVFRQJyxoaXRzOjMsbXM6MjgwMCxibG9ja2VkOmJsb2NrZWRJUHN9OwogIGNvbnN0IHJlc3A9YXdhaXQgY2FsbEFJKGluY2lkZW50LHRydWUsbXNnKTsKICB0aGlua2luZy5pbm5lckhUTUw9JzxkaXYgY2xhc3M9ImNtLWxhYmVsIj5JQSBTT0M8L2Rpdj48ZGl2PicrcmVzcCsnPC9kaXY+JzsKICBsb2cuc2Nyb2xsVG9wPWxvZy5zY3JvbGxIZWlnaHQ7CiAgc3BlYWsocmVzcCk7Cn0KCmRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdjaGF0LWluJykuYWRkRXZlbnRMaXN0ZW5lcigna2V5ZG93bicsZnVuY3Rpb24oZSl7aWYoZS5rZXk9PT0nRW50ZXInKXNlbmRDaGF0KCk7fSk7CgpmdW5jdGlvbiBpbml0KCl7CiAgaWYod2luZG93LnNwZWVjaFN5bnRoZXNpcyl3aW5kb3cuc3BlZWNoU3ludGhlc2lzLmdldFZvaWNlcygpOwogIGFkZEV2ZW50KCdpbmZvJywn4pyFJywnU2lzdGVtYSBpbmljaWFsaXphZG8g4oCUIHRvZG9zIGxvcyBhZ2VudGVzIGFjdGl2b3MnLCc1IGFnZW50ZXMgb25saW5lIMK3IG9ycXVlc3RhZG9yIFRDUDo5OTk5IMK3IG1vdG9yIElBIGNvbmVjdGFkbycpOwogIGFkZEV2ZW50KCdpbmZvJywn8J+UjScsJ0h1bnRlciBlc2NhbmVhbmRvIHJlZCAxOTIuMTY4LjEuMC8yNCcsJzMgaG9zdHMgYWN0aXZvcyDCtyB0b3AtMjAgcHVlcnRvcyBtb25pdG9yaXphZG9zJyk7CiAgYWRkRXZlbnQoJ2luZm8nLCfwn42vJywnSG9uZXlwb3QgYWN0aXZvIGVuIHB1ZXJ0b3MgMjEsIDIyLCA4MCcsJ2Jhbm5lcnMgZmlkZWRpZ25vcyBjb25maWd1cmFkb3MgwrcgbG9nZ2luZyBoYWJpbGl0YWRvJyk7CiAgc2V0SW50ZXJ2YWwoZnVuY3Rpb24oKXsKICAgIGlmKHNpbVJ1bm5pbmcpcmV0dXJuOwogICAgdmFyIG1zZ3M9WwogICAgICBbJ2luZm8nLCfwn5KTJywnSGVhcnRiZWF0IOKAlCBob25leXBvdC0wMScsJ3VwdGltZSAnK01hdGguZmxvb3IoTWF0aC5yYW5kb20oKSoxODArMTApKydtIMK3IDAgZmFsc29zIHBvc2l0aXZvcyddLAogICAgICBbJ2luZm8nLCfwn5SNJywnRXNjYW5lbyBodW50ZXIgY29tcGxldGFkbycsJ3NpbiBjYW1iaW9zIGVuIHRvcG9sb2fDrWEgwrcgMyBob3N0cyBhY3Rpdm9zJ10sCiAgICAgIFsnaW5mbycsJ/Cfk4onLCdSZXBvcnRlIGhhcmRlbmluZycsJ3NpbiB2dWxuZXJhYmlsaWRhZGVzIGNyw610aWNhcyBkZXRlY3RhZGFzJ10sCiAgICBdOwogICAgdmFyIG09bXNnc1tNYXRoLmZsb29yKE1hdGgucmFuZG9tKCkqbXNncy5sZW5ndGgpXTsKICAgIGFkZEV2ZW50KG1bMF0sbVsxXSxtWzJdLG1bM10pOwogIH0sNzAwMCk7Cn0KPC9zY3JpcHQ+CjwvYm9keT4KPC9odG1sPgo="
SOC_HTML = _b64.b64decode(_HTML_B64).decode("utf-8")

def build_soc_html():
    """Genera el HTML del panel SOC con la API key ya inyectada."""
    api_key = state["config"].get("api_key", "")
    html = SOC_HTML.replace('const API_KEY=""', f'const API_KEY="{api_key}"')
    html = html.replace(
        'document.getElementById(\'api-modal\').style.display=\'none\';',
        'if(document.getElementById("api-modal"))document.getElementById("api-modal").style.display="none";'
    )
    return html

import http.server

class SOCHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            html = build_soc_html().encode("utf-8") if SOC_HTML else self._fallback_html()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(html)

        elif self.path == "/api/state":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            with state["lock"]:
                data = {
                    "total_hits":    state["total_hits"],
                    "total_threats": state["total_threats"],
                    "total_blocked": state["total_blocked"],
                    "events":        state["events"][-80:],
                    "blocked_ips":   list(state["blocked_ips"]),
                    "last_ai":       state.get("last_ai"),
                    "config": {
                        "honeypot_ports":  state["config"]["honeypot_ports"],
                        "risk_threshold":  state["config"]["risk_threshold"],
                        "risk_window_ms":  state["config"]["risk_window_ms"],
                        "auto_block":      state["config"]["auto_block"],
                    }
                }
            self.wfile.write(json.dumps(data).encode())

        elif self.path == "/api/unblock" :
            self.send_response(405)
            self.end_headers()

        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == "/api/unblock":
            length = int(self.headers.get("Content-Length", 0))
            body   = json.loads(self.rfile.read(length).decode())
            ip     = body.get("ip", "")
            with state["lock"]:
                state["blocked_ips"].discard(ip)
            logger.info("IP %s desbloqueada manualmente.", ip)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"ok": True}).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def _fallback_html(self):
        return b"<html><body><h1>Sentinel SOC</h1><p>Panel web no encontrado.</p></body></html>"

def run_web_server():
    port = state["config"]["web_port"]
    server = http.server.HTTPServer(("0.0.0.0", port), SOCHandler)
    logger.info("Panel SOC disponible en http://localhost:%d", port)
    server.serve_forever()

# ─── INSTALACIÓN COMO SERVICIO ────────────────────────────────────────────────
def install_service():
    """Instala Sentinel SOC como servicio del sistema operativo."""
    exe = str(Path(sys.executable))
    script = str(Path(__file__).resolve())

    if IS_WINDOWS:
        try:
            import winreg
            key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, "SentinelSOC", 0, winreg.REG_SZ, f'"{exe}" "{script}" --service')
            winreg.CloseKey(key)
            logger.info("✅ Sentinel SOC instalado como servicio de inicio de Windows.")
            print("\n✅ Instalado. El sistema arrancará automáticamente con Windows.")
        except Exception as e:
            logger.error("No se pudo instalar el servicio: %s", e)
            print(f"\n⚠ No se pudo instalar como servicio: {e}")
            print("  Ejecuta como Administrador para instalar el servicio.")

    elif IS_LINUX:
        service_content = f"""[Unit]
Description=Sentinel SOC — Sistema de Defensa en Red
After=network.target

[Service]
Type=simple
ExecStart={exe} {script} --service
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
"""
        service_path = Path("/etc/systemd/system/sentinel-soc.service")
        try:
            service_path.write_text(service_content)
            os.system("systemctl daemon-reload")
            os.system("systemctl enable sentinel-soc")
            os.system("systemctl start sentinel-soc")
            logger.info("✅ Sentinel SOC instalado como servicio systemd.")
            print("\n✅ Instalado como servicio systemd. Arrancará automáticamente.")
            print("   Estado: systemctl status sentinel-soc")
        except PermissionError:
            print("\n⚠ Necesitas ejecutar como root: sudo python sentinel.py install")

    elif IS_MAC:
        plist = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>com.sentinel.soc</string>
    <key>ProgramArguments</key>
    <array><string>{exe}</string><string>{script}</string><string>--service</string></array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
</dict>
</plist>"""
        plist_path = Path.home() / "Library/LaunchAgents/com.sentinel.soc.plist"
        plist_path.write_text(plist)
        os.system(f"launchctl load {plist_path}")
        print("\n✅ Instalado como LaunchAgent en macOS.")

# ─── INICIO DEL SISTEMA ───────────────────────────────────────────────────────
def print_banner():
    if not IS_WINDOWS:
        os.system("clear")
    print("""
\033[96m╔══════════════════════════════════════════════════════════════╗
║  ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗  ║
║  ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║  ║
║  ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║  ║
║  ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║  ║
║  ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗║
║  ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝║
║                                                              ║
║  \033[92mSOC — Sistema de Monitorización y Defensa en Red v1.0\033[96m      ║
║  \033[97mAutor : Pedro Rodríguez Amaro — Colegio Lagomar DAM 2024/25\033[96m ║
╚══════════════════════════════════════════════════════════════╝\033[0m
""")

def start_system():
    cfg = state["config"]
    print_banner()
    logger.info("Iniciando Sentinel SOC v1.0...")

    # Solicitar API Key si no está configurada
    if not cfg["api_key"]:
        print("\033[96m  Anthropic API Key (Enter para modo simulado):\033[0m ", end="")
        try:
            key = input().strip()
            if key:
                cfg["api_key"] = key
                # Guardar en config
                parser = configparser.ConfigParser()
                parser.read(CONFIG_FILE)
                if "sentinel" not in parser:
                    parser["sentinel"] = {}
                parser["sentinel"]["api_key"] = key
                with open(CONFIG_FILE, "w") as f:
                    parser.write(f)
                print("\033[92m  ✅ API Key guardada.\033[0m\n")
            else:
                print("\033[93m  ⚠  Modo simulado activado.\033[0m\n")
        except (EOFError, KeyboardInterrupt):
            pass

    # Arrancar honeypot listeners
    for port in cfg["honeypot_ports"]:
        threading.Thread(target=run_honeypot_listener, args=(port,), daemon=True).start()
        time.sleep(0.1)

    # Arrancar servidor web SOC
    threading.Thread(target=run_web_server, daemon=True).start()

    time.sleep(1)
    logger.info("✅ Sistema operativo. Panel: http://localhost:%d", cfg["web_port"])

    try:
        webbrowser.open(f"http://localhost:{cfg['web_port']}")
    except Exception:
        pass

    print(f"\n\033[92m{'═'*60}\033[0m")
    print(f"\033[92m  ✅  SENTINEL SOC ACTIVO\033[0m")
    print(f"\033[96m  Panel web: http://localhost:{cfg['web_port']}\033[0m")
    print(f"\033[97m  Honeypot: puertos {cfg['honeypot_ports']}\033[0m")
    print(f"\033[90m  Log: {LOG_FILE}\033[0m")
    print(f"\033[92m{'═'*60}\033[0m\n")
    print("\033[90m  Ctrl+C para detener el sistema.\033[0m\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Sistema detenido por el usuario.")
        print("\n\033[93m  Sistema detenido.\033[0m\n")
        sys.exit(0)

# ─── PUNTO DE ENTRADA ─────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Sentinel SOC — Sistema de Defensa en Red",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Comandos:
  (sin argumentos)   Arranca el sistema interactivamente
  install            Instala como servicio del sistema operativo
  --service          Arranca en modo servicio (sin interacción)
  --apikey KEY       Configura la API Key de Anthropic
  --port PORT        Puerto del panel web (por defecto: 7777)

Ejemplos:
  python sentinel.py
  python sentinel.py install
  python sentinel.py --apikey sk-ant-api03-...
        """
    )
    parser.add_argument("command", nargs="?", help="Comando a ejecutar")
    parser.add_argument("--service", action="store_true", help="Modo servicio")
    parser.add_argument("--apikey", help="API Key de Anthropic")
    parser.add_argument("--port", type=int, help="Puerto del panel web")

    args = parser.parse_args()
    cfg  = load_config()

    if args.apikey:
        cfg["api_key"] = args.apikey
        state["config"]["api_key"] = args.apikey
        logger.info("API Key configurada.")

    if args.port:
        cfg["web_port"] = args.port
        state["config"]["web_port"] = args.port

    if args.command == "install":
        load_config()
        install_service()
        return

    if args.service:
        # Modo servicio: sin interacción, sin banner visual
        for port in cfg["honeypot_ports"]:
            threading.Thread(target=run_honeypot_listener, args=(port,), daemon=True).start()
        threading.Thread(target=run_web_server, daemon=True).start()
        logger.info("Sentinel SOC iniciado en modo servicio.")
        try:
            while True:
                time.sleep(5)
        except KeyboardInterrupt:
            sys.exit(0)
        return

    start_system()

if __name__ == "__main__":
    main()
