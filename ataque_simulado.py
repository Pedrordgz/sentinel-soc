#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║     SIMULADOR DE ATAQUE — DEMO TRIBUNAL                          ║
║     Ejecutar en una SEGUNDA TERMINAL mientras sentinel_demo.py   ║
║     está corriendo en la primera                                 ║
╚══════════════════════════════════════════════════════════════════╝

CÓMO USAR:
    Terminal 1: python sentinel_demo.py   (ya corriendo)
    Terminal 2: python ataque_simulado.py  (este script)
"""

import socket
import time
import sys
import os

# ─── COLORES ──────────────────────────────────────────────────────────────────
if sys.platform == "win32":
    os.system("color")

RESET  = "\033[0m";  BOLD   = "\033[1m";  DIM = "\033[2m"
RED    = "\033[31m"; GREEN  = "\033[32m"; YELLOW = "\033[33m"
CYAN   = "\033[36m"; WHITE  = "\033[37m"
BRIGHT_RED  = "\033[91m"; BRIGHT_GREEN = "\033[92m"
BRIGHT_YELLOW = "\033[93m"; BRIGHT_CYAN = "\033[96m"
BG_RED = "\033[41m"

# ─── CONFIGURACIÓN ────────────────────────────────────────────────────────────
TARGET_IP   = "127.0.0.1"  # localhost (el honeypot está en la misma máquina)
SCAN_PORTS  = [21, 22, 80] # puertos a "escanear" (los del honeypot)
ALT_PORTS   = [2021, 2022, 2080]  # alternativos si los primeros están en modo sin privilegios

def print_attacker_banner():
    os.system("cls" if sys.platform == "win32" else "clear")
    print(f"""
{BRIGHT_RED}╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   {BOLD}SIMULADOR DE ATAQUE — NMAP -sV{RESET}{BRIGHT_RED}                               ║
║                                                              ║
║   {WHITE}Este script simula un atacante ejecutando Nmap{BRIGHT_RED}              ║
║   {WHITE}para escanear puertos y detectar servicios.{BRIGHT_RED}                 ║
║                                                              ║
║   {BRIGHT_YELLOW}⚠  SOLO PARA FINES EDUCATIVOS — ENTORNO CONTROLADO{BRIGHT_RED}      ║
╚══════════════════════════════════════════════════════════════╝{RESET}
""")

def ts():
    import datetime
    return datetime.datetime.now().strftime("%H:%M:%S.%f")[:11]

def scan_port(ip, port, timeout=2):
    """Intenta conectar a un puerto y devuelve el banner recibido."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        try:
            banner = s.recv(256)
        except socket.timeout:
            banner = b""
        s.close()
        return True, banner.decode("utf-8", errors="replace").strip()
    except (ConnectionRefusedError, socket.timeout, OSError):
        return False, ""

def main():
    print_attacker_banner()

    print(f"{BRIGHT_CYAN}  [{ts()}] Iniciando simulación de ataque...{RESET}")
    print(f"  {DIM}IP objetivo: {TARGET_IP}{RESET}")
    print(f"  {DIM}Puertos objetivo: {SCAN_PORTS}{RESET}")
    print(f"\n  {BRIGHT_YELLOW}Observa la Terminal 1 y el panel web — verás la detección en tiempo real{RESET}\n")
    print(f"{BRIGHT_RED}{'─'*62}{RESET}")

    time.sleep(1.5)

    print(f"\n{BRIGHT_RED}  [{ts()}] $ nmap -sV {TARGET_IP}{RESET}")
    print(f"  {DIM}Starting Nmap 7.94 ( https://nmap.org ){RESET}\n")
    time.sleep(1)

    # Intentar puertos normales primero, luego alternativos
    ports_to_try = [(p, p_alt) for p, p_alt in zip(SCAN_PORTS, ALT_PORTS)]
    successful_ports = []

    for normal_port, alt_port in ports_to_try:
        # Primero intentar el puerto normal
        port_to_use = normal_port
        open_ok, banner = scan_port(TARGET_IP, normal_port, timeout=1)

        if not open_ok:
            # Intentar el alternativo
            open_ok, banner = scan_port(TARGET_IP, alt_port, timeout=1)
            if open_ok:
                port_to_use = alt_port

        service_names = {21: "ftp", 22: "ssh", 80: "http", 2021: "ftp", 2022: "ssh", 2080: "http"}
        svc = service_names.get(port_to_use, "unknown")

        if open_ok:
            successful_ports.append(port_to_use)
            print(f"  {BRIGHT_GREEN}[{ts()}] Puerto {port_to_use}/tcp ABIERTO  {svc:<6}  {banner[:50]}{RESET}")
        else:
            print(f"  {DIM}[{ts()}] Puerto {normal_port}/tcp cerrado{RESET}")

        time.sleep(0.8)

    if not successful_ports:
        print(f"\n  {BRIGHT_YELLOW}⚠  No se encontraron puertos abiertos.{RESET}")
        print(f"  {DIM}Asegúrate de que sentinel_demo.py está corriendo en la Terminal 1.{RESET}\n")
        return

    print(f"\n  {BRIGHT_YELLOW}Nmap scan report for {TARGET_IP}{RESET}")
    print(f"  {WHITE}Host is up (0.00012s latency).{RESET}")
    print(f"  {WHITE}{len(successful_ports)} port(s) open{RESET}\n")

    # Segunda pasada — escaneo más agresivo para activar el umbral
    print(f"{BRIGHT_RED}  [{ts()}] Segunda pasada — detección de versiones (-sV)...{RESET}\n")
    time.sleep(0.5)

    for port in successful_ports:
        _, banner = scan_port(TARGET_IP, port)
        if banner:
            print(f"  {BRIGHT_RED}[{ts()}] Fingerprint detectado en {port}/tcp: {banner[:60]}{RESET}")
        time.sleep(0.4)

    # Tercera conexión para superar el umbral de Riesgo Alto
    print(f"\n{BRIGHT_RED}  [{ts()}] Verificación adicional de servicios...{RESET}\n")
    time.sleep(0.3)

    for port in successful_ports:
        scan_port(TARGET_IP, port, timeout=1)
        print(f"  {BRIGHT_RED}[{ts()}] Reconexión a {port}/tcp completada{RESET}")
        time.sleep(0.3)

    print(f"\n{BRIGHT_RED}{'═'*62}{RESET}")
    print(f"{BRIGHT_RED}{BOLD}  ⚡  ESCANEO COMPLETADO — OBSERVA LA TERMINAL 1{RESET}")
    print(f"{BRIGHT_RED}{'═'*62}{RESET}")
    print(f"\n  {WHITE}El sistema de defensa debería haber:{RESET}")
    print(f"  {GREEN}  ✓ Detectado las conexiones al honeypot{RESET}")
    print(f"  {GREEN}  ✓ Correlacionado los hits temporalmente{RESET}")
    print(f"  {GREEN}  ✓ Clasificado el riesgo como ALTO{RESET}")
    print(f"  {GREEN}  ✓ Consultado al motor de IA{RESET}")
    print(f"  {GREEN}  ✓ Bloqueado esta IP automáticamente{RESET}")
    print(f"\n  {DIM}Revisa la Terminal 1 y el panel web para ver los detalles.{RESET}\n")

if __name__ == "__main__":
    main()
