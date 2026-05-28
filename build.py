#!/usr/bin/env python3
"""
BUILD.py — Genera el ejecutable de Sentinel SOC
================================================
Ejecuta este script en tu portátil para generar el .exe (Windows)
o el binario (Linux/Mac).

INSTRUCCIONES:
    1. Abre una terminal en esta carpeta
    2. Ejecuta: pip install pyinstaller requests psutil
    3. Ejecuta: python build.py
    4. El ejecutable aparece en la carpeta dist/

REQUISITOS:
    - Python 3.10 o superior
    - pip install pyinstaller requests psutil
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path

BASE = Path(__file__).parent
DIST = BASE / "dist"
BUILD = BASE / "build_tmp"

def run(cmd):
    print(f"  $ {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=False, text=True)
    if result.returncode != 0:
        print(f"  ❌ Error: código {result.returncode}")
        sys.exit(1)

def main():
    print("""
╔══════════════════════════════════════════════════════╗
║  SENTINEL SOC — GENERADOR DE EJECUTABLE              ║
║  Pedro Rodríguez Amaro — Colegio Lagomar DAM 2024/25 ║
╚══════════════════════════════════════════════════════╝
""")

    # Verificar PyInstaller
    try:
        import PyInstaller
        print(f"  ✅ PyInstaller {PyInstaller.__version__} encontrado.")
    except ImportError:
        print("  ❌ PyInstaller no encontrado.")
        print("  Instálalo con: pip install pyinstaller")
        sys.exit(1)

    # Verificar que sentinel.py existe
    sentinel_py = BASE / "sentinel.py"
    panel_html  = BASE / "sentinel_soc_panel.html"

    if not sentinel_py.exists():
        print("  ❌ sentinel.py no encontrado en", BASE)
        sys.exit(1)

    if not panel_html.exists():
        print("  ⚠  sentinel_soc_panel.html no encontrado — el panel web no estará embebido.")
        print("     Coloca el fichero HTML en la misma carpeta y vuelve a ejecutar.")

    print("\n  Generando ejecutable...\n")

    # Limpiar builds anteriores
    for d in [DIST, BUILD]:
        if d.exists():
            shutil.rmtree(d)

    # Determinar nombre del ejecutable
    is_windows = sys.platform.startswith("win")
    exe_name   = "SentinelSOC"

    # Construir comando PyInstaller
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",                        # Un solo ejecutable
        "--name", exe_name,                 # Nombre del ejecutable
        "--distpath", str(DIST),            # Carpeta de salida
        "--workpath", str(BUILD),           # Carpeta temporal
        "--clean",                          # Limpiar cache
        "--noconfirm",                      # No preguntar
        "--log-level", "WARN",              # Solo warnings
    ]

    # Incluir el panel HTML si existe
    if panel_html.exists():
        sep = ";" if is_windows else ":"
        cmd += ["--add-data", f"{panel_html}{sep}."]

    # Icono (si existe)
    icon_path = BASE / "icon.ico" if is_windows else BASE / "icon.icns"
    if icon_path.exists():
        cmd += ["--icon", str(icon_path)]

    # En Windows, opcional: ocultar la consola (descomenta si quieres solo panel web)
    # if is_windows:
    #     cmd += ["--noconsole"]

    cmd.append(str(sentinel_py))

    run(cmd)

    # Resultado
    exe_ext  = ".exe" if is_windows else ""
    exe_path = DIST / f"{exe_name}{exe_ext}"

    if exe_path.exists():
        size_mb = exe_path.stat().st_size / 1024 / 1024
        print(f"""
╔══════════════════════════════════════════════════════╗
║  ✅  EJECUTABLE GENERADO CORRECTAMENTE               ║
╠══════════════════════════════════════════════════════╣
║  Archivo : dist/{exe_name}{exe_ext:<35}║
║  Tamaño  : {size_mb:.1f} MB{' '*44}║
╚══════════════════════════════════════════════════════╝

  Cómo usar el ejecutable:

  Windows:
    Doble clic en SentinelSOC.exe
    O desde terminal: .\\SentinelSOC.exe

  Linux/Mac:
    chmod +x SentinelSOC
    ./SentinelSOC

  Instalar como servicio (arranque automático):
    Windows: .\\SentinelSOC.exe install
    Linux  : sudo ./SentinelSOC install
    Mac    : ./SentinelSOC install

  Configurar API Key:
    .\\SentinelSOC.exe --apikey sk-ant-api03-TU_KEY_AQUI

""")
    else:
        print("  ❌ No se encontró el ejecutable en dist/. Revisa los errores arriba.")
        sys.exit(1)

if __name__ == "__main__":
    main()
