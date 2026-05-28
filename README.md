# SENTINEL SOC v1.0
## Sistema de Monitorización y Defensa en Red
### Pedro Rodríguez Amaro — Colegio Lagomar DAM 2024/2025

---

## ¿Qué es Sentinel SOC?

Sentinel SOC es un sistema de detección y respuesta ante intrusiones diseñado para PYMEs. Detecta escaneos de red, identifica comportamientos anómalos mediante honeypots, consulta a un motor de Inteligencia Artificial para analizar cada incidente, y bloquea automáticamente las amenazas confirmadas — todo sin intervención humana.

---

## GENERAR EL EJECUTABLE (hazlo en tu portátil)

### Paso 1 — Instala las dependencias

```
pip install pyinstaller requests psutil
```

### Paso 2 — Coloca todos estos archivos en la misma carpeta:
```
sentinel.py
sentinel_soc_panel.html
build.py
README.md
```

### Paso 3 — Ejecuta el builder

```
python build.py
```

### Resultado

Aparece la carpeta `dist/` con:
- `SentinelSOC.exe` (Windows)
- `SentinelSOC` (Linux/Mac)

---

## USAR EL EJECUTABLE

### Arranque básico

```
# Windows — doble clic o:
SentinelSOC.exe

# Linux/Mac:
chmod +x SentinelSOC
./SentinelSOC
```

Al arrancar te pide la API Key de Anthropic. Si la tienes, la pegas. Si no, Enter para modo simulado.

El panel SOC se abre automáticamente en el navegador en http://localhost:7777

### Configurar API Key permanentemente

```
SentinelSOC.exe --apikey sk-ant-api03-TU_KEY_AQUI
```

### Instalar como servicio (arranca automáticamente con el sistema)

```
# Windows (como Administrador):
SentinelSOC.exe install

# Linux (como root):
sudo ./SentinelSOC install

# Mac:
./SentinelSOC install
```

### Puerto personalizado

```
SentinelSOC.exe --port 8080
```

---

## ARQUITECTURA DEL PRODUCTO

```
SentinelSOC.exe
│
├── Honeypot (puertos 21, 22, 80)
│   └── Simula FTP, SSH, HTTP con banners reales
│
├── Motor de Correlación
│   └── Ventana deslizante 5000ms · umbral 3 hits
│
├── Motor de IA (Claude API)
│   └── Analiza contexto · decide BLOCK o MONITOR
│
├── Canal de Mitigación
│   └── iptables (Linux) · netsh (Windows)
│
└── Panel SOC Web (localhost:7777)
    └── Dashboard en tiempo real · chat con IA
```

---

## MODELO DE NEGOCIO

| Plan | Precio | Incluye |
|------|--------|---------|
| PYME Basic | 25 €/mes | 1 servidor · soporte email |
| PYME Pro | 49 €/mes | 5 servidores · alertas Telegram |
| Enterprise | 199 €/mes | Ilimitado · SLA 99.9% · soporte 24/7 |

---

## PARA EL DÍA DE LA DEFENSA

1. Genera el ejecutable en casa con `python build.py`
2. Copia `SentinelSOC.exe` a tu portátil
3. Ante el tribunal: doble clic → el sistema arranca → panel web se abre
4. Pulsa "Simular Ataque" → el tribunal ve la IA en acción

El ejecutable es completamente autónomo. Sin Python, sin dependencias, sin configuración. Un doble clic.
