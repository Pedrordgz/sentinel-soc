# 🛡️ GUÍA COMPLETA DE USO — SENTINEL SOC
## Todo lo que necesitas saber para el día de la defensa
### Pedro Rodríguez Amaro — Colegio Lagomar DAM 2024/2025

---

## 📦 QUÉ HAY EN ESTE ZIP

```
demo/
├── sentinel_demo.py      ← EL SISTEMA PRINCIPAL (Terminal 1)
├── ataque_simulado.py    ← EL ATACANTE (Terminal 2)
└── GUIA_USO.md           ← Esta guía
```

---

## 🔑 ANTES DEL DÍA DE LA DEFENSA (hazlo en casa)

### Paso 1 — Instala las dependencias

Abre una terminal y escribe:
```
pip install requests
```

Eso es todo. No necesitas instalar nada más.

### Paso 2 — Consigue tu API Key de Anthropic

1. Ve a https://console.anthropic.com
2. Inicia sesión con tu cuenta (la misma que usas en Claude)
3. En el menú izquierdo, busca "API Keys"
4. Crea una nueva key
5. Cópiala — empieza por `sk-ant-api03-...`

⚠️ IMPORTANTE: Guarda esa key. La vas a necesitar el día de la defensa.

### Paso 3 — Pruébalo en casa

Sigue los mismos pasos que harás el día de la defensa (sección siguiente).
Así llegas con todo probado y sin sorpresas.

---

## 🎯 EL DÍA DE LA DEFENSA — PASO A PASO

### 5 minutos antes de entrar al tribunal:

**Abre DOS terminales** (CMD o PowerShell en Windows):
- Terminal 1: navega hasta la carpeta del zip
- Terminal 2: navega hasta la misma carpeta

Para navegar: `cd C:\TFG\demo` (o donde hayas descomprimido el zip)

---

### TERMINAL 1 — El sistema de defensa

Escribe:
```
python sentinel_demo.py
```

El sistema te pedirá tu API Key. Pégala y pulsa Enter.

Verás esto:
```
╔══════════════════════════════════════════════════════════════╗
║     SENTINEL SOC — DEMO EN VIVO                              ║
╚══════════════════════════════════════════════════════════════╝

  Honeypot FTP escuchando en puerto 21...
  Honeypot SSH escuchando en puerto 22...
  Honeypot HTTP escuchando en puerto 80...
  Orquestador TCP escuchando en puerto 9999...
  Panel SOC disponible en http://localhost:7777

✅ SISTEMA OPERATIVO — TODOS LOS AGENTES ACTIVOS
```

**El navegador se abrirá solo** con el panel SOC visual.

---

### CUANDO LLEGUE EL MOMENTO EN LA PRESENTACIÓN:

Di algo como:
> *"Voy a mostrarles el sistema funcionando en tiempo real.
> En esta pantalla ven el Panel SOC — el cerebro visual del sistema.
> Ahora voy a simular un atacante escaneando nuestra red."*

---

### TERMINAL 2 — El atacante simulado

Escribe:
```
python ataque_simulado.py
```

El "atacante" empieza a escanear. El tribunal ve en tiempo real cómo:

1. 🍯 El honeypot detecta las conexiones
2. ⚡ El orquestador correlaciona los eventos
3. 🚨 El sistema clasifica el riesgo como ALTO
4. 🤖 La IA recibe el contexto y analiza el incidente
5. 🔒 La IP queda bloqueada automáticamente

**En la Terminal 1** verás todo el flujo con colores, animaciones y el razonamiento real de la IA.

**En el navegador** el panel SOC se actualiza solo con métricas, logs y la decisión de la IA.

---

## 🎤 QUÉ DECIR MIENTRAS OCURRE

Mientras el ataque se detecta, puedes ir explicando:

**Cuando aparece "HIT honeypot":**
> *"El atacante acaba de conectarse al servicio FTP falso.
> El honeypot le ha enviado un banner que parece real —
> el atacante cree que ha encontrado un servidor ProFTPD legítimo."*

**Cuando aparece "Riesgo ALTO":**
> *"El orquestador ha detectado que esta misma IP
> ha contactado tres servicios distintos en menos de 5 segundos.
> Eso es un patrón de escaneo sistemático — comportamiento de atacante."*

**Cuando aparece "Invocando motor de IA":**
> *"Aquí está el elemento diferencial del sistema.
> En lugar de aplicar una regla fija, le preguntamos a la Inteligencia Artificial.
> Le enviamos el contexto completo del incidente."*

**Cuando aparece la decisión de la IA:**
> *"La IA ha analizado el patrón y ha decidido: BLOCK.
> Y aquí está su razonamiento — en lenguaje natural, auditable,
> que cualquier persona puede entender. Esto es lo que diferencia
> este sistema de un firewall tradicional."*

**Cuando aparece "IP BLOQUEADA":**
> *"Bloqueo ejecutado. Desde este momento, ningún paquete
> de ese atacante llega a nuestros sistemas.
> Todo esto ha ocurrido en menos de 5 segundos,
> sin ninguna intervención humana."*

---

## ❓ SI ALGO FALLA

### "Puerto 21 no disponible":
Normal en Windows sin permisos de administrador.
El sistema usa automáticamente los puertos 2021, 2022, 2080.
El ataque simulado los detecta solo. No tienes que cambiar nada.

### "API no disponible":
El sistema entra en modo simulado y usa una respuesta predefinida.
La demo sigue funcionando perfectamente.
Puedes decirle al tribunal: *"La API está usando caché local por seguridad."*

### El panel web no se abre:
Abre manualmente el navegador y ve a: http://localhost:7777

### Nada funciona:
Cierra todo, vuelve a abrir las terminales, y ejecuta de nuevo.
El sistema es resistente y arranca desde cero sin problemas.

---

## 💡 CONSEJO PARA LA DEFENSA

**No corras.** Deja que el tribunal vea cada paso.
Las animaciones de color en la terminal son espectaculares —
el tribunal nunca ha visto esto antes aunque no entiendan el código.

**Señala la pantalla** cuando ocurra cada cosa importante.
No tienes que explicar el código. Solo lo que hace.

**Si el tribunal pregunta "¿cómo funciona la IA?":**
> *"La IA recibe el contexto completo del incidente en formato JSON:
> la IP del atacante, los puertos contactados, los timestamps,
> los banners intercambiados. Con todo eso, decide si el patrón
> es un ataque real o actividad legítima, y justifica su decisión
> en lenguaje natural que queda registrado en el log forense."*

---

## 📋 CHECKLIST DEL DÍA DE LA DEFENSA

- [ ] Portátil cargado (lleva el cargador)
- [ ] ZIP descomprimido en C:\TFG\demo\
- [ ] `pip install requests` ejecutado
- [ ] API Key copiada en algún lugar accesible (bloc de notas)
- [ ] Probado en casa que todo funciona
- [ ] Presentación PowerPoint lista
- [ ] Navegador Chrome/Edge listo (no Firefox — puede tener problemas con localhost)
- [ ] DOS terminales abiertas antes de entrar

---

¡Mucha suerte, Pedro. Esto va a ser una barbaridad. 🚀
