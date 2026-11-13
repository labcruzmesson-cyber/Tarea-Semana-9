import json
import re
import os
from netmiko import ConnectHandler

def audit_cisco(net_connect, name, mode):
    results = []
    print(f"[*] Auditando Cisco IOS: {name}")
    run_conf = net_connect.send_command("show running-config")
    vty_conf = net_connect.send_command("show running-config | section line vty")
    
    # 1. Encriptación de contraseñas (Regex anclado al inicio de línea para evadir los "no service...")
    if re.search(r'^service password-encryption', run_conf, re.MULTILINE):
        results.append("- **[PASS]** Encriptación de contraseñas habilitada (`service password-encryption`).")
    else:
        results.append("- **[FAIL]** Falta habilitar la encriptación de contraseñas.")
        
    # 2. SSH versión 2 (Misma evasión con Regex)
    if re.search(r'^ip ssh version 2', run_conf, re.MULTILINE):
        results.append("- **[PASS]** SSH versión 2 forzado correctamente.")
    else:
        results.append("- **[FAIL]** SSH versión 2 no está forzado explícitamente.")
        
    # 3. Timeout VTY (Permite espacios al inicio porque los subcomandos en Cisco se indentan)
    if re.search(r'^\s*exec-timeout 5 0', vty_conf, re.MULTILINE):
        results.append("- **[PASS]** Timeout de sesión CLI/VTY configurado a 5 minutos.")
    else:
        results.append("- **[FAIL]** Timeout de sesión VTY incorrecto o ausente.")
        
    if mode == "apply":
        if not os.path.exists("configs"):
            os.makedirs("configs")
        with open(f"configs/{name}_running_config.txt", "w") as f:
            f.write(run_conf)
        print(f"[+] Running-Config guardado para {name}")
            
    return results

def audit_fortigate(net_connect, name, mode):
    results = []
    print(f"[*] Auditando FortiGate: {name}")
    
    # Usamos "get" en lugar de "show" para forzar a FortiOS a revelar los valores ocultos por defecto
    admin_timeout = net_connect.send_command("get system global | grep admintimeout")
    banner = net_connect.send_command("get system global | grep pre-login-banner")
    sys_intf = net_connect.send_command("show system interface port2")
    
    # 4. Timeout Admin
    if re.search(r'admintimeout\s*:\s*5\b', admin_timeout) or "set admintimeout 5" in admin_timeout:
        results.append("- **[PASS]** Timeout de administrador configurado a 5 minutos.")
    else:
        results.append("- **[FAIL]** Timeout de administrador incorrecto o no configurado en 5 min.")
        
    # 5. Banner Pre-login
    if "enable" in banner:
        results.append("- **[PASS]** Banner de advertencia pre-login habilitado.")
    else:
        results.append("- **[FAIL]** Banner de advertencia pre-login deshabilitado.")
        
    # 6. Protocolos Inseguros en port2
    if re.search(r'set allowaccess.*(?:telnet|\bhttp\b)', sys_intf):
        results.append("- **[FAIL]** Protocolos inseguros (Telnet/HTTP) encontrados en port2.")
    else:
        results.append("- **[PASS]** Sin protocolos de gestión inseguros en port2.")

    if mode == "apply":
        full_conf = net_connect.send_command("show full-configuration")
        if not os.path.exists("configs"):
            os.makedirs("configs")
        with open(f"configs/{name}_running_config.txt", "w") as f:
            f.write(full_conf)
        print(f"[+] Configuración completa guardada para {name}")
            
    return results

def remediate_cisco(net_connect, name):
    print(f"[!] Aplicando Hardening a Cisco IOS: {name}...")
    commands = [
        "service password-encryption",
        "ip ssh version 2",
        "line vty 0 4",
        "exec-timeout 5 0"
    ]
    net_connect.send_config_set(commands)
    net_connect.save_config()

def remediate_fortigate(net_connect, name):
    print(f"[!] Aplicando Hardening a FortiGate: {name}...")
    commands = [
        "config system global",
        "set admintimeout 5",
        "set pre-login-banner enable",
        "end",
        "config system interface",
        "edit port2",
        "set allowaccess ping ssh https",
        "next",
        "end"
    ]
    net_connect.send_config_set(commands)

def main():
    while True:
        print("\n" + "="*45)
        print("   HERRAMIENTA DE AUDITORÍA Y HARDENING CIS")
        print("="*45)
        print("1. Crear informe sin aplicar reglas (Auditoría)")
        print("2. Aplicar reglas, generar informe póstumo y respaldar configs")
        print("3. Salir")
        
        opcion = input("\nSeleccione una opción (1-3): ")
        
        if opcion == "3":
            print("Saliendo del programa...")
            break
        elif opcion not in ["1", "2"]:
            print("Opción inválida. Intente de nuevo.")
            continue
            
        mode = "audit" if opcion == "1" else "apply"

        try:
            with open("devices.json", "r") as f:
                devices = json.load(f)
        except FileNotFoundError:
            print("[-] Error: No se encontró devices.json.")
            return

        report_title = "Póstumo (Remediado)" if mode == "apply" else "Inicial (Sin Remediación)"
        report = f"# Informe {report_title} de Auditoría CIS Benchmark\n\n"
        filename = "informe_postumo.md" if mode == "apply" else "informe_auditoria.md"

        for dev in devices:
            name = dev.pop("name")
            try:
                net_connect = ConnectHandler(**dev)
                
                if mode == "apply":
                    if "cisco_ios" in dev["device_type"]:
                        net_connect.enable()
                        remediate_cisco(net_connect, name)
                    elif "fortinet" in dev["device_type"]:
                        remediate_fortigate(net_connect, name)

                report += f"## Dispositivo: {name} (IP: {dev['ip']})\n"
                if "cisco_ios" in dev["device_type"]:
                    if mode == "audit": net_connect.enable()
                    res = audit_cisco(net_connect, name, mode)
                elif "fortinet" in dev["device_type"]:
                    res = audit_fortigate(net_connect, name, mode)
                    
                report += "\n".join(res) + "\n\n"
                net_connect.disconnect()
                print(f"[+] Proceso completado para {name}")
                
            except Exception as e:
                print(f"[-] Error con {name}: {e}")
                report += f"## Dispositivo: {name}\n- **[ERROR]** Fallo de conexión.\n\n"

        with open(filename, "w") as f:
            f.write(report)
            
        print(f"\n[✔] Finalizado. Revisa el archivo generado: '{filename}'")
        if mode == "apply":
            print("[✔] Running-Configs guardados en el directorio '/configs/'")

if __name__ == "__main__":
    main()