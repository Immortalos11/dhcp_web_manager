import subprocess
import sys
import re
import time
from ipaddress import ip_network, ip_address
import socket # Per gethostbyaddr
import logging
import threading # Per threading.Event

logger = logging.getLogger('dhcp_server.network_tools')
if not logger.handlers:
    logger.setLevel(logging.DEBUG)
    # handler = logging.StreamHandler(sys.stdout)
    # handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
    # logger.addHandler(handler)
    # logger.propagate = False

def run_command(command, timeout=5):
    """Esegue un comando di sistema e restituisce il suo output."""
    try:
        use_shell = sys.platform == "win32"
        process = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False, shell=use_shell, creationflags=subprocess.CREATE_NO_WINDOW if use_shell else 0)
        return process.stdout + process.stderr
    except subprocess.TimeoutExpired:
        logger.warning(f"Comando '{' '.join(command if isinstance(command, list) else command)}' timeout dopo {timeout}s")
        return "Comando timeout"
    except Exception as e:
        logger.error(f"Errore esecuzione comando '{' '.join(command if isinstance(command, list) else command)}': {e}")
        return f"Errore esecuzione comando: {e}"

def parse_arp_table(arp_output, target_ip_str=None):
    mac_addresses = {}
    pattern = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?(([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})")
    
    for line in arp_output.splitlines():
        match = pattern.search(line) # Rimosso .lower() qui, il pattern regex gestisce A-F e a-f
        if match:
            ip = match.group(1)
            mac = match.group(2).replace("-", ":").lower() # Normalizza MAC dopo il match
            mac_addresses[ip] = mac
            if target_ip_str and ip == target_ip_str:
                return mac
    
    if target_ip_str:
        return mac_addresses.get(target_ip_str)
    return mac_addresses

def scan_network_for_devices(network_cidr, stop_event: threading.Event = None):
    discovered_devices_dict = {} 
    
    if stop_event is None:
        stop_event = threading.Event()

    original_timeout = socket.getdefaulttimeout() # Salva il timeout globale all'inizio

    try:
        net = ip_network(network_cidr, strict=False)
        logger.info(f"Inizio scansione rete per {network_cidr} (fino a {net.num_addresses} host). Interrompere se necessario.")
        hosts_to_scan = [str(host) for host in net.hosts()]
        
        total_hosts = len(hosts_to_scan)
        for i, ip_str in enumerate(hosts_to_scan):
            if stop_event.is_set():
                logger.info(f"Scansione rete interrotta dall'utente a IP {ip_str} (ping).")
                break 
            
            if i % 25 == 0 or i == total_hosts - 1 : 
                logger.info(f"Fase Ping: IP {i+1}/{total_hosts}: {ip_str}")

            ping_command = ["ping", "-n", "1", "-w", "200", ip_str] if sys.platform == "win32" else ["ping", "-c", "1", "-W", "0.2", "-i", "0.1", ip_str]
            status = "Offline"
            
            try:
                result = subprocess.run(ping_command, capture_output=True, text=True, timeout=0.3, check=False, shell=sys.platform=="win32", creationflags=subprocess.CREATE_NO_WINDOW if sys.platform=="win32" else 0)
                if result.returncode == 0:
                    status = "Online"
                    discovered_devices_dict[ip_str] = {"ip": ip_str, "mac": "In attesa ARP...", "hostname": "In attesa DNS...", "status": status}
            except subprocess.TimeoutExpired:
                logger.debug(f"Ping a {ip_str} timeout.")
            except Exception as e:
                logger.error(f"Errore pingando {ip_str}: {e}")
        
        if stop_event.is_set():
            logger.info("Scansione ping interrotta. Procedo con ARP e DNS per gli IP trovati finora.")
        else:
            logger.info(f"Completati i ping. {len(discovered_devices_dict)} IPs hanno risposto. Ora cerco MAC e Hostname...")

        if not discovered_devices_dict:
            logger.info("Nessun IP attivo trovato dalla scansione ping.")
            socket.setdefaulttimeout(original_timeout) # Ripristina timeout prima di uscire
            return []

        time.sleep(0.5) 
        arp_table_output = run_command(["arp", "-a"], timeout=10)
        arp_macs = parse_arp_table(arp_table_output)

        active_ips_list = list(discovered_devices_dict.keys())
        total_active = len(active_ips_list)
        for i, ip_to_check in enumerate(active_ips_list):
            if stop_event.is_set():
                logger.info("Recupero MAC/Hostname interrotto dall'utente.")
                break
            
            if i % 10 == 0 or i == total_active -1:
                 logger.info(f"Fase ARP/DNS: Dispositivo {i+1}/{total_active}: {ip_to_check}")

            device_entry = discovered_devices_dict[ip_to_check]
            device_entry["mac"] = arp_macs.get(ip_to_check, "N/A (Non in ARP)")
            
            try:
                socket.setdefaulttimeout(0.5) # Timeout breve per questa specifica risoluzione DNS
                hostname, _, _ = socket.gethostbyaddr(ip_to_check)
                device_entry["hostname"] = hostname
            except socket.herror:
                device_entry["hostname"] = "N/A (Reverse DNS fallito)"
            except socket.timeout:
                device_entry["hostname"] = "N/A (Timeout DNS)"
            except Exception: 
                device_entry["hostname"] = "N/A (Errore DNS)"
            finally:
                socket.setdefaulttimeout(original_timeout) # Ripristina sempre il timeout originale
        
        final_devices_list = list(discovered_devices_dict.values())
        if stop_event.is_set():
             logger.info(f"Scansione rete interrotta. Analizzati parzialmente {len(final_devices_list)} dispositivi.")
        else:
            logger.info(f"Scansione rete completata. Analizzati {len(final_devices_list)} dispositivi che hanno risposto al ping.")
        return final_devices_list

    except ValueError:
        logger.error(f"Formato CIDR rete non valido: {network_cidr}")
        socket.setdefaulttimeout(original_timeout) # Ripristina timeout in caso di errore iniziale
        return [{"ip": "Errore", "mac": "Formato CIDR non valido", "hostname": "", "status": ""}]
    except Exception as e:
        logger.error(f"Errore durante la scansione della rete: {e}", exc_info=True)
        socket.setdefaulttimeout(original_timeout) # Ripristina timeout in caso di errore generale
        return [{"ip": "Errore", "mac": str(e), "hostname": "", "status": ""}]
    finally:
        socket.setdefaulttimeout(original_timeout) # Assicura che il timeout globale venga ripristinato

