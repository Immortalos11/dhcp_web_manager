import os
import sys
import socket
import sqlite3
import time
import json
import logging
import psutil
import threading
import subprocess
from ipaddress import IPv4Address, IPv4Network, ip_address

from dhcppython.packet import DHCPPacket
from dhcppython import options

from flask import (Flask, render_template, request, jsonify, flash, redirect, url_for)
from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, SelectField, SubmitField
from wtforms.validators import DataRequired, IPAddress, MacAddress, NumberRange, Optional

# Importa network_tools e gestisce la sua disponibilità
try:
    from network_tools import scan_network_for_devices
    network_tools_available = True
except ImportError:
    network_tools_available = False
    print("ATTENZIONE: Modulo 'network_tools.py' non trovato. La funzionalità di Scoperta Rete non sarà disponibile.")


# --- Mappa dei tipi DHCP per logging ---
DHCP_TYPE_MAP = {
    1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE", 
    5: "ACK", 6: "NAK", 7: "RELEASE", 8: "INFORM",
}
DHCP_MESSAGE_TYPE_STR_MAP = {
    1: "DHCPDISCOVER", 2: "DHCPOFFER", 3: "DHCPREQUEST", 4: "DHCPDECLINE",
    5: "DHCPACK", 6: "DHCPNAK", 7: "DHCPRELEASE", 8: "DHCPINFORM",
}

# --- Variabile Globale per il Thread DHCP ---
dhcp_thread = None
dhcp_server_instance = None

# --- Variabili Globali per lo Stato della Scansione Rete ---
scan_in_progress = False
last_scan_results = []
current_scan_network_cidr = None
scan_thread_obj = None
scan_stop_event = None 
scan_lock = threading.Lock()

# --- Configurazione Logging ---
log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('dhcp_server') # Logger principale per l'app
logger.setLevel(logging.INFO) 
if logger.hasHandlers():
    logger.handlers.clear()
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(log_formatter)
logger.addHandler(console_handler)

# --- Database ---
# DB_FILE = "dhcp_server_data.db" # Vecchia riga
DATABASE_DIR = "/data" # Directory per i dati persistenti nel container
DB_FILE = os.environ.get('DATABASE_FILE_PATH', os.path.join(DATABASE_DIR, 'dhcp_server_data.db'))

# Assicurati che la directory /data esista se non usiamo un volume subito
# (anche se con i volumi Docker la crea automaticamente sull'host se non esiste)
# Questa parte è più per esecuzione locale o se il volume non è montato la prima volta
if not os.path.exists(DATABASE_DIR) and os.environ.get('DATABASE_FILE_PATH'):
    try:
        os.makedirs(DATABASE_DIR)
        logger.info(f"Creata directory per database: {DATABASE_DIR}")
    except OSError as e:
        logger.error(f"Impossibile creare directory per database {DATABASE_DIR}: {e}")

def get_db_conn():
    return sqlite3.connect(DB_FILE, check_same_thread=False)

def init_db():
    conn = get_db_conn()
    cursor = conn.cursor()
    cursor.execute('CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT)')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS leases (
            mac_address TEXT PRIMARY KEY, ip_address TEXT NOT NULL UNIQUE,
            lease_start_time INTEGER NOT NULL, lease_end_time INTEGER NOT NULL,
            hostname TEXT, is_static INTEGER DEFAULT 0
        )''')
    cursor.execute('CREATE TABLE IF NOT EXISTS static_reservations (mac_address TEXT PRIMARY KEY, ip_address TEXT NOT NULL UNIQUE)')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp REAL NOT NULL,
            level TEXT NOT NULL, message TEXT NOT NULL
        )''')
    conn.commit()
    conn.close()

class DatabaseLogger(logging.Handler):
    def emit(self, record):
        conn = get_db_conn()
        cursor = conn.cursor()
        try:
            # Usa il formattatore del logger principale per consistenza
            msg = logger.handlers[0].formatter.format(record) if logger.handlers else record.getMessage()
            # Estrai solo il messaggio effettivo se il formattatore standard è usato
            msg_only = msg.split(' - ', 2)[-1] if ' - ' in msg and len(msg.split(' - ', 2)) == 3 else msg
            
            cursor.execute("INSERT INTO logs (timestamp, level, message) VALUES (?, ?, ?)",
                           (record.created, record.levelname, msg_only))
            cursor.execute("DELETE FROM logs WHERE id NOT IN (SELECT id FROM logs ORDER BY timestamp DESC LIMIT 500)")
            conn.commit()
        except Exception as e:
            print(f"Errore logging DB: {e}") # Errore critico, stampa su console
        finally:
            if conn:
                conn.close()

db_log_handler = DatabaseLogger()
db_log_handler.setFormatter(log_formatter) # Usa lo stesso formattatore
logger.addHandler(db_log_handler)

def get_config(key, default=None):
    conn = get_db_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT value FROM config WHERE key = ?", (key,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else default

def set_config(key, value):
    conn = get_db_conn()
    cursor = conn.cursor()
    cursor.execute("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", (key, str(value)))
    conn.commit()
    conn.close()

def normalize_mac(mac_string):
    if isinstance(mac_string, str):
        return mac_string.replace(":", "").replace("-", "").lower().strip()
    if isinstance(mac_string, bytes):
        try:
            return mac_string.decode('utf-8').replace(":", "").replace("-", "").lower().strip()
        except UnicodeDecodeError:
            return "".join([f"{b:02x}" for b in mac_string]).lower()
    return mac_string 

def format_mac_for_display(mac_input_str):
    normalized = normalize_mac(mac_input_str)
    if isinstance(normalized, str) and len(normalized) == 12:
        try:
            int(normalized, 16) # Valida se è esadecimale
            return ":".join(normalized[i:i+2] for i in range(0, 12, 2))
        except ValueError:
            return mac_input_str # Ritorna l'input se la normalizzazione fallisce
    return mac_input_str

def get_static_reservations():
    conn = get_db_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT mac_address, ip_address FROM static_reservations ORDER BY ip_address")
    rows = cursor.fetchall()
    conn.close()
    return {normalize_mac(r[0]): r[1] for r in rows if normalize_mac(r[0])}


def add_static_reservation(mac, ip_str_new):
    conn = get_db_conn()
    cursor = conn.cursor()
    original_mac_input = mac
    normalized_mac_target = normalize_mac(mac)
    
    try:
        new_ip_obj = IPv4Address(ip_str_new)
    except ValueError:
        logger.error(f"Tentativo di aggiungere prenotazione con IP non valido: {ip_str_new}")
        flash(f"L'indirizzo IP '{ip_str_new}' non è valido.", "danger")
        return False

    if not normalized_mac_target or len(normalized_mac_target) != 12:
        logger.error(f"Formato MAC non valido dopo normalizzazione per prenotazione: '{original_mac_input}' -> '{normalized_mac_target}'")
        flash(f"Il formato del MAC address '{original_mac_input}' non è valido.", "danger")
        return False
    try:
        query_check_reservation = "SELECT mac_address FROM static_reservations WHERE ip_address = ? AND mac_address != ?"
        cursor.execute(query_check_reservation, (str(new_ip_obj), normalized_mac_target))
        existing_reservation_for_ip_row = cursor.fetchone()
        
        if existing_reservation_for_ip_row:
            conflicting_mac_normalized = normalize_mac(existing_reservation_for_ip_row[0])
            logger.error(f"Errore: IP {new_ip_obj} è già prenotato staticamente per MAC {format_mac_for_display(conflicting_mac_normalized)}.")
            flash(f"L'IP {new_ip_obj} è già prenotato staticamente per un altro MAC: {format_mac_for_display(conflicting_mac_normalized)}.", "danger")
            if conn: conn.close() 
            return False
        
        query_check_lease = "SELECT mac_address FROM leases WHERE ip_address = ? AND mac_address != ? AND is_static = 0 AND lease_end_time > ?"
        cursor.execute(query_check_lease, (str(new_ip_obj), normalized_mac_target, int(time.time())))
        active_dynamic_lease_for_ip_row = cursor.fetchone()
        if active_dynamic_lease_for_ip_row:
            conflicting_mac_normalized = normalize_mac(active_dynamic_lease_for_ip_row[0])
            logger.warning(f"Attenzione: IP {new_ip_obj} è attualmente un lease dinamico attivo per MAC {format_mac_for_display(conflicting_mac_normalized)}. Creando una prenotazione statica si potrebbe causare un conflitto temporaneo.")
            flash(f"Attenzione: l'IP {new_ip_obj} è attualmente un lease dinamico attivo per MAC {format_mac_for_display(conflicting_mac_normalized)}. La prenotazione statica verrà creata, ma potrebbe esserci un conflitto temporaneo. Il dispositivo {format_mac_for_display(conflicting_mac_normalized)} dovrà rilasciare/rinnovare il suo IP.", "warning")

        cursor.execute("INSERT OR REPLACE INTO static_reservations (mac_address, ip_address) VALUES (?, ?)", (normalized_mac_target, str(new_ip_obj)))
        
        cursor.execute("SELECT ip_address, is_static FROM leases WHERE mac_address = ?", (normalized_mac_target,))
        current_lease_row = cursor.fetchone()
        if current_lease_row:
            current_leased_ip_for_target_mac = IPv4Address(current_lease_row[0])
            is_lease_static = bool(current_lease_row[1])
            if current_leased_ip_for_target_mac != new_ip_obj:
                logger.info(f"MAC {format_mac_for_display(normalized_mac_target)} ha un lease attivo per {current_leased_ip_for_target_mac}. Verrà rimosso a seguito della nuova prenotazione per {new_ip_obj}.")
                cursor.execute("DELETE FROM leases WHERE mac_address = ?", (normalized_mac_target,))
            elif not is_lease_static :
                 logger.info(f"MAC {format_mac_for_display(normalized_mac_target)} ha già {current_leased_ip_for_target_mac} (dinamico). Il lease verrà aggiornato a statico.")
                 cursor.execute("UPDATE leases SET is_static = 1 WHERE mac_address = ?", (normalized_mac_target,))
        
        conn.commit()
        logger.info(f"Aggiunta/Aggiornata prenotazione: MAC_NORM='{normalized_mac_target}' (Originale:'{format_mac_for_display(original_mac_input)}') = {new_ip_obj}")
        return True
    except sqlite3.Error as e:
        logger.error(f"Errore DB aggiungendo prenotazione MAC='{original_mac_input}', IP='{ip_str_new}': {e}")
        flash(f"Errore Database: {e}", "danger")
        return False
    finally:
        if conn:
            conn.close()

def remove_static_reservation(mac):
    conn = get_db_conn()
    cursor = conn.cursor()
    original_mac_input = mac
    normalized_mac = normalize_mac(mac)
    
    logger.info(f"Tentativo di rimozione prenotazione. Input originale: '{format_mac_for_display(original_mac_input)}', Normalizzato a: '{normalized_mac}'")
    
    rows_affected = 0 
    try:
        cursor.execute("DELETE FROM static_reservations WHERE mac_address = ?", (normalized_mac,))
        rows_affected = cursor.rowcount 
        conn.commit()
        
        if rows_affected > 0:
            logger.info(f"Prenotazione per MAC_NORM='{normalized_mac}' (Originale:'{format_mac_for_display(original_mac_input)}') RIMOSSA con successo. Righe modificate: {rows_affected}")
        else:
            logger.warning(f"Nessuna prenotazione trovata nel DB per MAC_NORM='{normalized_mac}' (Originale:'{format_mac_for_display(original_mac_input)}') durante il tentativo di rimozione. Righe modificate: {rows_affected}")

    except sqlite3.Error as e:
        logger.error(f"Errore DB durante la rimozione della prenotazione per MAC='{format_mac_for_display(original_mac_input)}': {e}")
        if conn:
            conn.rollback() 
    finally:
        if conn:
            conn.close()
    return rows_affected

def get_all_leases():
    conn = get_db_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT mac_address, ip_address, lease_end_time, hostname, is_static FROM leases ORDER BY ip_address")
    rows = cursor.fetchall()
    conn.close()
    return rows

def get_logs_from_db(limit=100):
    conn = get_db_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT timestamp, level, message FROM logs ORDER BY timestamp DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [{"time": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(r[0])), "level": r[1], "message": r[2]} for r in reversed(rows)]

# --- DHCP Server Thread ---
class DhcpServerThread(threading.Thread):
    def __init__(self):
        super().__init__()
        self._running = threading.Event()
        self.sock = None
        self.config = {}
        self.daemon = True

    def load_config(self):
        try:
            raw_static_reservations = get_static_reservations()
            current_static_reservations = {
                normalize_mac(k): IPv4Address(v) for k, v in raw_static_reservations.items() if normalize_mac(k)
            }
            self.config = {
                'server_ip': IPv4Address(get_config('server_ip', '192.168.1.1')),
                'interface': get_config('interface', '0.0.0.0'),
                'subnet_mask': IPv4Address(get_config('subnet_mask', '255.255.255.0')),
                'gateway': IPv4Address(get_config('gateway', '192.168.1.1')),
                'dns_servers_str': [str(ip_obj) for ip_obj in [IPv4Address(ip) for ip in json.loads(get_config('dns_servers', '["8.8.8.8"]'))]],
                'lease_time': int(get_config('lease_time', '3600')),
                'pool_start': IPv4Address(get_config('pool_start', '192.168.1.100')),
                'pool_end': IPv4Address(get_config('pool_end', '192.168.1.200')),
                'static_reservations': current_static_reservations,
            }
            self.config['subnet'] = IPv4Network(f"{self.config['pool_start']}/{self.config['subnet_mask']}", strict=False)
            logger.info("Configurazione caricata nel thread DHCP.")
            return True
        except Exception as e:
            logger.error(f"Errore caricamento/parsing configurazione DHCP: {e}", exc_info=True)
            return False

    def _get_lease_by_mac(self, mac_normalized):
        conn = get_db_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT ip_address, lease_end_time FROM leases WHERE mac_address = ?", (mac_normalized,))
        row = cursor.fetchone()
        conn.close()
        return row

    def _get_lease_by_ip(self, ip):
        conn = get_db_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT mac_address, lease_end_time FROM leases WHERE ip_address = ?", (str(ip),))
        row = cursor.fetchone()
        conn.close()
        return row

    def _add_or_update_lease(self, mac_normalized, ip, lease_duration, hostname=None, is_static=False):
        start_time = int(time.time())
        end_time = start_time + lease_duration
        conn = get_db_conn()
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT OR REPLACE INTO leases (mac_address, ip_address, lease_start_time, lease_end_time, hostname, is_static)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (mac_normalized, str(ip), start_time, end_time, hostname, 1 if is_static else 0))
            conn.commit()
            logger.info(f"Lease: MAC={format_mac_for_display(mac_normalized)}, IP={ip}, Host={hostname or 'N/A'}, Static={is_static}")
        except sqlite3.Error as e:
            logger.error(f"Errore DB Lease {mac_normalized}: {e}")
        finally:
            conn.close()

    def _find_available_ip(self):
        conn = get_db_conn()
        cursor = conn.cursor()
        current_time = int(time.time())
        cursor.execute("DELETE FROM leases WHERE lease_end_time < ? AND is_static = 0", (current_time,))
        conn.commit()
        cursor.execute("SELECT ip_address FROM leases")
        used_ips = {IPv4Address(row[0]) for row in cursor.fetchall()}
        conn.close()
        used_ips.update(self.config['static_reservations'].values())
        used_ips.add(self.config['server_ip'])
        used_ips.add(self.config['gateway'])
        for ip_int in range(int(self.config['pool_start']), int(self.config['pool_end']) + 1):
            ip = IPv4Address(ip_int)
            if ip not in used_ips:
                return ip
        return None

    def _handle_discover(self, packet, client_mac_normalized):
        offered_ip = None
        if client_mac_normalized in self.config['static_reservations']:
            ip_from_reservation = self.config['static_reservations'][client_mac_normalized]
            lease_on_reserved_ip = self._get_lease_by_ip(ip_from_reservation)
            if not lease_on_reserved_ip or normalize_mac(lease_on_reserved_ip[0]) == client_mac_normalized:
                offered_ip = ip_from_reservation
                logger.info(f"OFFER: {format_mac_for_display(client_mac_normalized)} -> {offered_ip} (Da prenotazione statica)")
            else:
                 logger.warning(f"IP statico {ip_from_reservation} per {format_mac_for_display(client_mac_normalized)} è attualmente in lease da un altro MAC: {format_mac_for_display(lease_on_reserved_ip[0])}!")
                 offered_ip = None
        
        if not offered_ip:
            existing_lease_for_mac = self._get_lease_by_mac(client_mac_normalized)
            if existing_lease_for_mac and existing_lease_for_mac[1] > time.time():
                 current_ip_in_lease = IPv4Address(existing_lease_for_mac[0])
                 if client_mac_normalized in self.config['static_reservations'] and \
                    self.config['static_reservations'][client_mac_normalized] != current_ip_in_lease:
                     logger.info(f"OFFER (differito): {format_mac_for_display(client_mac_normalized)} ha lease per {current_ip_in_lease}, ma prenotazione per {self.config['static_reservations'][client_mac_normalized]}. Non si offre ora.")
                     return None
                 else:
                    offered_ip = current_ip_in_lease
                    logger.info(f"OFFER: {format_mac_for_display(client_mac_normalized)} -> {offered_ip} (Rinnovo lease esistente)")
            
            if not offered_ip:
                offered_ip = self._find_available_ip()
                if offered_ip:
                    logger.info(f"OFFER: {format_mac_for_display(client_mac_normalized)} -> {offered_ip} (Nuovo dinamico)")
                else:
                    logger.warning(f"Nessun IP disponibile per {format_mac_for_display(client_mac_normalized)}")
                    return None
        
        opt_list = options.OptionList()
        opt_list.append(options.options.short_value_to_object(53, DHCP_MESSAGE_TYPE_STR_MAP[2]))
        opt_list.append(options.options.short_value_to_object(1, str(self.config['subnet_mask'])))
        opt_list.append(options.options.short_value_to_object(3, [str(self.config['gateway'])])) 
        if self.config['dns_servers_str']:
            opt_list.append(options.options.short_value_to_object(6, self.config['dns_servers_str']))
        opt_list.append(options.options.short_value_to_object(51, self.config['lease_time']))
        opt_list.append(options.options.short_value_to_object(54, str(self.config['server_ip'])))

        offer = DHCPPacket(
            op="BOOTREPLY", 
            htype=packet.htype,
            hlen=packet.hlen,
            hops=0,
            xid=packet.xid,
            secs=0,
            flags=packet.flags,
            ciaddr=IPv4Address('0.0.0.0'),
            yiaddr=offered_ip,
            siaddr=self.config['server_ip'],
            giaddr=IPv4Address('0.0.0.0'),
            chaddr=packet.chaddr,
            sname=b'',
            file=b'',
            options=opt_list
        )
        return offer

    def _handle_request(self, packet, client_mac_normalized):
        requested_ip_opt = packet.options.by_code(50)
        server_id_opt = packet.options.by_code(54)
        
        if server_id_opt and IPv4Address(server_id_opt.data) != self.config['server_ip']:
            logger.debug(f"Richiesta per un altro server ID ({IPv4Address(server_id_opt.data)}), ignorata.")
            return None

        if requested_ip_opt:
            requested_ip = IPv4Address(requested_ip_opt.data)
        elif packet.ciaddr != IPv4Address('0.0.0.0'):
            requested_ip = packet.ciaddr
        else:
            logger.warning(f"REQUEST da {format_mac_for_display(client_mac_normalized)} senza IP richiesto (opzione 50) o ciaddr valido.")
            return None 

        logger.info(f"REQUEST: {format_mac_for_display(client_mac_normalized)} chiede {requested_ip}")
        can_assign, is_static = False, False
        
        if client_mac_normalized in self.config['static_reservations']:
            reserved_ip_for_client = self.config['static_reservations'][client_mac_normalized]
            if requested_ip == reserved_ip_for_client:
                can_assign, is_static = True, True
            else:
                logger.warning(f"NAK per {format_mac_for_display(client_mac_normalized)}: richiede {requested_ip} ma ha prenotazione per {reserved_ip_for_client}.")
                can_assign = False
        elif (self.config['pool_start'] <= requested_ip <= self.config['pool_end']):
            lease_on_requested_ip = self._get_lease_by_ip(requested_ip)
            if not lease_on_requested_ip or normalize_mac(lease_on_requested_ip[0]) == client_mac_normalized:
                can_assign, is_static = True, False 
            else:
                logger.warning(f"NAK per {format_mac_for_display(client_mac_normalized)}: IP richiesto {requested_ip} è in uso da {format_mac_for_display(lease_on_requested_ip[0])}.")
                can_assign = False
        else:
            logger.warning(f"NAK per {format_mac_for_display(client_mac_normalized)}: IP richiesto {requested_ip} fuori range o non valido.")
            can_assign = False
        
        if can_assign:
            hostname_opt = packet.options.by_code(12)
            hostname = hostname_opt.data.decode('ascii', errors='ignore') if hostname_opt else None
            self._add_or_update_lease(client_mac_normalized, requested_ip, self.config['lease_time'], hostname, is_static)
            
            opt_list_ack = options.OptionList()
            opt_list_ack.append(options.options.short_value_to_object(53, DHCP_MESSAGE_TYPE_STR_MAP[5]))
            opt_list_ack.append(options.options.short_value_to_object(1, str(self.config['subnet_mask'])))
            opt_list_ack.append(options.options.short_value_to_object(3, [str(self.config['gateway'])]))
            if self.config['dns_servers_str']:
                opt_list_ack.append(options.options.short_value_to_object(6, self.config['dns_servers_str']))
            opt_list_ack.append(options.options.short_value_to_object(51, self.config['lease_time']))
            opt_list_ack.append(options.options.short_value_to_object(54, str(self.config['server_ip'])))

            ack = DHCPPacket(
                op="BOOTREPLY",
                htype=packet.htype,
                hlen=packet.hlen,
                hops=0,
                xid=packet.xid,
                secs=0,
                flags=packet.flags,
                ciaddr=requested_ip, 
                yiaddr=requested_ip,
                siaddr=self.config['server_ip'],
                giaddr=packet.giaddr if packet.giaddr != IPv4Address('0.0.0.0') else IPv4Address('0.0.0.0'),
                chaddr=packet.chaddr,
                sname=b'',
                file=b'',
                options=opt_list_ack
            )
            logger.info(f"ACK: {format_mac_for_display(client_mac_normalized)} -> {requested_ip}")
            return ack
        else: 
            logger.warning(f"Invio NAK a {format_mac_for_display(client_mac_normalized)} per IP {requested_ip}")
            
            opt_list_nak = options.OptionList()
            opt_list_nak.append(options.options.short_value_to_object(53, DHCP_MESSAGE_TYPE_STR_MAP[6]))
            opt_list_nak.append(options.options.short_value_to_object(54, str(self.config['server_ip'])))

            nak = DHCPPacket(
                op="BOOTREPLY",
                htype=packet.htype,
                hlen=packet.hlen,
                hops=0,
                xid=packet.xid,
                secs=0,
                flags=packet.flags, 
                ciaddr=IPv4Address('0.0.0.0'),
                yiaddr=IPv4Address('0.0.0.0'),
                siaddr=IPv4Address('0.0.0.0'),
                giaddr=packet.giaddr if packet.giaddr != IPv4Address('0.0.0.0') else IPv4Address('0.0.0.0'),
                chaddr=packet.chaddr,
                sname=b'',
                file=b'',
                options=opt_list_nak
            )
            return nak

    def run(self):
        if not self.load_config():
            logger.error("Configurazione DHCP non valida. Thread non avviato.")
            return

        self._running.set()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.settimeout(1.0)

        bind_ip = self.config['interface']
        try:
            self.sock.bind((bind_ip, 67))
            logger.info(f"Server DHCP in ascolto su {bind_ip}:67")
        except OSError as e:
            logger.error(f"Errore Bind su {bind_ip}:67: {e}. (Admin? Porta in uso?)")
            self._running.clear()
            self.sock = None
            return

        while self._running.is_set():
            try:
                data, addr = self.sock.recvfrom(1024)
                packet = DHCPPacket.from_bytes(data)
                msg_type_opt = packet.options.by_code(53)
                if not msg_type_opt: continue

                msg_type_code = msg_type_opt.data[0]
                msg_type_name = DHCP_TYPE_MAP.get(msg_type_code, f"UNKNOWN({msg_type_code})")
                
                client_mac_normalized = normalize_mac(packet.chaddr) 
                
                logger.info(f"Ricevuto {msg_type_name} da MAC: {format_mac_for_display(client_mac_normalized)} (Originale: {packet.chaddr})")

                response = None
                if msg_type_code == 1: # DISCOVER
                    response = self._handle_discover(packet, client_mac_normalized)
                elif msg_type_code == 3: # REQUEST
                    response = self._handle_request(packet, client_mac_normalized)

                if response:
                    dest_ip = '255.255.255.255'
                    if packet.giaddr != IPv4Address('0.0.0.0'):
                        dest_ip = str(packet.giaddr)
                    
                    self.sock.sendto(response.asbytes, (dest_ip, 68))

            except socket.timeout:
                continue
            except Exception as e:
                logger.error(f"Errore nel loop DHCP: {e}", exc_info=True)

        if self.sock:
             self.sock.close()
        self.sock = None
        logger.info("Server DHCP fermato.")

    def stop(self):
        logger.info("Richiesta di arresto server DHCP...")
        self._running.clear()

    def is_running(self):
        return self._running.is_set()

# --- Flask App ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'sostituisci-con-una-chiave-veramente-segreta-e-casuale'

@app.context_processor
def inject_global_vars():
    return dict(
        active_page=request.endpoint, 
        network_tools_available=network_tools_available 
    )

def get_interfaces():
    ifaces = [('0.0.0.0', '0.0.0.0 (Tutte - Rischioso!)')]
    try:
        addrs = psutil.net_if_addrs()
        for iface, snics in addrs.items():
            for snic in snics:
                if snic.family == socket.AF_INET:
                    ifaces.append((snic.address, f"{iface} ({snic.address})"))
    except Exception as e:
        logger.error(f"Impossibile elencare interfacce: {e}")
    return ifaces

# --- Forms (Flask-WTF) ---
class ConfigForm(FlaskForm):
    interface = SelectField('Interfaccia di Ascolto', choices=[], validators=[DataRequired()]) # choices verranno popolate dinamicamente
    server_ip = StringField('IP Server', validators=[DataRequired(), IPAddress(message="IP Server non valido.")])
    subnet_mask = StringField('Subnet Mask', validators=[DataRequired(), IPAddress(message="Subnet Mask non valida.")])
    gateway = StringField('Gateway', validators=[DataRequired(), IPAddress(message="Gateway non valido.")])
    dns_servers = StringField('Server DNS (separati da ,)', validators=[DataRequired()])
    lease_time = IntegerField('Durata Lease (sec)', validators=[DataRequired(), NumberRange(min=60, message="Lease time minimo 60s.")])
    pool_start = StringField('Inizio Pool', validators=[DataRequired(), IPAddress(message="IP Inizio Pool non valido.")])
    pool_end = StringField('Fine Pool', validators=[DataRequired(), IPAddress(message="IP Fine Pool non valido.")])
    submit = SubmitField('Salva Configurazione')

    def validate_dns_servers(self, field):
        try:
            [IPv4Address(ip.strip()) for ip in field.data.split(',') if ip.strip()]
        except Exception:
            raise ValueError("Uno o più server DNS non sono indirizzi IP validi.")

class ReservationForm(FlaskForm):
    mac_address = StringField('MAC Address (es. AA:BB:CC:00:11:22)', validators=[DataRequired(), MacAddress(message="MAC Address non valido.")])
    ip_address = StringField('Indirizzo IP', validators=[DataRequired(), IPAddress(message="Indirizzo IP non valido.")])
    submit = SubmitField('Aggiungi/Aggiorna')

# --- Routes ---
@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/config', methods=['GET', 'POST'])
def config_route(): 
    form = ConfigForm()
    form.interface.choices = get_interfaces()

    if form.validate_on_submit():
        if dhcp_thread and dhcp_thread.is_running():
             flash('Arrestare il server prima di modificare la configurazione.', 'warning')
        else:
            try:
                start = IPv4Address(form.pool_start.data)
                end = IPv4Address(form.pool_end.data)
                if start >= end:
                    flash('L\'IP di inizio pool deve essere minore di quello di fine.', 'danger')
                    return render_template('config.html', form=form)

                dns_list = [str(IPv4Address(ip.strip())) for ip in form.dns_servers.data.split(',') if ip.strip()]

                set_config('interface', form.interface.data)
                set_config('server_ip', form.server_ip.data)
                set_config('subnet_mask', form.subnet_mask.data)
                set_config('gateway', form.gateway.data)
                set_config('dns_servers', json.dumps(dns_list))
                set_config('lease_time', form.lease_time.data)
                set_config('pool_start', form.pool_start.data)
                set_config('pool_end', form.pool_end.data)
                flash('Configurazione salvata con successo.', 'success')
                logger.info("Configurazione salvata via Web UI.")
                return redirect(url_for('config_route'))
            except Exception as e:
                flash(f'Errore nel salvataggio: {e}', 'danger')

    elif request.method == 'GET':
        form.interface.data = get_config('interface', '0.0.0.0')
        form.server_ip.data = get_config('server_ip', '192.168.56.10')
        form.subnet_mask.data = get_config('subnet_mask', '255.255.255.0')
        form.gateway.data = get_config('gateway', '192.168.56.1')
        form.dns_servers.data = ','.join(json.loads(get_config('dns_servers', '["8.8.8.8"]')))
        form.lease_time.data = int(get_config('lease_time', '3600'))
        form.pool_start.data = get_config('pool_start', '192.168.56.100')
        form.pool_end.data = get_config('pool_end', '192.168.56.200')
    else: 
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"Errore nel campo '{getattr(form, field).label.text}': {error}", 'danger')

    return render_template('config.html', form=form)

@app.route('/reservations')
def reservations():
    form = ReservationForm()
    static_res_raw = get_static_reservations()
    static_res_display = {format_mac_for_display(mac): ip for mac, ip in static_res_raw.items()}
    return render_template('reservations.html', reservations=static_res_display, form=form)

@app.route('/reservations/add', methods=['POST'])
def add_reservation_route():
    form = ReservationForm()
    if form.validate_on_submit():
        if add_static_reservation(form.mac_address.data, form.ip_address.data):
            flash_msg = f'Prenotazione aggiunta/aggiornata per {format_mac_for_display(form.mac_address.data)} a {form.ip_address.data}.'
            if not (dhcp_thread and dhcp_thread.is_running()):
                flash_msg += " Avviare il server DHCP per applicare."
            else:
                flash_msg += " Riavviare il server DHCP per rendere la modifica pienamente operativa."
            flash(flash_msg, 'success')
        else:
            if not any(True for _ in app.jinja_env.globals['get_flashed_messages'](with_categories=True, category_filter=['danger','warning'])):
                 flash('Errore durante l\'aggiunta della prenotazione.', 'danger')
    else:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"Errore nel campo '{getattr(form, field).label.text}': {error}", 'danger')
    return redirect(url_for('reservations'))

@app.route('/reservations/remove', methods=['POST'])
def remove_reservation_route():
    mac_from_form = request.form.get('mac_address')
    
    rows_deleted = 0 
    if mac_from_form:
        rows_deleted = remove_static_reservation(mac_from_form)
        
    if rows_deleted > 0:
        flash_msg = f'Prenotazione per {format_mac_for_display(mac_from_form)} rimossa con successo.'
        if not (dhcp_thread and dhcp_thread.is_running()):
             flash_msg += " Avviare il server DHCP per rendere operativa la modifica."
        else:
            flash_msg += " Riavviare il server DHCP per rendere pienamente operativa la modifica."
        flash(flash_msg, 'success')
    elif mac_from_form : 
        flash(f'Nessuna prenotazione trovata per MAC {format_mac_for_display(mac_from_form)} da rimuovere.', 'warning')
    else: 
        flash('MAC address non specificato per la rimozione.', 'danger')
    return redirect(url_for('reservations'))

if network_tools_available:
    @app.route('/discovery')
    def discovery_page():
        default_subnet = ""
        try:
            server_ip_str = get_config('server_ip', '192.168.1.1')
            subnet_mask_str = get_config('subnet_mask', '255.255.255.0')
            if server_ip_str and subnet_mask_str:
                network = IPv4Network(f"{server_ip_str}/{subnet_mask_str}", strict=False)
                default_subnet = f"{network.network_address}/{network.prefixlen}"
        except Exception as e:
            logger.warning(f"Impossibile calcolare subnet di default per scansione: {e}")
        return render_template('discovery.html', default_subnet=default_subnet)

    @app.route('/api/start_network_scan', methods=['POST'])
    def api_start_network_scan():
        global scan_in_progress, last_scan_results, scan_thread_obj, scan_stop_event, current_scan_network_cidr, scan_lock

        with scan_lock:
            if scan_in_progress:
                return jsonify({"status": "error", "message": f"Una scansione è già in corso per {current_scan_network_cidr}."}), 409
        
        data = request.get_json()
        network_to_scan = data.get('network_cidr')

        if not network_to_scan:
            try:
                server_ip_str = get_config('server_ip')
                subnet_mask_str = get_config('subnet_mask')
                if server_ip_str and subnet_mask_str:
                    network = IPv4Network(f"{server_ip_str}/{subnet_mask_str}", strict=False)
                    network_to_scan = str(network.with_prefixlen)
                else:
                    return jsonify({"status": "error", "message": "Range di rete non specificato e configurazione DHCP server non trovata."}), 400
            except Exception as e:
                logger.error(f"Errore nel determinare la rete di scansione dalla configurazione: {e}")
                return jsonify({"status": "error", "message": "Errore nel determinare la rete di scansione."}), 500
        
        logger.info(f"Richiesta scansione rete per: {network_to_scan}")
        
        def scan_thread_target(app_context, net_cidr, stop_event_ref):
            global last_scan_results, scan_in_progress, current_scan_network_cidr, scan_thread_obj, scan_lock
            with app_context: 
                logger.info(f"Thread di scansione avviato per {net_cidr}")
                results = scan_network_for_devices(net_cidr, stop_event_ref) 
                with scan_lock:
                    last_scan_results = results
                    for device in last_scan_results: 
                         if device.get("mac") and device["mac"] != "N/A":
                            device["mac_display"] = format_mac_for_display(device["mac"])
                         else:
                            device["mac_display"] = "N/A"
                    scan_in_progress = False
                    # Non resettare current_scan_network_cidr qui, così la UI sa quale scansione è finita
                    scan_thread_obj = None 
                logger.info(f"Thread di scansione per {net_cidr} completato/interrotto. Risultati: {len(last_scan_results)}")

        with scan_lock:
            scan_in_progress = True
            last_scan_results = [] 
            current_scan_network_cidr = network_to_scan
            scan_stop_event = threading.Event()
            
            app_context = app.app_context()
            scan_thread_obj = threading.Thread(target=scan_thread_target, args=(app_context, network_to_scan, scan_stop_event))
            scan_thread_obj.daemon = True
            scan_thread_obj.start()

        return jsonify({"status": "ok", "message": f"Scansione di rete per {network_to_scan} avviata in background."})

    @app.route('/api/scan_status', methods=['GET'])
    def api_scan_status():
        global scan_in_progress, current_scan_network_cidr, last_scan_results, scan_lock
        with scan_lock:
            return jsonify({
                "in_progress": scan_in_progress,
                "network_cidr": current_scan_network_cidr, 
                "has_results": bool(last_scan_results) and not scan_in_progress 
            })

    @app.route('/api/get_last_scan_results', methods=['GET'])
    def api_get_last_scan_results():
        global last_scan_results, scan_lock
        with scan_lock:
            results_to_send = []
            for device in last_scan_results:
                dev_copy = device.copy()
                if dev_copy.get("mac") and dev_copy["mac"] != "N/A" and not dev_copy.get("mac_display"):
                    dev_copy["mac_display"] = format_mac_for_display(dev_copy["mac"])
                elif not dev_copy.get("mac_display"):
                     dev_copy["mac_display"] = "N/A"
                results_to_send.append(dev_copy)
            return jsonify({"status": "ok", "devices": results_to_send})


    @app.route('/api/stop_network_scan', methods=['POST'])
    def api_stop_network_scan():
        global scan_in_progress, scan_thread_obj, scan_stop_event, scan_lock
        with scan_lock:
            if scan_in_progress and scan_stop_event:
                logger.info("Richiesta di interruzione scansione rete via API...")
                scan_stop_event.set()
                return jsonify({"status": "ok", "message": "Richiesta di interruzione scansione inviata."})
            elif not scan_in_progress:
                return jsonify({"status": "ok", "message": "Nessuna scansione attualmente in corso."})
            else: 
                return jsonify({"status": "error", "message": "Impossibile interrompere la scansione (stato inconsistente)."}), 500
# --- API Routes Esistenti ---
@app.route('/api/status')
def api_status():
    global dhcp_thread
    return jsonify({"running": dhcp_thread is not None and dhcp_thread.is_running()})

@app.route('/api/leases')
def api_leases():
    leases = get_all_leases()
    return jsonify([
        {"mac": format_mac_for_display(l[0]), "ip": l[1], "end_time": l[2], "hostname": l[3], "is_static": bool(l[4])}
        for l in leases
    ])

@app.route('/api/logs')
def api_logs():
    return jsonify(get_logs_from_db())

@app.route('/api/start', methods=['POST'])
def api_start():
    global dhcp_thread, dhcp_server_instance
    if dhcp_thread and dhcp_thread.is_running():
        return jsonify({"status": "error", "message": "Server già attivo"}), 400

    logger.info("Richiesta di avvio server via Web UI...")
    dhcp_server_instance = DhcpServerThread()
    dhcp_thread = dhcp_server_instance
    dhcp_thread.start()
    time.sleep(1.5) 
    if dhcp_server_instance.is_running() and dhcp_server_instance.sock is not None:
         return jsonify({"status": "ok", "message": "Server DHCP avviato."})
    else:
         dhcp_thread = None
         dhcp_server_instance = None
         logger.error("Avvio server DHCP fallito. Controllare i log e la configurazione (es. permessi, interfaccia corretta).")
         return jsonify({"status": "error", "message": "Avvio server DHCP fallito. Controllare i log per dettagli."}), 500

@app.route('/api/stop', methods=['POST'])
def api_stop():
    global dhcp_thread, dhcp_server_instance
    if not dhcp_thread or not dhcp_thread.is_running():
        return jsonify({"status": "error", "message": "Server non attivo"}), 400

    logger.info("Richiesta di arresto server via Web UI...")
    dhcp_server_instance.stop()
    dhcp_thread.join(timeout=5)
    if dhcp_thread.is_alive():
        logger.warning("Il thread DHCP non si è fermato entro il timeout.")
    dhcp_thread = None
    dhcp_server_instance = None
    return jsonify({"status": "ok", "message": "Server DHCP fermato."})

def is_valid_ip(ip_str):
    try:
        ip_address(ip_str)
        return True
    except ValueError:
        return False

@app.route('/api/ping/<ip_address_str>')
def api_ping(ip_address_str):
    if not is_valid_ip(ip_address_str):
        logger.warning(f"Tentativo di ping verso un indirizzo non valido: {ip_address_str}")
        return jsonify({"status": "error", "output": "Indirizzo IP non valido."}), 400

    logger.info(f"Esecuzione ping verso: {ip_address_str}")
    
    num_pings_str = "5"
    num_pings_int = int(num_pings_str)
    ping_timeout_per_packet_ms_str = "1000" 
    
    subprocess_timeout_seconds = num_pings_int * (int(ping_timeout_per_packet_ms_str) / 1000) + 3 
    if subprocess_timeout_seconds < 7: subprocess_timeout_seconds = 7

    if sys.platform == "win32":
        command = ["ping", "-n", num_pings_str, "-w", ping_timeout_per_packet_ms_str, ip_address_str]
    else:
        command = ["ping", "-c", num_pings_str, "-W", "1", ip_address_str]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=subprocess_timeout_seconds, 
            check=False
        )
        output = f"--- Eseguendo: {' '.join(command)} ---\n"
        output += f"--- Codice Uscita: {result.returncode} ---\n\n"
        output += result.stdout
        output += result.stderr

        if result.returncode == 0:
             logger.info(f"Ping {ip_address_str}: Successo")
             return jsonify({"status": "ok", "output": output})
        else:
             logger.warning(f"Ping {ip_address_str}: Fallito o Timeout (codice uscita: {result.returncode})")
             return jsonify({"status": "error", "output": output})

    except subprocess.TimeoutExpired:
        logger.error(f"Ping {ip_address_str}: Timeout subprocess ({subprocess_timeout_seconds}s) scaduto!")
        return jsonify({"status": "error", "output": f"Ping timeout ({subprocess_timeout_seconds} secondi)."}), 500
    except FileNotFoundError:
         logger.error("Comando 'ping' non trovato. Assicurati che sia nel PATH.")
         return jsonify({"status": "error", "output": "Comando 'ping' non trovato."}), 500
    except Exception as e:
        logger.error(f"Errore generico ping {ip_address_str}: {e}", exc_info=True)
        return jsonify({"status": "error", "output": f"Errore: {e}"}), 500

@app.route('/api/set_lease_ip', methods=['POST'])
def set_lease_ip():
    data = request.get_json()
    if not data:
        return jsonify({"status": "error", "message": "Dati JSON non validi o mancanti."}), 400
        
    mac_address = data.get('mac_address')
    new_ip_address = data.get('new_ip_address')

    if not mac_address or not new_ip_address:
        return jsonify({"status": "error", "message": "MAC address e nuovo IP sono richiesti."}), 400

    try:
        IPv4Address(new_ip_address) 
    except ValueError:
        return jsonify({"status": "error", "message": f"Il nuovo indirizzo IP '{new_ip_address}' non è valido."}), 400
    
    normalized_mac = normalize_mac(mac_address) 
    if not normalized_mac or len(normalized_mac) != 12:
        return jsonify({"status": "error", "message": f"Formato MAC address '{mac_address}' non valido."}), 400

    if add_static_reservation(normalized_mac, new_ip_address): 
        flash_message = (f"Prenotazione statica per MAC {format_mac_for_display(normalized_mac)} "
                         f"impostata/aggiornata a {new_ip_address}. "
                         f"ARRESTARE e RIAVVIARE il server DHCP (dalla tab 'Controllo Server') "
                         f"e far rinnovare il lease al client per applicare la modifica.")
        flash(flash_message, 'info')
        return jsonify({"status": "ok", "message": "Prenotazione statica impostata/aggiornata. Vedi messaggio sopra per i passaggi successivi."})
    else:
        if not any(True for _ in app.jinja_env.globals['get_flashed_messages'](with_categories=True, category_filter=['danger','warning'])):
            flash(f"Impossibile impostare la prenotazione per MAC {format_mac_for_display(normalized_mac)} a {new_ip_address}. Controllare i log.", 'danger')
        return jsonify({"status": "error", "message": f"Impossibile impostare prenotazione per {format_mac_for_display(normalized_mac)}. Controllare i log."}), 500

# --- Main ---
if __name__ == '__main__':
    try:
        init_db()
        if network_tools_available: 
             logger.info("Modulo network_tools.py caricato.")
        
        logger.info("Applicazione Web DHCP Manager avviata.")
        print("*" * 60)
        print("ATTENZIONE: Eseguire Flask in questo modo NON è per produzione.")
        print("           L'interfaccia è accessibile su http://<TUO_IP>:5000")
        print("           Questa interfaccia NON HA AUTENTICAZIONE.")
        print("           Il server DHCP richiede permessi ADMIN per partire.")
        print("*" * 60)
        app.run(host='0.0.0.0', port=5000, debug=False)
    except Exception as e:
        logger.error(f"Errore fatale nell'applicazione: {e}", exc_info=True)
        print(f"ERRORE FATALE: {e}")
    finally:
        input("\nIl programma è terminato. Premi Invio per chiudere questa finestra...")

