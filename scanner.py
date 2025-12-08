import ipaddress       # для роботи з підмережами типу 192.168.0.0/24
import subprocess      # для запуску системної команди ping


def ping_host(ip):
    """
    Перевіряє, чи відповідає хост на ping.
    Повертає True, якщо є відповідь, і False, якщо ні.
    """
    result = subprocess.run(
        ["ping", "-n", "1", "-w", "200", ip],  # 1 пакет, таймаут 200 мс
        stdout=subprocess.DEVNULL,            # не показуємо текст ping
        stderr=subprocess.DEVNULL
    )
    return result.returncode == 0  # 0 = успіх (є відповідь)


def scan_network(network_cidr):
    """
    Сканує підмережу (наприклад, '192.168.0.0/24')
    і повертає список IP-адрес, які відповіли на ping.
    """
    network = ipaddress.ip_network(network_cidr, strict=False)
    alive_hosts = []

    print("Сканування підмережі:", network_cidr)

    for ip in network.hosts():     # перебираємо всі можливі адреси хостів
        ip_str = str(ip)
        print(f"Перевіряю {ip_str} ... ", end="")

        if ping_host(ip_str):
            print("АКТИВНИЙ")
            alive_hosts.append(ip_str)
        else:
            print("немає відповіді")

    return alive_hosts
