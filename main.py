from scanner import scan_network


def main():
    print("Прототип сканера локальної мережі")
    network = input("Введіть підмережу (наприклад, 192.168.0.0/24): ").strip()

    if network == "":
        # якщо нічого не ввели – беремо підмережу за замовчуванням
        network = "192.168.0.0/24"
        print("Порожній ввід → використовую підмережу за замовчуванням:", network)

    hosts = scan_network(network)

    print("\n--- РЕЗУЛЬТАТ ---")
    if not hosts:
        print("Активних хостів не знайдено.")
    else:
        print(f"Знайдено {len(hosts)} активних хостів:")
        for ip in hosts:
            print(" -", ip)


if __name__ == "__main__":
    main()
