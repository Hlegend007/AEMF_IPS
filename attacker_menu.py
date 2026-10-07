"""Interactive Shadow attack menu for an isolated Kali lab VM."""

from shadow.attacks import HTTP_DESYNC_PAYLOADS, ICMP_TUNNEL_PAYLOADS, Shadow

DESYNC_VARIANTS = tuple(HTTP_DESYNC_PAYLOADS)
ICMP_VARIANTS = tuple(ICMP_TUNNEL_PAYLOADS)


def send_attack(shadow, attack, target, interface, source, variant=None):
    attack_name = variant or attack
    layers = ["base64"] if attack_name == "icmp" else []
    plan = shadow.build(
        attack_name,
        layers=layers,
        fragment_size=4 if attack_name == "icmp" else 8,
        out_of_order=True,
    )
    print(f"Sending {attack_name.upper()} test traffic to {target}")
    shadow.send_live(plan, target, iface=interface, src_ip=source or None)
    print(f"{attack_name.upper()} test complete")


def main():
    shadow = Shadow()
    target = input("Ubuntu defender IP [192.168.56.20]: ").strip() or "192.168.56.20"
    interface = input("Kali Host-only interface [enp0s8]: ").strip() or "enp0s8"
    source = input("Kali source IP [192.168.56.10]: ").strip() or "192.168.56.10"

    while True:
        print("\nAEMF Shadow attack menu")
        print("1. Send ICMP baseline test")
        print("2. Send one ICMP tunnel variant")
        print("3. Send all ICMP tunnel variants")
        print("4. Send HTTP splitter baseline test")
        print("5. Send one HTTP desync variant")
        print("6. Send all HTTP desync variants")
        print("7. Send both baseline tests")
        print("0. Exit")
        choice = input("Select an option: ").strip()

        if choice == "1":
            send_attack(shadow, "icmp", target, interface, source)
        elif choice == "2":
            print("Available variants: " + ", ".join(ICMP_VARIANTS))
            variant = input("Variant: ").strip().lower()
            if variant in ICMP_VARIANTS:
                send_attack(shadow, "icmp", target, interface, source, variant)
            else:
                print("Unknown variant.")
        elif choice == "3":
            for variant in ICMP_VARIANTS:
                send_attack(shadow, "icmp", target, interface, source, variant)
        elif choice == "4":
            send_attack(shadow, "http", target, interface, source)
        elif choice == "5":
            print("Available variants: " + ", ".join(DESYNC_VARIANTS))
            variant = input("Variant: ").strip().lower()
            if variant in DESYNC_VARIANTS:
                send_attack(shadow, "http", target, interface, source, variant)
            else:
                print("Unknown variant.")
        elif choice == "6":
            for variant in DESYNC_VARIANTS:
                send_attack(shadow, "http", target, interface, source, variant)
        elif choice == "7":
            send_attack(shadow, "icmp", target, interface, source)
            send_attack(shadow, "http", target, interface, source)
        elif choice == "0":
            return
        else:
            print("Invalid option.")


if __name__ == "__main__":
    main()
