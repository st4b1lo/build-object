import ipaddress
from pathlib import Path

def process(input_path: Path, output_path: Path,
            group4_name="Malicious_v4_fqdn", group6_name="Malicious_v6"):
    items_v4_or_fqdn = []
    items_v6 = []

    lines = input_path.read_text(encoding="utf-8").splitlines()
    with output_path.open("w", encoding="utf-8") as outfile:
        # IPv4 e FQDN
        outfile.write("config firewall address\n")
        for raw in lines:
            entry = raw.strip()
            if not entry or entry.startswith("#") or entry.startswith("==="):
                continue
            try:
                iface = ipaddress.ip_interface(entry)
                if isinstance(iface.ip, ipaddress.IPv4Address):
                    name = entry if "/" in entry else f"{iface.ip}/32"
                    outfile.write(f'    edit "{name}"\n')
                    outfile.write(f"        set subnet {iface.ip} {iface.network.netmask}\n")
                    outfile.write("    next\n")
                    items_v4_or_fqdn.append(name)
                # IPv6 lo gestiamo dopo
            except ValueError:
                # FQDN
                name = entry
                outfile.write(f'    edit "{name}"\n')
                outfile.write("        set type fqdn\n")
                outfile.write(f'        set fqdn "{name}"\n')
                outfile.write("    next\n")
                items_v4_or_fqdn.append(name)
        outfile.write("end\n\n")

        # IPv6 in modalità prefisso
        outfile.write("config firewall address6\n")
        for raw in lines:
            entry = raw.strip()
            if not entry or entry.startswith("#") or entry.startswith("==="):
                continue
            try:
                iface = ipaddress.ip_interface(entry if "/" in entry else f"{entry}/128")
                if isinstance(iface.ip, ipaddress.IPv6Address):
                    name = entry if "/" in entry else f"{iface.ip}/128"
                    cidr = name
                    outfile.write(f'    edit "{name}"\n')
                    outfile.write(f"        set ip6 {cidr}\n")
                    outfile.write("    next\n")
                    items_v6.append(name)
            except ValueError:
                pass
        outfile.write("end\n\n")

        # Gruppi
        if items_v4_or_fqdn:
            members4 = " ".join(f'"{m}"' for m in items_v4_or_fqdn)
            outfile.write("config firewall addrgrp\n")
            outfile.write(f'    edit "{group4_name}"\n')
            outfile.write(f"        set member {members4}\n")
            outfile.write("    next\n")
            outfile.write("end\n\n")
        if items_v6:
            members6 = " ".join(f'"{m}"' for m in items_v6)
            outfile.write("config firewall addrgrp6\n")
            outfile.write(f'    edit "{group6_name}"\n')
            outfile.write(f"        set member {members6}\n")
            outfile.write("    next\n")
            outfile.write("end\n")

if __name__ == "__main__":
    file_in = input("Enter the name of the file to process: ").strip()
    input_path = Path(file_in)
    output_path = Path("formatted_objects.txt")
    process(input_path, output_path)
    print(f"\nProcessing complete! Output saved in {output_path.resolve()}")
