import ipaddress

# Asks for the name of the file that contains IP or FQDN
input_file = input("Enter the name of the file to process: ")
output_file = "formatted_objects.txt"

# We will keep counters for how many entries are IPs and how many are FQDNs
count_ip = 0
count_fqdn = 0

# This list will hold the final names actually used in 'edit' and in the group
processed_items = []

with open(input_file, "r") as infile, open(output_file, "w") as outfile:
    for line in infile:
        entry = line.strip()
        if not entry:
            continue  # ignore empty lines

        try:
            # Attempt to parse the string as an IP (with or without slash) using ip_interface
            iface = ipaddress.ip_interface(entry)
            ip_str = str(iface.ip)
            netmask_str = str(iface.network.netmask)

            # If the user already specified a slash, we keep that name.
            # Otherwise, if it's /32, we append /32 to the name (e.g., 1.2.3.4 -> 1.2.3.4/32)
            # In all other cases, we keep the entry as is.

            if "/" in entry:
                name_for_edit = entry
            else:
                if netmask_str == "255.255.255.255":
                    name_for_edit = ip_str + "/32"
                else:
                    name_for_edit = entry

            outfile.write(f"edit {name_for_edit}\n")
            outfile.write(f"set subnet {ip_str} {netmask_str}\n")
            outfile.write("next\n")

            processed_items.append(name_for_edit)
            count_ip += 1

        except ValueError:
            # If a ValueError is raised, it's not a valid IP (or IP with slash), so treat it as an FQDN
            outfile.write(f"edit {entry}\n")
            outfile.write(f"set fqdn {entry}\n")
            outfile.write("next\n")

            processed_items.append(entry)
            count_fqdn += 1

    # Adds the final command with all the newly created objects
    outfile.write("config firewall addrgrp\n")
    outfile.write("edit Malicous\n")

    # Build the list of members with quotes around each IP/FQDN
    member_list = " ".join(f'"{item}"' for item in processed_items)
    outfile.write(f"set member {member_list}\n")
    outfile.write("end\n")

# After processing, print a summary to the console
print("Processing complete!")
print(f"Total entries processed: {count_ip + count_fqdn}")
print(f"- IP addresses: {count_ip}")
print(f"- FQDNs: {count_fqdn}")
