#!/usr/bin/python3

import sys
import os
import re

class Binds:
    bindtype = ""
    zone = ""
    permits = []

class SourceBind:
    def __init__(self):
        self.bindtype = "source"


class InterfaceBind:
    def __init__(self):
        self.bindtype = "interface"


class ZonePermits:
    name = ""
    ports = []
    protocols = []
    services = []
    source_ports = []
    target = None


    def __init__(self, **kwargs):
        self.name = ""
        self.ports = []
        self.protocols = []
        self.services = []
        self.source_ports = []
        self.target = None

        for key, value in kwargs.items():
            self.__dict__[key] = value

    def __setitem__(self, key, value):
        setattr(self, key, value)

    def __getitem(self, key):
        return getaddr(self, key)

    def __repr__(self):
        return "\n".join([ x for x in (
                f"{self.name} ({self.target})",
                f"  Services: {', '.join(self.services)}" if self.services else "",
                f"  Ports: {', '.join(self.ports)}" if self.ports else "",
                f"  Source ports: {', '.join(self.source_ports)}" if self.source_ports else "",
                f"  Protocols: {', '.join(self.protocols)}" if self.protocols else "",
        ) if x])

sources = {}
interfaces = {}
zones = {}

sosreport=sys.argv[1]
firewalld_dir=f"{sosreport}/sos_commands/firewalld"
firewalld_list_all_zones=f"{firewalld_dir}/firewall-cmd_--list-all-zones"
firewalld_conf=f"{sosreport}/etc/firewalld/firewalld.conf"

if not os.path.isdir(sosreport):
    print(f"Sosreport path doesn't exist {sosreport}")
    sys.exit(1)

if not os.path.isdir(firewalld_dir):
    print(f"Sosreport doesn't contain a firewalld dump {sosreport}")
    sys.exit(1)

if not os.path.exists(firewalld_list_all_zones):
    print(f"Sosreport firewalld doesn't include a zone dump {sosreport}")
    sys.exit(1)


firewalld_conf_params = dict([ x.split("=") for x in open(firewalld_conf).read().split('\n') if x and not x.startswith("#") ])

explained = {}
current_zone=None
current_zone_active=False
current_triggers = []
current_permits = []
last_key = ""

for line in open(firewalld_list_all_zones).read().split('\n'):
    #print("LINE", line, "  --  ", f"LAST KEY \"{last_key}\"")

    if not line: # ^$: end of zone
        last_key = ""
        continue

    #if not line.startswith(" "):
    if re.match("[a-zA-Z0-9]", line):  #^zonename (active)?
        # New Zone

        words = line.split(" ")
        if len(words) == 1:
            current_zone_active=False
            continue

        current_zone_active=True
        zone_name = words[0]
        current_zone = zone_name

        zones[zone_name] = ZonePermits(name=zone_name)

        #print(f"Zone {zone_name}: {current_zone_active}")

    elif last_key == "rich rules":
        # Ignore rich rules for now
        continue

    elif not current_zone_active:
        # Ignore keys from inactive zones
        continue

    else:
        key, values = [ x.strip() for x in line.split(":", 1) ]
        last_key = key

        if not values:
            continue

        values = [x.strip() for x in values.split(" ") if x.strip() ]

        if key == "sources":
            for source in values:
                sources[source] = zones[zone_name]
        elif key == "interfaces":
            for interface in values:
                interfaces[interface] = zones[zone_name]

        elif key in ("source-ports", "ports", "services", "protocols"):
                key = key.replace("-", "_")
                for value in values:
                    zones[zone_name][key] = values

        elif key == "target":
            zones[zone_name][key] = values[0]

        #print("\tKEY", key, "VALUE", values)

for source, zone in sources.items():
    print(f"{source} -> {zone}\n")

for interface, zone in interfaces.items():
    print(f"{interface} -> {zone}\n")

default_zone_name = firewalld_conf_params.get("DefaultZone")
if default_zone_name:
    default_zone = zones.get(default_zone_name)
print(f"All other traffic -> {default_zone}")


#print("SOURCES", sources)
#print("INTERFACES", interfaces)
