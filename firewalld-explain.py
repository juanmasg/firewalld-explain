#!/usr/bin/python3

import sys
import os
import re
from argparse import ArgumentParser
from subprocess import Popen, PIPE, check_output

class Zone:
    name = ""
    ports = []
    protocols = []
    services = []
    source_ports = []
    rich_rules = []
    target = None


    def __init__(self, **kwargs):
        self.name = ""
        self.ports = []
        self.protocols = []
        self.services = []
        self.source_ports = []
        self.rich_rules = []
        self.target = None

        for key, value in kwargs.items():
            self.__dict__[key] = value

    def __setitem__(self, key, value):
        setattr(self, key, value)

    def __getitem(self, key):
        return getaddr(self, key)

    def __repr__(self):
        newline='\n'
        return " ".join([ x for x in (
                f"{self.name} (target:{self.target})",
                f"{newline}  Services: {','.join(self.services)}" if self.services else "",
                f"{newline}  Ports: {','.join(self.ports)}" if self.ports else "",
                f"{newline}  Source ports: {','.join(self.source_ports)}" if self.source_ports else "",
                f"{newline}  Protocols: {','.join(self.protocols)}" if self.protocols else "",
                f"{newline}  Rich rules:{newline} {newline.join(self.rich_rules)}" if self.rich_rules else "",
        ) if x])

class Firewalld:
    _firewallcmd_bin = "firewall-cmd"
    _zones = None
    _sources = None
    _interfaces = None

    def __init__(self):
        self._zones = {}
        self._sources = {}
        self._interfaces = {}

    def _parse_all_zones(self, contents):

        last_key = ""
        current_zone_active = False

        for line in contents.split("\n"):
            #print("LINE", line, "LAST KEY", last_key)
            if not line:
                # ^$: end of zone
                last_key = ""
                continue

            elif re.match("\w", line):
                # new zone

                words = line.split(" ")
                if len(words) == 1: 
                    # zone not (active)
                    current_zone_active = False
                    continue

                current_zone_active = True
                current_zone_name = words[0]
                self._zones[current_zone_name] = Zone(name=current_zone_name)

            elif last_key == "rich rules":
                self._zones[current_zone_name].rich_rules.append(line)
                continue

            elif not current_zone_active:
                # ignore data from inactive zones
                continue

            else:
                key, values = [ x.strip() for x in line.split(":", 1) ]
                last_key = key

                if not values:
                    continue

                values = [x.strip() for x in values.split(" ") if x.strip() ]

                if key == "sources":
                    for source in values:
                        self._sources[source] = self._zones[current_zone_name]
                elif key == "interfaces":
                    for interface in values:
                        self._interfaces[interface] = self._zones[current_zone_name]

                elif key in ("source-ports", "ports", "services", "protocols"):
                        key = key.replace("-", "_")
                        for value in values:
                            self._zones[current_zone_name][key] = values

                elif key == "target":
                    self._zones[current_zone_name][key] = values[0]


        # Sort all sources by netmask. This is NOT the order in which firewalld processes them but
        # it's easier to read
        sorted_sources = {}
        for key in sorted(self._sources, key=lambda x: int(x.split("/")[1]) if "/" in x else 32, reverse=True ):
            sorted_sources[key] = self._sources[key]

        self._sources = sorted_sources



    def list_all_zones(self):
        cmd = f"{self._firewallcmd_bin} --list-all-zones"
        proc = Popen(cmd.split(" "), stdout=PIPE)
        stdout, stderr = proc.communicate()
        if stderr and b"FirewallD is not running" in stderr:
            print(stderr)
            return None

        return stdout.decode("utf8")

    def _parse_firewalld_conf(self, contents):
        pairs = [ x.split("=") for x in contents.split('\n') \
                if x and not x.startswith("#") ]

        return dict(pairs)

    def firewalld_conf(self):
        filepath = "/etc/firewalld/firewalld.conf"
        contents = open(filepath).read()
        return self._parse_firewalld_conf(contents)

    def explain_table(self):

        try:
            from tabulate import tabulate
        except Exception as e:
            print(f"Cannot build table because \"tabulate\" is not available: {e}")
            print(f"Hint: `python -m pip install tabulate --user`")
            return False

        contents = self.list_all_zones()
        if not contents:
            return

        self._parse_all_zones(contents)

        prev_zone_name = ""
        i = 1

        table_data = [["#", "Trigger", "Zone", "Ports", "Source ports",
                        "Services", "Protocols", "Rich rules", "Target"]]

        for source, zone in self._sources.items():
            table_data.append([i, source, *zone_to_tabulate_row(zone)])
            i += 1

        for interface, zone in self._interfaces.items():
            table_data.append([i, interface, *zone_to_tabulate_row(zone)])
            i += 1

        default_zone_name = self.firewalld_conf().get("DefaultZone")
        default_zone = self._zones.get(default_zone_name)
        table_data.append([i, "Other traffic", *zone_to_tabulate_row(default_zone)])

        print(tabulate(table_data, headers="firstrow",
            tablefmt="fancy_grid", maxcolwidths=80))

        return True


    def explain_text(self):
        contents = self.list_all_zones()
        if not contents:
            return 

        self._parse_all_zones(contents)

        for source, zone in self._sources.items():
            print(f"\n{source} -> {zone}")
        
        for interface, zone in self._interfaces.items():
            print(f"\n{interface} -> {zone}")

        firewalld_conf = self.firewalld_conf()
        
        default_zone_name = firewalld_conf.get("DefaultZone")
        if default_zone_name:
            default_zone = self._zones.get(default_zone_name)

        print(f"\nAll_other_traffic -> {default_zone}")

    def explain_nwdiag(self):
        pass
        #diag_data = """
        #    nwdiag{
        #        inet [shape = cloud];
        #        inet -- 
        #    }
        #"""





class SOSFirewalld(Firewalld):
    _sospath = None

    def __init__(self, sospath):
        Firewalld.__init__(self)
        self._sospath = sospath

    @staticmethod
    def check_sos_path(sospath):
        if not os.path.isdir(sospath):
            return False

        if not os.path.isdir(f"{sospath}/sos_commands/firewalld"):
            return False

        return True


    def list_all_zones(self):
        filepath = f"{self._sospath}/sos_commands/firewalld/firewall-cmd_--list-all-zones"
        data = open(filepath).read()
        if data and "FirewallD is not running" in data:
            print("FirewallD was not running")
            return None

        return data

    def firewalld_conf(self):
        filepath = f"{self._sospath}/etc/firewalld/firewalld.conf"
        contents = open(filepath).read()
        return self._parse_firewalld_conf(contents)


def zone_to_tabulate_row(zone):
    return [ zone.name,
             " ".join(zone.ports),
             " ".join(zone.source_ports),
             " ".join(zone.services),
             " ".join(zone.protocols),
             " ".join(zone.rich_rules),
             zone.target]


if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument("--sos", "-S", help="Path to sosreport with firewalld dump")
    parser.add_argument("--table", "-T", help="Table format", action="store_true")
    
    args = parser.parse_args()
    
    firewalld = None
    
    if args.sos:
        if not SOSFirewalld.check_sos_path(args.sos):
            print(f"sosreport path doesn't seem to contain firewalld data {args.sos}")
            sys.exit(1)
    
        firewalld = SOSFirewalld(args.sos)
    else:
        firewalld = Firewalld()
    
    if args.table:
        firewalld.explain_table()
    else:
        firewalld.explain_text()


