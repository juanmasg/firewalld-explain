# firewalld-explain
Runs `firewall-cmd --list-all-zones` and prints a summary of all relevant information.  
Alternatively, it can scan `firewall-cmd_--list-all-zones` from a sosreport

# Example:

  * Default text only output:
      ```
      $ sudo ./firewalld-explain.py 
      
      192.168.2.0/24 -> trusted (target:ACCEPT)
      
      10.0.0.0/16 -> test-zone (target:default) 
        Ports: 1234/tcp
      
      enp1s0 -> public (target:default) 
        Services: cockpit,dhcpv6-client,ssh
      
      enp4s0 -> test-zone (target:default) 
        Ports: 1234/tcp
      
      All_other_traffic -> public (target:default) 
        Services: cockpit,dhcpv6-client,ssh
      ```

  * Table format:
      ```
      $ sudo ./firewalld-explain.py -T
      ╒═════╤════════════════╤═══════════╤══════════╤════════════════╤═══════════════════════════╤═════════════╤══════════════╤══════════╕
      │   # │ Trigger        │ Zone      │ Ports    │ Source ports   │ Services                  │ Protocols   │ Rich rules   │ Target   │
      ╞═════╪════════════════╪═══════════╪══════════╪════════════════╪═══════════════════════════╪═════════════╪══════════════╪══════════╡
      │   1 │ 192.168.2.0/24 │ trusted   │          │                │                           │             │              │ ACCEPT   │
      ├─────┼────────────────┼───────────┼──────────┼────────────────┼───────────────────────────┼─────────────┼──────────────┼──────────┤
      │   2 │ 10.0.0.0/16    │ test-zone │ 1234/tcp │                │                           │             │              │ default  │
      ├─────┼────────────────┼───────────┼──────────┼────────────────┼───────────────────────────┼─────────────┼──────────────┼──────────┤
      │   3 │ enp1s0         │ public    │          │                │ cockpit dhcpv6-client ssh │             │              │ default  │
      ├─────┼────────────────┼───────────┼──────────┼────────────────┼───────────────────────────┼─────────────┼──────────────┼──────────┤
      │   4 │ enp4s0         │ test-zone │ 1234/tcp │                │                           │             │              │ default  │
      ├─────┼────────────────┼───────────┼──────────┼────────────────┼───────────────────────────┼─────────────┼──────────────┼──────────┤
      │   5 │ Other traffic  │ public    │          │                │ cockpit dhcpv6-client ssh │             │              │ default  │
      ╘═════╧════════════════╧═══════════╧══════════╧════════════════╧═══════════════════════════╧═════════════╧══════════════╧══════════╛
      ```
      
  * Dot format:  
    `$ sudo ./firewalld-explain.py -D`

  * Open automatically the generated graph:

    `$ sudo ./firewalld-explain.py -D -V`
  
    ![](<.img/firewalld-explain.gv.png>)

  * Open automatically the generated graph via an arbitrary command:
    ```
    $ sudo ./firewalld-explain.py -D -E "graph-easy --input=%f"
    #================#     +----------------+     +---------------------------------------+     +---------+
    H  10.0.0.0/16   H --> | zone:test-zone | --> |            Ports: 1234/tcp            | --> | default |
    #================#     +----------------+     +---------------------------------------+     +---------+
                             ^                                                                    ^
                             |                                                                    |
                             |                                                                    |
    #================#     +----------------+                                                     |
    H 192.168.2.0/24 H     |     enp4s0     |                                                     |
    #================#     +----------------+                                                     |
      |                                                                                           |
      |                                                                                           |
      v                                                                                           |
    +----------------+     +----------------+     +---------------------------------------+       |
    |  zone:trusted  | --> |                | --> |                ACCEPT                 |       |
    +----------------+     +----------------+     +---------------------------------------+       |
    +----------------+     +----------------+     +---------------------------------------+       |
    |     enp1s0     | --> |  zone:public   | --> | Services: cockpit, dhcpv6-client, ssh | ------+
    +----------------+     +----------------+     +---------------------------------------+


    ```
  
  * Scan from a sosreport:
      ```
      $ ./firewalld-explain.py -S /path/to/sosreport
      ```
