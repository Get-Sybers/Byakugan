# Dashboards in the `malcolm` space

36 dashboards, one file each under `kibana/dashboards/`. "Selects" is the set of `event.dataset` values the
dashboard's panel queries name on its data view; "all" marks a dashboard with panels that apply no dataset filter.
The navigation panel at the top of every dashboard links the dashboards of each section below.

## General network logs

| Dashboard | File | Data view | Selects | Panels |
|---|---|---|---|---|
| Overview | `overview.ndjson` | `logs-dxdfir.zeek-*` | dns, all | 7 |
| Connections | `connections.ndjson` | `logs-dxdfir.zeek-*` | conn | 15 |
| Files | `files.ndjson` | `logs-dxdfir.zeek-*` | files, all | 8 |
| PE | `pe.ndjson` | `logs-dxdfir.zeek-*` | pe | 7 |
| Zeek Weird | `zeek-weird.ndjson` | `logs-dxdfir.zeek-*` | weird | 6 |
| Suricata Alerts | `suricata-alerts.ndjson` | `logs-dxdfir.detections-*` | alert (event.provider:suricata) | 7 |

## Protocols

| Dashboard | File | Data view | Selects | Panels |
|---|---|---|---|---|
| DCE/RPC | `dce-rpc.ndjson` | `logs-dxdfir.zeek-*` | dce_rpc | 11 |
| DHCP | `dhcp.ndjson` | `logs-dxdfir.zeek-*` | dhcp | 6 |
| DNS | `dns.ndjson` | `logs-dxdfir.zeek-*` | dns | 12 |
| FTP | `ftp.ndjson` | `logs-dxdfir.zeek-*` | ftp | 9 |
| HTTP | `http.ndjson` | `logs-dxdfir.zeek-*` | http, all | 16 |
| WebSocket | `websocket.ndjson` | `logs-dxdfir.zeek-*` | websocket | 8 |
| IRC | `irc.ndjson` | `logs-dxdfir.zeek-*` | irc | 7 |
| Kerberos | `kerberos.ndjson` | `logs-dxdfir.zeek-*` | kerberos | 13 |
| LDAP | `ldap.ndjson` | `logs-dxdfir.zeek-*` | ldap, ldap_search | 10 |
| MQTT | `mqtt.ndjson` | `logs-dxdfir.zeek-*` | mqtt_connect, mqtt_publish, mqtt_subscribe | 10 |
| MySQL | `mysql.ndjson` | `logs-dxdfir.zeek-*` | mysql | 5 |
| NTLM | `ntlm.ndjson` | `logs-dxdfir.zeek-*` | ntlm | 11 |
| NTP | `ntp.ndjson` | `logs-dxdfir.zeek-*` | ntp | 9 |
| PostgreSQL | `postgresql.ndjson` | `logs-dxdfir.zeek-*` | postgresql | 9 |
| QUIC | `quic.ndjson` | `logs-dxdfir.zeek-*` | quic | 7 |
| RADIUS | `radius.ndjson` | `logs-dxdfir.zeek-*` | radius | 9 |
| Redis | `redis.ndjson` | `logs-dxdfir.zeek-*` | redis | 9 |
| RDP | `rdp.ndjson` | `logs-dxdfir.zeek-*` | rdp | 10 |
| RFB | `rfb.ndjson` | `logs-dxdfir.zeek-*` | rfb | 12 |
| SIP | `sip.ndjson` | `logs-dxdfir.zeek-*` | sip | 12 |
| SMB | `smb.ndjson` | `logs-dxdfir.zeek-*` | smb_files, smb_mapping | 11 |
| SMTP | `smtp.ndjson` | `logs-dxdfir.zeek-*` | smtp | 11 |
| SNMP | `snmp.ndjson` | `logs-dxdfir.zeek-*` | snmp | 7 |
| SSH | `ssh.ndjson` | `logs-dxdfir.zeek-*` | ssh | 8 |
| SSL | `ssl.ndjson` | `logs-dxdfir.zeek-*` | ssl | 11 |
| X.509 | `x-509.ndjson` | `logs-dxdfir.zeek-*` | ocsp, x509 | 13 |
| Syslog | `syslog.ndjson` | `logs-dxdfir.zeek-*` | syslog | 9 |
| Tunnels | `tunnels.ndjson` | `logs-dxdfir.zeek-*` | tunnel | 7 |

## ICS protocols

| Dashboard | File | Data view | Selects | Panels |
|---|---|---|---|---|
| Modbus | `modbus.ndjson` | `logs-dxdfir.zeek-*` | modbus | 6 |
| DNP3 | `dnp3.ndjson` | `logs-dxdfir.zeek-*` | dnp3 | 7 |

## Panels

Every dashboard also carries the navigation panel (markdown). Kinds: table, pie chart, metric, chart and tag cloud are Lens
visualisations stored in the dashboard; a Discover table is a saved search stored in the same file; Vega is a
Vega visualisation stored in the dashboard, which queries Elasticsearch through its own specification under the
dashboard's time range and filters. The query after a panel is the KQL it applies on the data view.

### Overview (`overview.ndjson`)

- Total Log Count Over Time (chart)
- Log Type (table)
- Total Number of Logs (metric)
- DNS - Queries (table): `event.dataset:dns`
- Log Source (table)
- Application Protocol (table)
- All Logs (Discover table of event.provider, event.dataset, id.orig_h, id.resp_h, id.resp_p, uid)

### Connections (`connections.ndjson`)

- Connections - Log Count Over Time (chart): `event.dataset:conn`
- Connections - Source IP Address (table): `event.dataset:conn`
- Connections - Destination IP Address (table): `event.dataset:conn`
- Connections - Responder Bytes (table): `event.dataset:conn`
- Connections - Missed Bytes (table): `event.dataset:conn`
- Connections - Connection State (table): `event.dataset:conn`
- Connections - Top 10 - Total Bytes By Connection (chart): `event.dataset:conn`
- Connections - Top 10 - Total Bytes By Destination IP (chart): `event.dataset:conn`
- Connections - Top 10 - Total Bytes By Destination Port (chart): `event.dataset:conn`
- Connections - Top 10 - Total Bytes By Source IP (chart): `event.dataset:conn`
- Connections - Log Count (metric): `event.dataset:conn`
- Connections - Total Bytes Per Source/Destination IP Pair (table): `event.dataset:conn`
- Connections - Destination Port (table): `event.dataset:conn`
- Connections - Protocol (pie chart): `event.dataset:conn`
- Connections - Logs (Discover table of proto, service, id.orig_h, id.orig_p, id.resp_h, id.resp_p, network.bytes, uid): `event.dataset:conn`

### Files (`files.ndjson`)

- Files - Log Count Over Time (chart): `event.dataset:files`
- Files - Files By Size (Bytes) (table): `event.dataset:files`
-  - Destination IP Address (table): `event.dataset:files`
- Files - Source IP Address (table): `event.dataset:files`
- Files - Log Count (metric): `event.dataset:files`
- Files - Source (chart): `event.dataset:files`
- Files - MIME Type (table)
- Files - Logs (Discover table of id.orig_h, id.resp_h, source, mime_type, uid): `event.dataset:files`

### PE (`pe.ndjson`)

- PE - Log Count Over Time (chart): `event.dataset:pe`
- PE - OS (pie chart): `event.dataset:pe`
- PE - Subsystem (pie chart): `event.dataset:pe`
- PE - Section Name (table): `event.dataset:pe`
- PE - Machine (table): `event.dataset:pe`
- PE - Log Count (metric): `event.dataset:pe`
- PE - Logs (Discover table of machine, os, subsystem, id): `event.dataset:pe`

### Zeek Weird (`zeek-weird.ndjson`)

- Weird - Log Count Over Time (chart): `event.dataset:weird`
- Weird - Source (table): `event.dataset:weird`
- Weird - Destination (table): `event.dataset:weird`
- Weird - Log Count (metric): `event.dataset:weird`
- Weird - Name (table): `event.dataset:weird`
- Weird - Logs (Discover table of id.orig_h, id.orig_p, id.resp_h, id.resp_p, name, uid): `event.dataset:weird`

### Suricata Alerts (`suricata-alerts.ndjson`)

- Alerts - Log Count (metric): `event.provider:suricata AND event.dataset:alert`
- Alerts - Log Count Over Time (chart): `event.provider:suricata AND event.dataset:alert`
- Alert Category (chart): `event.provider:suricata AND event.dataset:alert`
- Alerts - Name (table): `event.provider:suricata AND event.dataset:alert`
- Alerts - Source (table): `event.provider:suricata AND event.dataset:alert`
- Alerts - Destination (table): `event.provider:suricata AND event.dataset:alert`
- Suricata Alerts - Logs (Discover table of alert.category, alert.signature, alert.signature_id, src_ip, dest_ip, flow_id): `event.provider:suricata AND event.dataset:alert`

### DCE/RPC (`dce-rpc.ndjson`)

- DCE/RPC - Log Count Over Time (chart): `event.dataset:dce_rpc`
- DCE/RPC - Source IP Address (table): `event.dataset:dce_rpc`
- DCE/RPC - Destination IP Address (table): `event.dataset:dce_rpc`
- DCE/RPC - Endpoint (table): `event.dataset:dce_rpc`
- DCE/RPC - Named Pipe (table): `event.dataset:dce_rpc`
- DCE/RPC - Operation (table): `event.dataset:dce_rpc`
- DCE/RPC - Round Trip Time (table): `event.dataset:dce_rpc`
- DCE/RPC - Log Count (metric): `event.dataset:dce_rpc`
- DCE/RPC - Destination Port (table): `event.dataset:dce_rpc`
- DCE/RPC - Summary (table): `event.dataset:dce_rpc`
- DCE/RPC - Logs (Discover table of id.orig_h, id.orig_p, id.resp_h, id.resp_p, operation, endpoint, uid): `event.dataset:dce_rpc`

### DHCP (`dhcp.ndjson`)

- DHCP - Log Count Over Time (chart): `event.dataset:dhcp`
- DHCP - Destination IP Address (table): `event.dataset:dhcp`
- DHCP - Source IP Address (table): `event.dataset:dhcp`
- DHCP - Log Count (metric): `event.dataset:dhcp`
- DHCP - IP to MAC Assignment (table): `event.dataset:dhcp`
- DHCP - Logs (Discover table of event.dataset, mac, assigned_addr, client_addr, server_addr, host_name, domain, msg_types, uids): `event.dataset:dhcp`

### DNS (`dns.ndjson`)

- DNS - Server (table): `event.dataset:dns`
- DNS - Client (table): `event.dataset:dns`
- DNS - Query Class (pie chart): `event.dataset:dns`
- DNS - Query/Answer (table): `event.dataset:dns`
- DNS - Log Count Over Time (chart): `event.dataset:dns`
- DNS - Destination Port (chart): `event.dataset:dns`
- DNS - Log Count (metric): `event.dataset:dns`
- DNS - Answers (table): `event.dataset:dns`
- DNS - Response Code (Name) (table): `event.dataset:dns`
- DNS - Query Type (table): `event.dataset:dns`
- DNS - Protocol (pie chart): `event.dataset:dns`
- DNS - Logs (Discover table of id.orig_h, id.resp_h, query, answers, uid): `event.dataset:dns`

### FTP (`ftp.ndjson`)

- FTP - Log Count Over Time (chart): `event.dataset:ftp`
- FTP - Argument (table): `event.dataset:ftp`
- FTP - Commands and Replies (table): `event.dataset:ftp`
- FTP - Reply (pie chart): `event.dataset:ftp`
- FTP - Source (table): `event.dataset:ftp`
- FTP - Destination (table): `event.dataset:ftp`
- FTP - Username (table): `event.dataset:ftp`
- FTP - Log Count (metric): `event.dataset:ftp`
- FTP - Logs (Discover table of id.orig_h, id.resp_h, command, reply_msg, uid): `event.dataset:ftp`

### HTTP (`http.ndjson`)

- HTTP - Status Over Time (chart): `event.dataset:http`
- HTTP - Sites (table): `event.dataset:http`
- HTTP - Sites Hosting EXEs (table): `resp_mime_types:"application/x-dosexec"`
- HTTP - URIs (table): `event.dataset:http`
- HTTP - Source IP Address (table): `event.dataset:http`
- HTTP - Destination IP Address (table): `event.dataset:http`
- HTTP - User Agent (table): `event.dataset:http`
- HTTP - Referrer (table): `event.dataset:http`
- HTTP - Destination Port (chart): `event.dataset:http`
- HTTP - Log Count (metric): `event.dataset:http`
- HTTP  - Status and Method (table): `event.dataset:http`
- HTTP - Unique Usernames and Passwords (metric): `event.dataset:http`
- HTTP - Version (pie chart): `(event.dataset:http) AND (NOT version:"0.0")`
- HTTP - File Type (tag cloud): `event.dataset:http`
- HTTP - Logs (Discover table of id.orig_h, id.resp_h, id.resp_p, host, method, status_msg, uid): `event.dataset:http`
- HTTP - Method and Status (Vega)

### WebSocket (`websocket.ndjson`)

- WebSocket - Log Count (metric): `event.dataset:websocket`
- WebSocket - Logs Over Time (chart): `event.dataset:websocket`
- WebSocket - Source IP (table): `event.dataset:websocket`
- WebSocket - Destination IP (table): `event.dataset:websocket`
- WebSocket - Client Extensions (table): `event.dataset:websocket`
- WebSocket - Server Extensions (table): `event.dataset:websocket`
- WebSocket - URI (table): `event.dataset:websocket`
- WebSocket - Logs (Discover table of id.orig_h, id.resp_h, id.resp_p, host, uri, user_agent, subprotocol, client_protocols, client_extensions, server_extensions, uid): `event.dataset:websocket`

### IRC (`irc.ndjson`)

- IRC - Log Count Over Time (chart): `event.dataset:irc`
- IRC - Destination IP Address (table): `event.dataset:irc`
- IRC - Source IP Address (table): `event.dataset:irc`
- IRC - Destination Port (table): `event.dataset:irc`
- IRC - Log Count (metric): `event.dataset:irc`
- IRC - Command (table): `event.dataset:irc`
- IRC - Logs (Discover table of id.orig_h, id.resp_h, id.resp_p, nick, command, value, uid): `event.dataset:irc`

### Kerberos (`kerberos.ndjson`)

- Kerberos - Log Count Over Time (chart): `event.dataset:kerberos`
- Kerberos - Client (table): `event.dataset:kerberos`
- Kerberos - Success Status (pie chart): `event.dataset:kerberos`
- Kerberos - Server (table): `event.dataset:kerberos`
- Kerberos - Cipher (pie chart): `event.dataset:kerberos`
- Kerberos - Source IP Address (table): `event.dataset:kerberos`
- Kerberos - Destination IP Address (table): `event.dataset:kerberos`
- Kerberos - Service (table): `event.dataset:kerberos`
- Kerberos - Log Count (metric): `event.dataset:kerberos`
- Kerberos - Request Types (pie chart): `event.dataset:kerberos`
- Kerberos - Renewable Ticket Requested (pie chart): `event.dataset:kerberos`
- Kerberos - Destination Ports (chart): `event.dataset:kerberos`
- Kerberos - Logs (Discover table of id.orig_h, id.resp_h, id.resp_p, request_type, success, error_msg, uid): `event.dataset:kerberos`

### LDAP (`ldap.ndjson`)

- LDAP - Log Count Over Time (chart): `event.dataset:ldap`
- LDAP - Logs (Discover table of id.orig_h, id.resp_h, id.resp_p, version, message_id, opcode, object, argument, result, uid): `event.dataset:ldap`
- LDAP - Source IP (table): `event.dataset:ldap`
- LDAP - Destination IP (table): `event.dataset:ldap`
- LDAP - Log Count (metric): `event.dataset:(ldap OR ldap_search)`
- LDAP - Bind (table): `(event.dataset:ldap) AND (opcode:bind*)`
- LDAP - Search Scope (chart): `event.dataset:ldap_search`
- LDAP - Result Code (table): `event.dataset:(ldap OR ldap_search)`
- LDAP - Operation (table): `event.dataset:(ldap OR ldap_search)`
- LDAP Search - Logs (Discover table of id.orig_h, id.resp_h, id.resp_p, message_id, base_object, filter, result_count, result, uid): `event.dataset:ldap_search`

### MQTT (`mqtt.ndjson`)

- MQTT - Log Count (metric): `event.dataset:(mqtt_connect OR mqtt_publish OR mqtt_subscribe)`
- MQTT - Log Count Over Time (chart): `event.dataset:(mqtt_connect OR mqtt_publish OR mqtt_subscribe)`
- MQTT - Source IP (table): `event.dataset:(mqtt_connect OR mqtt_publish OR mqtt_subscribe)`
- MQTT - Destination IP (table): `event.dataset:(mqtt_connect OR mqtt_publish OR mqtt_subscribe)`
- MQTT - Protocol (pie chart): `event.dataset:mqtt_connect`
- MQTT - Client ID (table): `event.dataset:mqtt_connect`
- MQTT - Subscription (table): `event.dataset:mqtt_subscribe`
- MQTT - Publish (table): `event.dataset:mqtt_publish`
- MQTT - Publish Payload (table): `event.dataset:mqtt_publish`
- MQTT - All Logs (Discover table of id.orig_h, id.resp_h, id.resp_p, event.dataset, uid): `event.dataset:(mqtt_connect OR mqtt_publish OR mqtt_subscribe)`

### MySQL (`mysql.ndjson`)

- MySQL - Log Count Over Time (chart): `event.dataset:mysql`
- MySQL - Log Count (metric): `event.dataset:mysql`
- MySQL - Success (pie chart): `event.dataset:mysql`
- MySQL - Commands (table): `event.dataset:mysql`
- MySQL - Logs (Discover table of id.orig_h, id.resp_h, id.resp_p, cmd, success, uid): `event.dataset:mysql`

### NTLM (`ntlm.ndjson`)

- NTLM - Log Count Over Time (chart): `event.dataset:ntlm`
- NTLM - Hostname (table): `event.dataset:ntlm`
- NTLM - Domain Name (table): `event.dataset:ntlm`
- NTLM - Username (table): `event.dataset:ntlm`
- NTLM - Destination IP Address (table): `event.dataset:ntlm`
- NTLM - Source IP Address (table): `event.dataset:ntlm`
- NTLM - Destination Port (table): `event.dataset:ntlm`
- NTLM - Log Count (metric): `event.dataset:ntlm`
- NTLM - Hostname to Username (table): `event.dataset:ntlm`
- NTLM - Success (pie chart): `event.dataset:ntlm`
- NTLM - Logs (Discover table of id.orig_h, id.resp_h, id.resp_p, hostname, domainname, server_nb_computer_name, server_dns_computer_name, server_tree_name, uid): `event.dataset:ntlm`

### NTP (`ntp.ndjson`)

- NTP - Logs (Discover table of id.orig_h, id.resp_h, version, stratum, mode, org_time, xmt_time, uid): `event.dataset:ntp`
- NTP - Log Count (metric): `event.dataset:ntp`
- NTP - Log Count Over Time (chart): `event.dataset:ntp`
- NTP - Stratum (chart): `event.dataset:ntp`
- NTP - Version (pie chart): `event.dataset:ntp`
- NTP - Mode (pie chart): `event.dataset:ntp`
- NTP - Polling Interval (chart): `event.dataset:ntp`
- NTP - Source IP (table): `event.dataset:ntp`
- NTP - Destination IP (table): `event.dataset:ntp`

### PostgreSQL (`postgresql.ndjson`)

- PostgreSQL - Log Count (metric): `event.dataset:postgresql`
- PostgreSQL - Log Count Over Time (chart): `event.dataset:postgresql`
- PostgreSQL - Database (chart): `event.dataset:postgresql`
- PostgreSQL - Action and Results (table): `event.dataset:postgresql`
- PostgreSQL - Application (table): `event.dataset:postgresql`
- PostgreSQL - Source IP (table): `event.dataset:postgresql`
- PostgreSQL - Destination IP (table): `event.dataset:postgresql`
- PostgreSQL - User (table): `event.dataset:postgresql`
- PostgreSQL - Logs (Discover table of id.orig_h, id.resp_h, database, application_name, user, frontend, success, frontend_arg, backend_arg, rows, uid): `event.dataset:postgresql`

### QUIC (`quic.ndjson`)

- QUIC - Log Count (metric): `event.dataset:quic`
- QUIC - Logs (Discover table of id.orig_h, id.resp_h, server_name, version, uid): `event.dataset:quic`
- QUIC - Log Count Over Time (chart): `event.dataset:quic`
- QUIC - Source IP Address (table): `event.dataset:quic`
- QUIC - Destination IP Address (table): `event.dataset:quic`
- QUIC - Server Name (table): `event.dataset:quic`
- QUIC - Version (pie chart): `event.dataset:quic`

### RADIUS (`radius.ndjson`)

- RADIUS - Log Count Over Time (chart): `event.dataset:radius`
- RADIUS - Source IP Address (table): `event.dataset:radius`
- RADIUS - Destination IP Address (table): `event.dataset:radius`
- RADIUS - MAC (table): `event.dataset:radius`
- RADIUS - Connection Information (table): `event.dataset:radius`
- RADIUS - Log Count (metric): `event.dataset:radius`
- RADIUS - Username (table): `event.dataset:radius`
- RADIUS - Authentication Result (pie chart): `event.dataset:radius`
- RADIUS - Logs (Discover table of id.orig_h, id.resp_h, id.resp_p, username, mac, framed_addr, result, uid): `event.dataset:radius`

### Redis (`redis.ndjson`)

- Redis - Logs Over Time (chart): `event.dataset:redis`
- Redis - Log Count (metric): `event.dataset:redis`
- Redis - Success (pie chart): `event.dataset:redis`
- Redis - Source (table): `event.dataset:redis`
- Redis - Destination (table): `event.dataset:redis`
- Redis - Action and Result (table): `event.dataset:redis`
- Redis - Key (table): `event.dataset:redis`
- Redis - Key and Value (table): `event.dataset:redis`
- Redis - Logs (Discover table of id.orig_h, id.orig_p, id.resp_h, id.resp_p, cmd.name, success, cmd.key, uid): `event.dataset:redis`

### RDP (`rdp.ndjson`)

- RDP - Log Count Over Time (chart): `event.dataset:rdp`
- RDP - Source IP Address (table): `event.dataset:rdp`
- RDP - Destination IP Address (table): `event.dataset:rdp`
- RDP - Cookie (table): `event.dataset:rdp`
- RDP - Result (pie chart): `event.dataset:rdp`
- RDP - Keyboard Layout (pie chart): `event.dataset:rdp`
- RDP - Client Version (chart): `event.dataset:rdp`
- RDP - Log Count (metric): `event.dataset:rdp`
- RDP - Encryption (pie chart): `event.dataset:rdp`
- RDP - Logs (Discover table of id.orig_h, id.resp_h, id.resp_p, client_build, keyboard_layout, security_protocol, encryption_method, result, uid): `event.dataset:rdp`

### RFB (`rfb.ndjson`)

- RFB - Log Count Over Time (chart): `event.dataset:rfb`
- RFB - Authentication Status (pie chart): `event.dataset:rfb`
- RFB - Exclusive Session (pie chart): `event.dataset:rfb`
- RFB - Desktop Name (table): `event.dataset:rfb`
- RFB - Source IP Address (table): `event.dataset:rfb`
- RFB - Destination IP Address (table): `event.dataset:rfb`
- RFB - Destination Port (table): `event.dataset:rfb`
- RFB - Server Version (table): `event.dataset:rfb`
- RFB - Client Version (table): `event.dataset:rfb`
- RFB - Authentication Method (chart): `event.dataset:rfb`
- RFB - Log Count (metric): `event.dataset:rfb`
- RFB - Logs (Discover table of id.orig_h, id.resp_h, id.resp_p, desktop_name, authentication_method, auth, share_flag, uid): `event.dataset:rfb`

### SIP (`sip.ndjson`)

- SIP - Log Count Over Time (chart): `event.dataset:sip`
- SIP - Source IP Address (table): `event.dataset:sip`
- SIP - Destination IP Address (table): `event.dataset:sip`
- SIP - Request Path (table): `event.dataset:sip`
- SIP - URI (table): `event.dataset:sip`
- SIP - User Agent (table): `event.dataset:sip`
- SIP - Content Type (pie chart): `event.dataset:sip`
- SIP - Method (chart): `event.dataset:sip`
- SIP - Destination Port (table): `event.dataset:sip`
- SIP - Log Count (metric): `event.dataset:sip`
- SIP - Status (table): `event.dataset:sip`
- SIP - Logs (Discover table of id.orig_h, id.resp_h, id.resp_p, method, content_type, status_msg, uid): `event.dataset:sip`

### SMB (`smb.ndjson`)

- SMB - Log Count Over Time (chart): `event.dataset:(smb_files OR smb_mapping)`
- SMB - Source IP Address (table): `event.dataset:(smb_files OR smb_mapping)`
- SMB - Destination IP Address (table): `event.dataset:(smb_files OR smb_mapping)`
- SMB - Version (pie chart): `event.dataset:(smb_files OR smb_mapping)`
- SMB - FIle Path (table): `event.dataset:(smb_files OR smb_mapping)`
- SMB - File Name (table): `event.dataset:(smb_files OR smb_mapping)`
- SMB - File/Path Summary (table): `event.dataset:(smb_files OR smb_mapping)`
- SMB - Log Count (metric): `event.dataset:(smb_files OR smb_mapping)`
- SMB - Destination Port (table): `event.dataset:(smb_files OR smb_mapping)`
- SMB Action (table): `event.dataset:(smb_files OR smb_mapping)`
- SMB - Logs (Discover table of event.dataset, id.orig_h, id.resp_h, id.resp_p, version, action, uid): `event.dataset:(smb_files OR smb_mapping)`

### SMTP (`smtp.ndjson`)

- SMTP - Log Count Over Time (chart): `event.dataset:smtp`
- SMTP - Subject (table): `event.dataset:smtp`
- SMTP - "From" Address (table): `event.dataset:smtp`
- SMTP - "To" Address (table): `event.dataset:smtp`
- SMTP - TLS (pie chart): `event.dataset:smtp`
- SMTP - Source IP Address (table): `event.dataset:smtp`
- SMTP - Destination IP Address (table): `event.dataset:smtp`
- SMTP - User Agent (table): `event.dataset:smtp`
- SMTP - Destination Port (table): `event.dataset:smtp`
- SMTP - Log Count (metric): `event.dataset:smtp`
- SMTP - Logs (Discover table of x_originating_ip, id.orig_h, id.resp_h, id.resp_p, mailfrom, user_agent, uid): `event.dataset:smtp`

### SNMP (`snmp.ndjson`)

- SNMP - Log Count Over Time (chart): `event.dataset:snmp`
- SNMP - Source IP Address (table): `event.dataset:snmp`
- SNMP - Destination IP Address (table): `event.dataset:snmp`
- SNMP - Session Duration (table): `event.dataset:snmp`
- SNMP - Log Count (metric): `event.dataset:snmp`
- SNMP - Community String (table): `event.dataset:snmp`
- SNMP - Logs (Discover table of id.orig_h, id.resp_h, id.resp_p, version, community, uid): `event.dataset:snmp`

### SSH (`ssh.ndjson`)

- SSH - Log Count Over Time (chart): `event.dataset:ssh`
- SSH - Source IP Address (table): `event.dataset:ssh`
- SSH - Destination IP Address (table): `event.dataset:ssh`
- SSH - Client/Server (table): `event.dataset:ssh`
- SSH - Log Count (metric): `event.dataset:ssh`
- SSH -Server (table): `event.dataset:ssh`
- SSH - Version (pie chart): `event.dataset:ssh`
- SSH - Logs (Discover table of id.orig_h, id.resp_h, id.resp_p, auth_success, cipher_alg, mac_alg, uid): `event.dataset:ssh`

### SSL (`ssl.ndjson`)

- SSL - Log Count Over Time (chart): `event.dataset:ssl`
- SSL - Version (pie chart): `event.dataset:ssl`
- SSL - Source IP Address (table): `event.dataset:ssl`
- SSL - Destination Port (table): `event.dataset:ssl`
- SSL - Destination Address (table): `event.dataset:ssl`
- SSL - Log Count (metric): `event.dataset:ssl`
- SSL - Connection Established (pie chart): `event.dataset:ssl`
- SSL - Certificate Fingerprint (table): `event.dataset:ssl`
- SSL - Elliptic Curve (chart): `event.dataset:ssl`
- SSL - Next Protocol (table): `event.dataset:ssl`
- SSL - Logs (Discover table of id.orig_h, id.resp_h, id.resp_p, server_name, established, ssl_history, sni_matches_cert, uid): `event.dataset:ssl`

### X.509 (`x-509.ndjson`)

- X.509 - Log Count Over Time (chart): `event.dataset:x509`
- X.509 - Certificate Signing Algorithm (pie chart): `event.dataset:x509`
- X.509 - Certificate Subject (table): `event.dataset:x509`
- X.509 - Certificate Issuer (table): `event.dataset:x509`
- X.509 - Certificate Key Length (chart): `event.dataset:x509`
- X.509 - Certificate Key Algorithm (chart): `event.dataset:x509`
- X.509 - Log Count (metric): `event.dataset:x509`
- OCSP - Certificate Revocation (table): `(event.dataset:ocsp) AND (NOT certStatus:good)`
- X.509 - Is Host Certificate (pie chart): `event.dataset:x509`
- X.509 - Is Client Certificate (pie chart): `event.dataset:x509`
- X.509 - Certificate Fingerprint (table): `event.dataset:x509`
- X.509 - Logs (Discover table of host_cert, client_cert, certificate.sig_alg, certificate.version): `event.dataset:x509`
- OCSP - Logs (Discover table of thisUpdate, nextUpdate, certStatus, revokereason, revoketime, serialNumber, id): `event.dataset:ocsp`

### Syslog (`syslog.ndjson`)

- Syslog - Log Count Over Time (chart): `event.dataset:syslog`
- Syslog - Source IP Address (table): `event.dataset:syslog`
- Syslog - Destination IP Address (table): `event.dataset:syslog`
- Syslog - Destination Port (table): `event.dataset:syslog`
- Syslog - Log Count (metric): `event.dataset:syslog`
- Syslog - Severity (pie chart): `event.dataset:syslog`
- Syslog - Facility (chart): `event.dataset:syslog`
- Syslog - Protocol (pie chart): `event.dataset:syslog`
- Syslog (Zeek) - Logs (Discover table of id.orig_h, id.resp_h, id.resp_p, severity, facility, message, uid): `event.dataset:syslog`

### Tunnels (`tunnels.ndjson`)

- Tunnels - Log Count Over Time (chart): `event.dataset:tunnel`
- Tunnels - Type (pie chart): `event.dataset:tunnel`
- Tunnels - Destination Address (table): `event.dataset:tunnel`
- Tunnels - Source IP Address (table): `event.dataset:tunnel`
- Tunnels - Action (chart): `event.dataset:tunnel`
- Tunnels - Log Count (metric): `event.dataset:tunnel`
- Tunnels - Logs (Discover table of id.orig_h, id.orig_p, id.resp_h, id.resp_p, action, tunnel_type, uid): `event.dataset:tunnel`

### Modbus (`modbus.ndjson`)

- Modbus - Logs (Discover table of id.orig_h, id.resp_h, id.resp_p, func, exception, unit, tid, uid): `event.dataset:modbus`
- Modbus - Source IP (table): `event.dataset:modbus`
- Modbus - Destination IP (table): `event.dataset:modbus`
- Modbus - Log Count (metric): `event.dataset:modbus`
- Modbus - Logs Over Time (chart): `event.dataset:modbus`
- Modbus - Functions and Exceptions (table): `(event.dataset:modbus) AND (func:* OR exception:*)`

### DNP3 (`dnp3.ndjson`)

- DNP3 - Source IP (table): `event.dataset:dnp3`
- DNP3 - Destination IP (table): `event.dataset:dnp3`
- DNP3 - Function Request (table): `event.dataset:dnp3`
- DNP3 - Function Reply (table): `event.dataset:dnp3`
- DNP3 - Log Count (metric): `event.dataset:dnp3`
- DNP3 - Logs Over Time (chart): `event.dataset:dnp3`
- DNP3 - Logs (Discover table of id.orig_h, id.resp_h, id.resp_p, fc_request, fc_reply, uid): `event.dataset:dnp3`
