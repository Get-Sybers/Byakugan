# `elastic/malcolm/` — the `malcolm` Kibana space

A Kibana space named `malcolm` holding 36 dashboards derived from the
[cisagov/Malcolm](https://github.com/cisagov/Malcolm) project, converted to
the documents DX_DFIR's Filebeat writes for Zeek and Suricata, together with
the Elasticsearch ingest pipelines and index templates that give those
documents the fields the dashboards query. An Ansible role loads all of it.

## Layout

```
elastic/malcolm/
├── README.md                       this file
├── DASHBOARDS.md                   every dashboard: file, data view, the logs it selects, its panels
├── LICENSE.Malcolm.txt             Malcolm's licence notice (Apache License 2.0)
├── ansible/
│   ├── malcolm-space.yml           the playbook: runs the malcolm_space role on localhost
│   └── roles/malcolm_space/        pipelines and templates -> stream rollover -> space -> import
├── elasticsearch/
│   ├── ingest_pipelines/           logs-dxdfir.zeek@malcolm, logs-dxdfir.detections@malcolm
│   ├── component_templates/        the same two names: bind the pipeline, type the fields it adds
│   └── index_templates/            logs-dxdfir.zeek, logs-dxdfir.detections
├── kibana/
│   ├── space.json                  the space (id malcolm)
│   ├── data-views.ndjson           malcolm-zeek, malcolm-suricata
│   └── dashboards/<name>.ndjson    one file per dashboard: its saved searches, then the dashboard
└── test_malcolm_assets.py          structural checks (pytest; the repository's `pytest -q` collects it)
```

## What the dashboards read

DX_DFIR's Filebeat (the `dxdfir_stack` role's `filebeat.yml` in the DX_DFIR
repository) ships every `*.json` and `*.jsonl` file under `/ingest/<type>/**`
through the `ndjson` parser (`expand_keys: true`) into the data stream
`logs-dxdfir.<type>-<namespace>`, where `<type>` is the first directory under
`/ingest`. Two of those streams feed this space.

| Stream | Written by | Files | Documents |
|---|---|---|---|
| `logs-dxdfir.zeek-*` | the Zeek lane: Zeek 9.0 run as `zeek -C -r <capture> LogAscii::use_json=T LogAscii::json_timestamps=JSON::TS_ISO8601` with its default script set (`ZEEK_SCRIPTS` empty) | `zeek/<item>/<log>.json` and the index `zeek/<item>/zeek.jsonl` | one per Zeek log record, fields named as Zeek writes them (`ts`, `uid`, `id.orig_h`, `conn_state`, …) |
| `logs-dxdfir.detections-*` | the signatures lane: Suricata EVE output, YARA and Hayabusa | `detections/suricata/<item>/eve.json` and its index `suricata.jsonl`; `detections/yara/…`; `detections/hayabusa/…` | one per EVE record (`timestamp`, `event_type`, `src_ip`, `alert.signature`, …); one per YARA or Hayabusa record |

Filebeat sets up neither an index template nor an ingest pipeline, so these
streams are created by Elasticsearch's built-in `logs` index template:
`logs@mappings` turns date detection off, `ecs@mappings` maps every string to
`keyword` and every field named `*.ip` or `*_ip` to `ip`; numbers and booleans
map by their JSON type. Filebeat sets `@timestamp` to the time it read the line
and `log.file.path` to the file it read.

## The ingest side: `elasticsearch/`

Two ingest pipelines, bound to the streams through component and index
templates.

`logs-dxdfir.zeek@malcolm`

1. copies Filebeat's `@timestamp` to `event.ingested`;
2. sets `@timestamp` from the record's `ts` (ISO 8601); a value that does not
   parse leaves `@timestamp` as it was and adds the tag `malcolm_ts_unparsed`;
3. sets `event.dataset` to the log name taken from the file name (`conn.json`
   gives `conn`; the `zeek.jsonl` index file gives `zeek_index`);
4. sets `event.provider` to `zeek`;
5. on `conn` records sets `network.bytes` to `orig_ip_bytes + resp_ip_bytes`;
6. runs `logs@default-pipeline` when that pipeline exists.

`logs-dxdfir.detections@malcolm`

1. copies `@timestamp` to `event.ingested`;
2. sets `event.provider` from the directory the file sits in (`suricata`,
   `hayabusa` or `yara`; a record with an `event_type` and none of those
   directories counts as Suricata) and `event.dataset` to the Suricata
   `event_type` (the `suricata.jsonl` index file gives `suricata_index`) or to
   the tool name for YARA and Hayabusa records; Suricata `alert` records also
   get `event.kind: alert`;
3. sets `@timestamp` from a Suricata record's `timestamp` (tag
   `malcolm_timestamp_unparsed` when it does not parse);
4. runs `logs@default-pipeline` when it exists.

Both pipelines leave the record's own fields untouched. The fields they add
are `@timestamp`, `event.ingested`, `event.dataset`, `event.provider`,
`event.kind` (Suricata alerts) and `network.bytes` (Zeek conn).

The component templates (`logs-dxdfir.zeek@malcolm`,
`logs-dxdfir.detections@malcolm`) set `index.default_pipeline` to the pipeline
of the same name, type the added fields and raise
`index.mapping.total_fields.limit` to 4000. The index templates
(`logs-dxdfir.zeek`, `logs-dxdfir.detections`) match `logs-dxdfir.zeek-*` and
`logs-dxdfir.detections-*` at priority 200, above the built-in `logs`
template's 100, and compose the stack's own `logs@mappings`, `logs@settings`,
`logs@custom` (when present) and `ecs@mappings` before the component template:
the mapping stays what the built-in template produces, plus the fields above.

A template applies to the backing indices created after it, so the role rolls
over every existing stream whose write index is not on the pipeline. Documents
indexed before that rollover keep Filebeat's read time in `@timestamp` and
carry no `event.dataset`.

Every object carries `_meta.version`. The role writes an object only when the
stored version differs from the file's, so a change to one of these files goes
with a version bump.

## The Kibana side: `kibana/`

- `space.json`: the space (`id: malcolm`, name `Malcolm`, initials `Ma`,
  colour `#54B399`, every Kibana feature enabled).
- `data-views.ndjson`: `malcolm-zeek` on `logs-dxdfir.zeek-*` and
  `malcolm-suricata` on `logs-dxdfir.detections-*`, time field `@timestamp`.
- `dashboards/<name>.ndjson`: one file per dashboard holding the saved
  searches the dashboard embeds (Discover tables, referenced by id) followed by
  the dashboard itself. Charts are Lens visualisations stored by value in the
  dashboard (data table, pie chart, metric, bar and line charts, tag cloud).
  The navigation panel at the top of every dashboard is a markdown
  visualisation whose links use the dashboards' ids; the HTTP dashboard's
  method-to-status sankey is a Vega visualisation. Object ids are fixed, so a
  re-import with `overwrite` updates the objects in place. Every panel query
  is KQL on the data view: `event.dataset:<log>` selects a Zeek log,
  `event.provider:suricata AND event.dataset:alert` the Suricata alerts.

[DASHBOARDS.md](DASHBOARDS.md) lists every dashboard with its data view, the
logs it selects and its panels.

### Field names

Malcolm's dashboards use the ECS names its Logstash pipelines produce; these
use the names of the documents described above. A Zeek column name applies to
the log that carries it.

| Malcolm | Zeek (`logs-dxdfir.zeek-*`) | Suricata (`logs-dxdfir.detections-*`) |
|---|---|---|
| `source.ip`, `source.port` | `id.orig_h`, `id.orig_p` (dhcp: `client_addr`) | `src_ip`, `src_port` |
| `destination.ip`, `destination.port` | `id.resp_h`, `id.resp_p` (dhcp: `server_addr`) | `dest_ip`, `dest_port` |
| `network.transport` | `proto` | `proto` |
| `network.protocol` as a filter | `event.dataset` | `event.dataset` |
| `network.protocol` bucketed over conn | `service` | `app_proto` |
| `network.protocol_version` | `version` | |
| `event.id` | `uid` (pe, ocsp: `id`; x509: `fingerprint`; dhcp: `uids`) | `flow_id` |
| `zeek.<log>.<field>` | `<field>`; renamed columns: `ssl_version` is `version`, `certificate_subject_full` is `certificate.subject`, `certificate_issuer_full` is `certificate.issuer`, kerberos `cname`/`sname` are `client`/`service`, ntlm `user`/`host`/`domain` are `username`/`hostname`/`domainname`, ldap `operation`/`result_code`/`result_message` are `opcode`/`result`/`diagnostic_message`, modbus `trans_id`/`unit_id` are `tid`/`unit`, redis `cmd_name`/`cmd_key`/`cmd_value`/`reply` are `cmd.name`/`cmd.key`/`cmd.value`/`reply.value`, dhcp `assigned_ip`/`requested_ip` are `assigned_addr`/`requested_addr`, conn `conn_state_description` is `conn_state` | |
| `event.action` | the log's own verb: http `method`, dns `opcode_name`, ftp `command`, dce_rpc `operation`, dhcp `msg_types`, dnp3 `fc_request`, irc `command`, kerberos `request_type`, ldap `opcode`, modbus `func`, mqtt_subscribe `action`, mysql `cmd`, ntp `mode`, postgresql `frontend`, redis `cmd.name`, sip `method`, smb_files `action`, tunnel `action` | `alert.action` |
| `event.result` | the log's own outcome: http `status_code`, dns `rcode_name`, ftp `reply_code`, dhcp `server_message`, dnp3 `fc_reply`, kerberos/mysql/postgresql/redis/ntlm `success`, ldap and ldap_search `result`, modbus `exception`, mqtt_connect `connect_status`, mqtt_publish `status`, rdp `result`, sip `status_code`, smtp `last_reply`, ssh `auth_success`, ssl `last_alert` | |
| `rule.name`, `rule.category`, `rule.id` | weird: `name` | `alert.signature`, `alert.category`, `alert.signature_id` |
| `event.severity` | | `alert.severity` |
| `related.user`, `related.password` | `user` (http, ntlm, radius: `username`), `password` | |
| `user_agent.original`, `url.original` | `user_agent`, `uri` | |
| `file.mime_type`, `file.name`, `file.size`, `file.source` | `mime_type` (http: `resp_mime_types`), `filename`, `total_bytes`, `source` | |
| `source.bytes`, `destination.bytes` | `orig_ip_bytes`, `resp_ip_bytes` | |
| `client.bytes`, `server.bytes` | `orig_bytes`, `resp_bytes` | |
| `source.packets`, `destination.packets` | `orig_pkts`, `resp_pkts` | |
| `network.bytes` (conn) | `network.bytes`, added by the pipeline | |
| `event.duration` | `duration` (seconds) | |
| `quic.host`, `quic.version` | `server_name`, `version` | |
| `@timestamp`, `event.dataset`, `event.provider`, `event.ingested`, `host.name` | the same names, set by the pipeline or by Filebeat | the same names |

### Scope

The space holds the Malcolm dashboards whose panels can be computed from
Zeek's default-script logs and Suricata's EVE records: the general dashboards
(Overview, Connections, Files, Executables, Zeek Weird, Suricata Alerts), one
dashboard per Zeek protocol log, and Modbus and DNP3 from Zeek's base
analyzers. It does not hold:

- panels that need Malcolm's enrichment: GeoIP, MAC and OUI, NetBox inventory,
  severity and risk scores, domain randomness scores, JA4 fingerprints,
  community ids, direction and subnet names, ATT&CK and vulnerability tags,
  file extraction and file scanning;
- dashboards and panels for Zeek logs the default script set does not write
  (notice, intel, signatures, software, known_hosts, known_services,
  known_certs, smb_cmd) or for the Zeek packages Malcolm installs (the ICSNPP
  protocol analyzers and their detailed Modbus and DNP3 logs, JA4, STUN,
  OSPF, TDS, TFTP);
- Malcolm's own host and beats telemetry, the map dashboards (their panel
  types were removed in Kibana 8) and the Security Overview, Severity and
  Actions and Results dashboards, which count Zeek and Suricata records in one
  shared field set.

## Loading it: `ansible/`

`malcolm-space.yml` runs the `malcolm_space` role on `localhost`
(`malcolm_hosts` and `malcolm_connection` override the target). The role:

1. puts the ingest pipelines, then the component templates, then the index
   templates (an object is written when it is missing or its `_meta.version`
   differs from the file's);
2. rolls over every existing `logs-dxdfir.zeek-*` and
   `logs-dxdfir.detections-*` data stream whose write index does not have the
   pipeline as `index.default_pipeline` (`malcolm_space_rollover: false` skips
   this step);
3. creates the Kibana space from `kibana/space.json`, or updates it when one
   of its fields differs;
4. imports `data-views.ndjson`, then every `dashboards/*.ndjson`, into the
   space with `overwrite=true`.

Steps 1 to 3 report `changed` only when they write; step 4 reports `changed`
whenever Kibana writes an object, which it does on every import. The role
authenticates with basic auth as `malcolm_space_elastic_user` on both
services; writing pipelines and templates, rolling streams over and managing
spaces take the `elastic` superuser's privileges. It needs ansible-core 2.10
or later (`ansible.builtin.uri` with `body_format: form-multipart`) and no
collection beyond `ansible.builtin`.

| Variable | Default | Meaning |
|---|---|---|
| `malcolm_space_es_url` | `https://127.0.0.1:9200` | Elasticsearch |
| `malcolm_space_kibana_url` | `http://127.0.0.1:5601` | Kibana, without a space prefix |
| `malcolm_space_elastic_user` | `elastic` | the user for both services |
| `malcolm_space_elastic_password` | required | its password; never logged |
| `malcolm_space_ca_file` | `""` | PEM CA certificate for https endpoints; empty uses the system trust store |
| `malcolm_space_validate_certs` | `true` | verify TLS certificates |
| `malcolm_space_id` | `malcolm` | the space id; matches `kibana/space.json` |
| `malcolm_space_rollover` | `true` | roll over streams whose write index is not on the pipeline |
| `malcolm_space_streams` | the two streams above | pattern and the pipeline each must be on |
| `malcolm_space_assets_dir` | `elastic/malcolm` | the directory holding `kibana/` and `elasticsearch/` |

On a DX_DFIR host the values come from its inventory: `dxdfir_elastic_bind`
and `dxdfir_elastic_es_port` (`127.0.0.1`, `9200`, https),
`dxdfir_elastic_kibana_port` (`5601`, http), the CA at
`ansible/inventory/secrets/<host>/certs/ca/ca.crt` and the `elastic` password
in `ansible/inventory/secrets/<host>/elastic_password`:

```sh
ansible-playbook elastic/malcolm/ansible/malcolm-space.yml \
  -e malcolm_space_es_url=https://127.0.0.1:9200 \
  -e malcolm_space_kibana_url=http://127.0.0.1:5601 \
  -e malcolm_space_ca_file=<dx_dfir>/ansible/inventory/secrets/<host>/certs/ca/ca.crt \
  -e malcolm_space_elastic_password="$(cat <dx_dfir>/ansible/inventory/secrets/<host>/elastic_password)"
```

Against the standalone stack in this directory (`elastic/docker-compose.yml`,
no TLS, ports 9201 and 5602) the same playbook takes
`-e malcolm_space_es_url=http://127.0.0.1:9201 -e malcolm_space_kibana_url=http://127.0.0.1:5602 -e malcolm_space_elastic_password="$ELASTIC_PASSWORD"`;
that stack has no Filebeat and no `logs-dxdfir.*` streams, so the rollover
step finds nothing and the dashboards fill once such streams exist.

## Changing a dashboard

Open the dashboard in the `malcolm` space, change it, then export it from
Stack Management › Saved Objects with its related objects (or
`POST /s/malcolm/api/saved_objects/_export` with `includeReferencesDeep: true`
and `excludeExportDetails: true`) and replace `kibana/dashboards/<name>.ndjson`
with the export, minus its `index-pattern` lines, which `data-views.ndjson`
owns. `pytest elastic/malcolm` checks the result's structure; the playbook
loads it. A field a dashboard needs and the pipeline must add goes into the
pipeline and its component template, each with `_meta.version` raised.

## Checks

```sh
pytest -q elastic/malcolm                                                  # structure of every file here
ansible-playbook -i localhost, --syntax-check elastic/malcolm/ansible/malcolm-space.yml
yamllint -c .yamllint elastic/malcolm/ansible
```

## Source and licence

The dashboards derive from Malcolm v26.09.0 (commit
`7cfac5bc448bd9031a2cbb35bd058d7253c2e2c8`, `dashboards/dashboards/*.json`),
Copyright 2026 Battelle Energy Alliance, LLC, Apache License 2.0;
`LICENSE.Malcolm.txt` is Malcolm's licence notice. They differ from the
originals in the field names, queries and data views described above, in the
visualisation format (Lens by value instead of the legacy aggregation-based
objects) and in the panels and dashboards outside the scope above, which are
absent. Everything else in this directory is under the repository's MIT
licence.
