# Ingest: ForensicArtifacts

`ingest.py` reads the `model/sources/forensicartifacts/` submodule and
writes the committed structural index `index.json` (canonical; the
submodule is refresh-time only).

```
python pipeline/ingest/forensicartifacts/ingest.py          # regenerate
python pipeline/ingest/forensicartifacts/ingest.py --check  # drift/staleness gate
```

Full documentation — contract, refresh procedure, CI posture, role in the
schema mission: [docs/pipelines/ingest/forensicartifacts.md](../../../docs/pipelines/ingest/forensicartifacts.md).
