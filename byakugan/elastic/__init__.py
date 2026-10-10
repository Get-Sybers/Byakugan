"""Byakugan's Elastic runtime: the CAR->ECS projection engine and the
load/timeline Elastic transport.

`projection.py` is the forward CAR->ECS projector and `inverse_projection.py`
its companion inverse (ECS->CAR, `byakugan timeline --elastic`); `load.py` is
`byakugan load` — a materialised CAR tree projected into an Elastic stack's
`logs-car.*` data streams, bundle or push mode; `_http.py` is the shared
stdlib-only HTTP plumbing (auth headers, TLS context, the one JSON request
primitive) both `load.py` and `byakugan/timeline.py`'s own `--elastic` fetch
go through. The projection CONTRACT these modules read — conventions.yml,
objects/<object>.yml, relationships.yml, inferred.yml, content.yml,
ecs_types.yml — is not code and lives at the repo root's `model/projection/`
(see that directory's own README.md); the RENDERED tree it produces — the
repo-root `elastic/` (component/index templates, the Byakugan Kibana space)
— is what `load.py --setup` applies (see elastic/README.md).
"""
