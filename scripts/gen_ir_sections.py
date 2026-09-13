#!/usr/bin/env python3
"""One-time bootstrap: emit go/internal/authoring/ir_sections.go from the committed
ir.json (the static non-map IR sections). After phase 3 the Go authoring is the
source of truth (ir.json is generated FROM Go), so this is provenance only."""
import json
d = json.load(open("go/internal/ir/ir.json"))

def emit(v, indent=1):
    pad = "\t"*indent
    if v is None: return "nil"
    if v is True: return "true"
    if v is False: return "false"
    if isinstance(v, int): return f"pyjson.Int({v})"
    if isinstance(v, float):
        return f"float64({v!r})"
    if isinstance(v, str):
        return go_str(v)
    if isinstance(v, list):
        if not v: return "[]pyjson.Value{}"
        inner = ",\n".join(pad+"\t"+emit(x, indent+1) for x in v)
        return "pa(\n"+inner+",\n"+pad+")"
    if isinstance(v, dict):
        if not v: return "po()"
        parts=[]
        for k,val in v.items():
            parts.append(pad+"\t"+go_str(k)+", "+emit(val, indent+1))
        return "po(\n"+",\n".join(parts)+",\n"+pad+")"
    raise TypeError(type(v))

def go_str(s):
    # Go interpreted string literal; escape backslash, quote, and control.
    out = s.replace("\\","\\\\").replace('"','\\"').replace("\n","\\n").replace("\t","\\t").replace("\r","\\r")
    return '"'+out+'"'

sections = ["marker_kinds","routes","evtx_maps","adapters","canon_user","spindle","golden"]
funcs = {"marker_kinds":"irMarkerKinds","routes":"irRoutes","evtx_maps":"irEvtxMaps",
         "adapters":"irAdapters","canon_user":"irCanonUser","spindle":"irSpindle","golden":"irGolden"}

lines = []
lines.append("// Code generated from ir.json (phase-3 bootstrap of the non-map IR sections).")
lines.append("// The static IR data byakugan/{spindle.yml,pipeline.py,normalize.py} used to")
lines.append("// source, now authored in Go. Regenerate with tools/gen_ir_sections (bootstrap");
lines.append("// only — hand-maintained thereafter). DO NOT edit the Python sources for these.")
lines.append("")
lines.append("package authoring")
lines.append("")
lines.append('import "github.com/get-sybers/byakugan/go/internal/pyjson"')
lines.append("")
for s in sections:
    lines.append(f"func {funcs[s]}() pyjson.Value {{")
    lines.append("\treturn "+emit(d[s], 1))
    lines.append("}")
    lines.append("")
open("go/internal/authoring/ir_sections.go","w").write("\n".join(lines))
print("wrote go/internal/authoring/ir_sections.go", len("\n".join(lines)), "bytes")
