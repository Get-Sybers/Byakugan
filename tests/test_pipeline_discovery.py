"""Source discovery over the GoDFIR-toolz framework layouts DX_DFIR's lanes write
(one folder per item — windows_logs/<item>/goevtx.jsonl,
log2timeline/jsonl/<source>/timeline.jsonl, godfir-toolz/<tool>/<item>/<tool>.jsonl)
beside the older per-host / per-image layouts, and that every discovered source
is ingested into its own store through the Go engine (the isolation rule)."""
import os

import pytest

from byakugan import pipeline
from go_engine import _binary
from processed_fixtures import (GOESE_INDEX, GOESE_NETWORK_USAGE, GOEVTX_4624, GORE_VALUE, PSORT_PREFETCH,
                                _GOESE_ITEM, jsonl, write_framework_tree)


def test_framework_files_are_routed():
    # the Go tools write <tool>.jsonl in the shape their map consumes: the file name is the route
    assert pipeline.route("goevtx.jsonl") == pipeline.EVTX_MAPS
    assert pipeline.route("gore.jsonl") == ["recmd_batch"]
    assert pipeline.route("goprefetch.jsonl") == ["prefetch_dump"]
    assert pipeline.route("gojle.jsonl") == ["jlecmd_dest"]
    assert pipeline.route("NetworkDataUsage.jsonl") == ["esedump_srum"]
    # known, not unknown: the index and the tools with no CAR map route to nothing explicitly
    for name in ("goese.jsonl", "gomft.jsonl", "gole.jsonl", "gorb.jsonl", "gosbe.jsonl",
                 "goamcache.jsonl", "goappcompat.jsonl", "gowxt.jsonl"):
        assert pipeline.route(name) == [], name
    # every known Go tool's <tool>.jsonl has an explicit route (mapped, or to nothing)
    for tool in pipeline.GODFIR_TOOLS:
        assert any(pattern in f"{tool}.jsonl" for pattern, _keys in pipeline.ROUTES), tool


def test_framework_layouts_are_discovered(tmp_path):
    expected = write_framework_tree(tmp_path)
    found = {name: (path, host) for name, path, host in pipeline.discover_sources(str(tmp_path))}
    assert set(found) == set(expected)
    # one goevtx item (one log) is one source, the directory holding goevtx.jsonl
    assert found["windows_logs_HOST01_Security.evtx"] == (
        str(tmp_path / "windows_logs" / "HOST01_Security.evtx"), None)
    # psort's per-item folder: the rendered timeline is the source file
    assert found["l2t_M57-JO.E01"] == (
        str(tmp_path / "log2timeline" / "jsonl" / "M57-JO.E01" / "timeline.jsonl"), None)
    # one Go-tool item is one source — its directory, and no host is claimed
    # (the item is a path, not a host)
    assert found["godfir_toolz_gore_img_Windows_System32_config_SOFTWARE"] == (
        str(tmp_path / "godfir-toolz" / "gore" / "img_Windows_System32_config_SOFTWARE"), None)
    assert all(host is None for _p, host in found.values())
    # the lanes' staging directories (the image exports) are never sources
    assert not any("_extracted" in name for name in found)


def test_psort_root_and_raw_container_layouts(tmp_path):
    # a psort output root mounted directly (jsonl/<source>/timeline.jsonl) and a
    # raw container beside the per-item folders are each one source
    jsonl(str(tmp_path / "jsonl" / "imgA" / "timeline.jsonl"), PSORT_PREFETCH)
    jsonl(str(tmp_path / "log2timeline" / "jsonl" / "imgB.jsonl"), PSORT_PREFETCH)
    jsonl(str(tmp_path / "log2timeline" / "jsonl" / "imgC" / "timeline.jsonl"), PSORT_PREFETCH)
    (tmp_path / "log2timeline" / "jsonl" / "imgD").mkdir()          # no timeline yet: not a source
    found = {name: path for name, path, _h in pipeline.discover_sources(str(tmp_path))}
    assert found == {
        "l2t_imgA": str(tmp_path / "jsonl" / "imgA" / "timeline.jsonl"),
        "l2t_imgB": str(tmp_path / "log2timeline" / "jsonl" / "imgB.jsonl"),
        "l2t_imgC": str(tmp_path / "log2timeline" / "jsonl" / "imgC" / "timeline.jsonl"),
    }


def test_older_layouts_still_discover_beside_the_framework_ones(tmp_path):
    write_framework_tree(tmp_path)
    # a host's EvtxECmd export (a directory of channels) and a godfir-toolz/<host>/
    # tree (no per-tool items) keep their per-host sources and fallback host
    jsonl(str(tmp_path / "windows_logs" / "hostA" / "Security_EvtxECmd_Output.json"), {"EventId": 1})
    jsonl(str(tmp_path / "godfir-toolz" / "hostB" / "PrefetchDump_Output.json"), {"Executable": "X"})
    found = {name: (path, host) for name, path, host in pipeline.discover_sources(str(tmp_path))}
    assert found["windows_logs_hostA"] == (str(tmp_path / "windows_logs" / "hostA"), None)
    assert found["godfir_toolz_hostB"] == (str(tmp_path / "godfir-toolz" / "hostB"), "HOSTB")
    assert "godfir_toolz_gore_img_Windows_System32_config_SOFTWARE" in found


def test_a_tool_dir_without_finished_items_yields_no_source(tmp_path):
    """A known Go tool's directory with no finished item — empty (the tool found
    nothing to parse) or an item still being written — is never a spurious
    host; the legacy host rule applies only to directories that are not tool
    directories."""
    gt = tmp_path / "godfir-toolz"
    (gt / "gore").mkdir(parents=True)                                  # ran, found no hive
    (gt / "goprefetch" / "img_Windows_Prefetch_X.pf").mkdir(parents=True)
    (gt / "goprefetch" / "img_Windows_Prefetch_X.pf" / "goprefetch.jsonl.part").write_text("")
    assert pipeline.discover_sources(str(tmp_path)) == []
    # beside them: a legacy host tree keeps its host, and a tool this engine
    # does not know yet is still a tool directory by its <item>/<name>.jsonl shape
    jsonl(str(gt / "hostB" / "PrefetchDump_Output.json"), {"Executable": "X"})
    jsonl(str(gt / "gonew" / "img_thing" / "gonew.jsonl"), {"k": "v"})
    found = {name: (path, host) for name, path, host in pipeline.discover_sources(str(tmp_path))}
    assert found == {
        "godfir_toolz_hostB": (str(gt / "hostB"), "HOSTB"),
        "godfir_toolz_gonew_img_thing": (str(gt / "gonew" / "img_thing"), None),
    }
    assert not any(host in ("GORE", "GOPREFETCH") for _p, host in found.values())


def test_framework_sources_are_ingested_one_store_each(tmp_path):
    _binary()                                    # the Go parse engine (built, or the test skips)
    expected = write_framework_tree(tmp_path)
    out = tmp_path / "car"
    results = {r["source"]: r for r in pipeline.run_batch(str(tmp_path), str(out))}
    assert set(results) == set(expected)
    for name, obj in expected.items():
        r = results[name]
        assert "error" not in r, r
        assert (out / name / "car_relationships.jsonl").is_file()  # ISOLATION: its own materialised tree
        if obj:
            assert r["objects"].get(obj, 0) >= 1, (name, r["objects"])
            assert (out / name / f"car_{obj}.jsonl").is_file()
        else:
            assert r["events"] == 0 and r["artefacts"] == []       # routed to nothing: an empty store, no error
    # the goevtx record fed the whole evtx map family (content-routed)
    assert results["windows_logs_HOST01_Security.evtx"]["objects"] == {
        "authentication": 1, "user_session": 1}
    # idempotent: a second run skips every source
    assert all(r.get("skipped") == "exists" for r in pipeline.run_batch(str(tmp_path), str(out)))


@pytest.mark.parametrize("name", ["windows_logs", "godfir-toolz", "log2timeline", "jsonl", "zeek", "memory"])
def test_an_absent_or_empty_lane_dir_discovers_nothing(tmp_path, name):
    assert pipeline.discover_sources(str(tmp_path)) == []
    (tmp_path / name).mkdir()
    assert pipeline.discover_sources(str(tmp_path)) == []
    assert not os.listdir(tmp_path / name)


# --------------------------------------------------------------------------- #
# DX_DFIR's current layout: processed/<tool>/[<collection>/]<host>/… — the
# leaf is the tool, a collection-scoped run one level below it, the tool's own
# per-item folders under that (windowlicker: <collection>/<subtool>/<host>/<item>/).
# --------------------------------------------------------------------------- #
def _write_tool_tree(root, collection: str | None) -> dict[str, str]:
    """One source per lane under the tool-named leaves, scoped to
    `collection` (None = an unscoped run: the host level sits directly under
    the leaf). Returns {expected source name: its source file/dir}."""
    root = str(root)
    c = [collection] if collection else []
    tag = f"{collection}_" if collection else ""
    wl = os.path.join(root, "windowlicker", *c)
    dh = os.path.join(root, "daemonhunter", *c)
    l2t = os.path.join(root, "log2timeline", *c)
    zk = os.path.join(root, "zeek", *c)
    mem = os.path.join(root, "anamnesis", *c)
    jsonl(os.path.join(wl, "goevtx", "HOST01", "Security.evtx", "goevtx.jsonl"), GOEVTX_4624)
    jsonl(os.path.join(wl, "gore", "img.E01", "Windows_System32_config_SOFTWARE", "gore.jsonl"), GORE_VALUE)
    jsonl(os.path.join(wl, "goese", "img.E01", _GOESE_ITEM, "NetworkDataUsage.jsonl"), GOESE_NETWORK_USAGE)
    jsonl(os.path.join(wl, "goese", "img.E01", _GOESE_ITEM, "goese.jsonl"), GOESE_INDEX)
    jsonl(os.path.join(dh, "gojournal", "srv.E01", "var_log_journal_x.journal", "gojournal.jsonl"), {"k": "v"})
    # the knowledge store is enrichment, never a source; the shared export is staging
    jsonl(os.path.join(dh, "knowledge", "srv.E01", "etc_os-release", "gohost.jsonl"), {"k": "v"})
    os.makedirs(os.path.join(root, "_extracted", *c, "img.E01", "export", "Windows"))
    jsonl(os.path.join(root, "_extracted", *c, "img.E01", "image_export.jsonl"), {"item": "img.E01"})
    # plaso: the rendered timeline beside the storage file, one <host>/ folder
    jsonl(os.path.join(l2t, "img.E01", "timeline.jsonl"), PSORT_PREFETCH)
    jsonl(os.path.join(l2t, "img.E01", "psort.jsonl"), {"timeline": "timeline.jsonl"})
    jsonl(os.path.join(l2t, "img.E01", "log2timeline.jsonl"), {"storage_file": "img.E01.plaso"})
    with open(os.path.join(l2t, "img.E01", "img.E01.plaso"), "wb") as fh:
        fh.write(b"plaso")
    jsonl(os.path.join(zk, "cap.pcap", "conn.json"), {"ts": "2020-01-01T00:00:01Z", "uid": "C1"})
    jsonl(os.path.join(zk, "cap.pcap", "zeek.jsonl"), {"logs": ["conn"]})
    os.makedirs(os.path.join(mem, "dump.raw"))
    with open(os.path.join(mem, "dump.raw", "car.db"), "wb") as fh:
        fh.write(b"")
    return {
        f"windowlicker_{tag}goevtx_HOST01_Security.evtx": os.path.join(wl, "goevtx", "HOST01", "Security.evtx"),
        f"windowlicker_{tag}gore_img.E01_Windows_System32_config_SOFTWARE":
            os.path.join(wl, "gore", "img.E01", "Windows_System32_config_SOFTWARE"),
        f"windowlicker_{tag}goese_img.E01_{_GOESE_ITEM}": os.path.join(wl, "goese", "img.E01", _GOESE_ITEM),
        f"daemonhunter_{tag}gojournal_srv.E01_var_log_journal_x.journal":
            os.path.join(dh, "gojournal", "srv.E01", "var_log_journal_x.journal"),
        f"l2t_{tag}img.E01": os.path.join(l2t, "img.E01", "timeline.jsonl"),
        f"zeek_{tag}cap.pcap": os.path.join(zk, "cap.pcap"),
        f"anamnesis_{tag}dump.raw": os.path.join(mem, "dump.raw", "car.db"),
    }


@pytest.mark.parametrize("collection", [None, "case-a"])
def test_tool_leaf_layouts_are_discovered(tmp_path, collection):
    expected = _write_tool_tree(tmp_path, collection)
    found = {name: (path, host) for name, path, host in pipeline.discover_sources(str(tmp_path))}
    assert {n: p for n, (p, _h) in found.items()} == expected
    # only a zeek capture claims a host (its folder name); a goevtx item is one
    # source, once — not a second time through the framework walk
    assert found[f"zeek_{collection + '_' if collection else ''}cap.pcap"][1] == "cap.pcap"
    assert all(h is None for n, (_p, h) in found.items() if not n.startswith("zeek_"))
    assert not any("_extracted" in n or "knowledge" in n for n in found)


def test_two_collections_are_distinct_sources(tmp_path):
    a = _write_tool_tree(tmp_path, "case-a")
    b = _write_tool_tree(tmp_path, "case-b")
    found = {name for name, _p, _h in pipeline.discover_sources(str(tmp_path))}
    assert found == set(a) | set(b)
    assert len(found) == len(a) + len(b)


def test_engine_and_detection_leaves_are_never_sources(tmp_path):
    # the engine's own output (a timeline.jsonl in a car tree, the loader's
    # state), the exchange and the detection lane's tree hold no CAR source
    jsonl(str(tmp_path / "byakugan" / "zeek_cap" / "timeline.jsonl"), {"k": "v"})
    jsonl(str(tmp_path / "byakugan" / "zeek_cap" / "car_relationships.jsonl"), {"k": "v"})
    jsonl(str(tmp_path / "byakugan-load" / "manifest.jsonl"), {"k": "v"})
    jsonl(str(tmp_path / "exchange" / "bundle.jsonl"), {"k": "v"})
    jsonl(str(tmp_path / "detections" / "hayabusa" / "case-a" / "HOST01" / "timeline.jsonl"), {"k": "v"})
    jsonl(str(tmp_path / "detections" / "yara" / "HOST01" / "yara.jsonl"), {"k": "v"})
    assert pipeline.discover_sources(str(tmp_path)) == []
