r"""B1: the volume GUID lifted to a first-class join key.

The cross-source value hunt found the CAR guid columns hold only minted
synthetic ids, so the strongest real key on a disk image — the globally-unique
`\\?\Volume{GUID}` that ties USN ↔ evtx ↔ registry ↔ mount table ↔ cloud-sync —
survived only as text in `native`. `native_ids.volume_guids` is the one shared
extractor; `enrich` lifts it into the queryable `volume_guid` column.
"""
from piiat_mitrecar import enrich, native_ids, store


def test_volume_guids_extracts_case_folds_dedupes():
    nat = {"path": r"\\?\Volume{09931F21-7FAF-44A9-81D8-1E73C14B9EAF}\x",
           "also": r"\??\Volume{09931f21-7faf-44a9-81d8-1e73c14b9eaf}"}
    # same volume in two cases -> one folded value
    assert native_ids.volume_guids(nat) == ["09931f21-7faf-44a9-81d8-1e73c14b9eaf"]


def test_volume_guids_accepts_str_dict_none():
    s = r"stuff \\?\Volume{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee} end"
    assert native_ids.volume_guids(s) == ["aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"]
    assert native_ids.volume_guids(None) == []
    assert native_ids.volume_guids({}) == []


def test_volume_guids_ignores_bare_com_guids():
    # a bare {8-4-4-4-12} with no Volume{ token is COM/CLSID noise, never a key
    assert native_ids.volume_guids({"clsid": "f750e6c3-38ee-11d1-85e5-00c04fc295ee"}) == []


def test_canonical_validates_and_folds():
    assert native_ids.canonical("09931F21-7FAF-44A9-81D8-1E73C14B9EAF") \
        == "09931f21-7faf-44a9-81d8-1e73c14b9eaf"
    assert native_ids.canonical("{09931f21-7faf-44a9-81d8-1e73c14b9eaf}") \
        == "09931f21-7faf-44a9-81d8-1e73c14b9eaf"
    # not a canonical GUID -> None (must not become a join key)
    for bad in (None, "", "not-a-guid", r"\\?\Volume{09931f21-7faf-44a9-81d8-1e73c14b9eaf}",
                "09931f21-7faf-44a9-81d8"):
        assert native_ids.canonical(bad) is None


def test_enrich_lifts_volume_guid_into_the_column():
    ev = {"car_object": "registry", "car_action": "value_edit", "guid": "r-1",
          "source_host": "PM6C56D", "timestamp": "2026-01-01T00:00:00Z",
          "_native": {"key_path": r"...\MountPoints2",
                      "data": r"\??\Volume{09931F21-7FAF-44A9-81D8-1E73C14B9EAF}"}}
    (out,) = enrich.enrich([ev])
    assert out["volume_guid"] == "09931f21-7faf-44a9-81d8-1e73c14b9eaf"  # folded into the column


def test_volume_guid_is_a_stored_column_on_every_object(tmp_path):
    # the non-MITRE header addition must be a real column on all 13 objects
    st = store.CarStore(str(tmp_path / "car.db"))
    try:
        for obj in st.model:
            assert "volume_guid" in st._cols(obj)
    finally:
        st.close()
