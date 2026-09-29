from hookconf.checks import ALL_IDS, CHECKS, NOT_TESTED_NOTES
from hookconf.levels import HARDENING, compute_levels, headline
from hookconf.report import markdown


def res(statuses):
    return [{"id": i, "status": s, "summary": f"{i} {s}", "evidence": {}, "sessions": []} for i, s in statuses.items()]


def all_ids(status="pass"):
    return {i: status for i in ALL_IDS}


def test_all_pass_reaches_l4_without_star():
    lv = compute_levels(res(all_ids()))
    assert lv["core"] == "L4" and lv["gaps"] == []
    assert headline(lv) == "Core L4 · hardening gaps: none found"


def test_hardening_failures_do_not_lower_core_level():
    st = all_ids()
    for i in ("B5", "B6", "A5", "A6", "M4"):
        st[i] = "fail"
    st["B5"] = "unsupported"
    lv = compute_levels(res(st))
    assert lv["core"] == "L4"
    assert lv["gaps"] == ["B5", "B6", "A5", "A6", "M4"]
    assert headline(lv).startswith("Core L4 · hardening gaps: B5 no fail-closed, B6 silent hook failure")


def test_interactive_untested_gives_star():
    st = all_ids()
    st["A1"] = st["P2"] = st["P3"] = "not_tested"
    lv = compute_levels(res(st))
    assert lv["core"] == "L4*" and lv["star"] is True
    assert lv["per_level"][2]["star"] and lv["per_level"][3]["untested"] == ["P2", "P3"]
    assert not lv["per_level"][4]["star"]


def test_other_untested_core_blocks():
    st = all_ids()
    st["B4"] = "not_tested"
    lv = compute_levels(res(st))
    assert lv["core"] == "L0"
    assert lv["per_level"][1]["blocking_status"] == {"B4": "not_tested"}


def test_star_carries_to_higher_levels_and_stops_at_first_unmet():
    st = all_ids()
    st["A1"] = "not_tested"
    st["P1"] = "fail"
    assert compute_levels(res(st))["core"] == "L2*"
    st = all_ids()
    st["O2"] = "fail"
    assert compute_levels(res(st))["core"] == "none"


def test_level_with_nothing_tested_is_not_met():
    st = all_ids()
    st["P1"] = st["P2"] = st["P3"] = "not_tested"
    lv = compute_levels(res(st))
    assert lv["core"] == "L2" and lv["per_level"][3]["met"] is False


def test_error_and_unsupported_block_core():
    for bad in ("error", "unsupported", "fail"):
        st = all_ids()
        st["M3"] = bad
        assert compute_levels(res(st))["core"] == "L3"


def test_not_applicable_does_not_block_and_gives_star():
    st = all_ids()
    st["O4"] = st["M3"] = "not_applicable"
    lv = compute_levels(res(st))
    assert lv["core"] == "L4*"
    assert lv["per_level"][0]["star"] and lv["per_level"][0]["not_applicable"] == ["O4"]
    assert lv["per_level"][0]["blocking_status"] == {} and lv["per_level"][0]["untested"] == []


def test_unsupported_still_blocks_where_not_applicable_does_not():
    st = all_ids()
    st["O4"] = "unsupported"
    assert compute_levels(res(st))["core"] == "none"
    st["O4"] = "not_applicable"
    st["O2"] = "fail"
    assert compute_levels(res(st))["core"] == "none"


def test_level_with_only_not_applicable_and_untested_is_not_met():
    st = all_ids()
    st["P1"] = "not_applicable"
    st["P2"] = st["P3"] = "not_tested"
    lv = compute_levels(res(st))
    assert lv["core"] == "L2" and lv["per_level"][3]["met"] is False
    md = markdown([doc("h", "1", st)])
    assert "not met; nothing tested; n/a: P1; untested: P2, P3" in md
    assert "| P1 | PermissionRequest allow honored headless | core | n/a |" in md


def test_not_applicable_hardening_is_not_a_gap():
    st = all_ids()
    st["M4"] = "not_applicable"
    lv = compute_levels(res(st))
    assert lv["gaps"] == [] and lv["hardening_not_tested"] == [] and lv["core"] == "L4"


def test_hardening_not_tested_listed():
    st = all_ids()
    st["P4"] = st["M5"] = "not_tested"
    lv = compute_levels(res(st))
    assert lv["hardening_not_tested"] == ["P4", "M5"] and lv["gaps"] == []
    assert set(HARDENING).isdisjoint({"O1", "B1", "B2", "B3", "B4", "A2", "P1", "M1", "M3"})


def test_every_id_is_either_checked_or_explained():
    assert set(ALL_IDS) == set(CHECKS) | set(NOT_TESTED_NOTES)


def doc(name, version, statuses, stale_levels=None):
    results = res(statuses)
    return {"kit": {"git_sha": "abc"}, "harness": {"name": name, "version": version}, "platform": {"os": "TestOS"},
            "date": "2026-09-23", "results": results, "levels": stale_levels or compute_levels(results),
            "sessions": {"s": {"egress_refused": ["CONNECT example.com:443"]}}}


def test_markdown_matrix():
    st = all_ids()
    st["B6"] = "fail"
    st["A1"] = "not_tested"
    st2 = all_ids()
    st2["A2"] = "fail"
    md = markdown([doc("h1", "1.0", st), doc("h2", "2.0", st2)])
    assert "| h1 1.0 | **L4*** | B6 silent hook failure |" in md
    assert "| h2 2.0 | **L1** | none found |" in md
    assert "| B6 | hook failure is never silent | FAIL | PASS |" in md
    assert "| A1 | ask prompts under auto-approve | core | not tested | PASS |" in md
    assert "met*; untested: A1" in md
    assert "blocked by A2 (fail)" in md
    assert "CONNECT example.com:443" in md


def test_markdown_recomputes_stale_levels():
    md = markdown([doc("h", "1", all_ids(), stale_levels={"reached": "L0", "per_level": []})])
    assert "**L4**" in md


def test_markdown_escapes_pipes():
    d = doc("h", "1", all_ids())
    d["results"][0]["summary"] = "a | b"
    assert r"a \| b" in markdown([d])


def test_report_keeps_the_newest_result_per_harness_version_and_os():
    from hookconf.report import newest_per_run_key
    def doc(os_, date, tag):
        return {"harness": {"name": "claude-code", "version": "2.1.278"}, "platform": {"os": os_}, "date": date, "tag": tag}
    docs = [doc("Linux", "2026-09-23T19:16:31+00:00", "a1"), doc("Windows", "2026-09-23T19:17:13+00:00", "w1"),
            doc("Linux", "2026-09-23T19:20:54+00:00", "a2")]
    kept = newest_per_run_key(docs)
    assert [d["tag"] for d in kept] == ["a2", "w1"]
