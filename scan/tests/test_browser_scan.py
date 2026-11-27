"""Browser-only scan and local-only menu entry; no website testing."""
import contextlib
import io
import json
import os
import sqlite3
import sys
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zbtriage import cli, menu, scope
from zbtriage.modules import browser
from zbtriage.readers import reader_select
from test_expanded_capabilities import BAD, context
from test_followup_fixes import bundle  # noqa: F401  (pytest fixture)


class Terminal(io.StringIO):
    def isatty(self):
        return True


def _user_data(root):
    """A Chromium user-data folder whose Default profile visited BAD."""
    profile = root / "User Data" / "Default"
    profile.mkdir(parents=True)
    (root / "User Data" / "Local State").write_text("{}", encoding="utf-8")
    with contextlib.closing(sqlite3.connect(profile / "History")) as db:
        db.execute("CREATE TABLE urls(url TEXT,title TEXT,last_visit_time INTEGER)")
        db.execute("INSERT INTO urls VALUES(?,?,?)", ("https://" + BAD + "/", "", 13000000000000000))
        db.commit()
    return str(root / "User Data")


# --- which readers run ----------------------------------------------------------

def test_browser_only_runs_just_the_browser_reader():
    assert [s.name for s in reader_select(context(browser_only=True))] == ["browser"]


def test_browser_only_does_not_narrow_a_targeted_or_phone_scan(tmp_path):
    targeted = [s.name for s in reader_select(context(targets=(str(tmp_path),)))]
    assert [s.name for s in reader_select(context(targets=(str(tmp_path),), browser_only=True))] == targeted


def test_the_default_scan_still_runs_more_than_the_browser():
    assert len(reader_select(context())) > 1


def test_browser_scan_type_parses_and_refuses_a_target(tmp_path):
    assert cli._parse(["--scan-type", "browser"]).scan_type == "browser"
    with pytest.raises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
        cli._parse(["--scan-type", "browser", "--target", str(tmp_path)])


def test_preview_names_the_one_check_and_its_limit():
    preview = scope.scope_preview(cli._parse(["--scan-type", "browser"]))
    assert preview["checks"] == ["browser"]
    assert any("Only browser profiles" in limit for limit in preview["limits"])


# --- end to end, in both entry points ---------------------------------------------

def test_a_browser_scan_reports_its_narrow_scope(tmp_path, bundle):
    user_data = _user_data(tmp_path)
    feed = tmp_path / "feed.txt"
    feed.write_text(BAD + "\tinfrastructure\tprimary\tfixture\n", encoding="utf-8")
    for name, api, module in (("source", cli, browser), ("bundle", bundle, bundle)):
        full = tmp_path / (name + ".json")
        out = io.StringIO()
        args = ["--iocs", str(feed), "--scan-type", "browser", "--json", str(full), "--no-banner"]
        if api is bundle:
            args.append("--no-pause")
        with patch.object(module, "CHROMIUM_ROOTS", [("Chrome", user_data)]), \
                patch.object(module, "APP_ROOTS", []), patch.object(module, "FIREFOX_ROOTS", []), \
                patch.object(api, "_force_utf8_io", lambda: None), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = api.main(args)
        assert code == 2, name
        doc = json.loads(full.read_text(encoding="utf-8"))
        assert sorted(doc["modules"]) == ["browser"], name
        assert doc["scope"]["scan_type"] == "browser"
        assert "browser-only" in [x["id"] for x in doc["must_relay"]]
        assert {h["indicator"] for h in doc["modules"]["browser"]["hits"]} == {BAD}
        assert "Only browser profiles were checked" in out.getvalue()


# --- the start menu -----------------------------------------------------------

def test_the_menu_entry_starts_a_browser_scan_without_opening_a_website(bundle):
    for api in (menu, bundle):
        args = cli._parse([])
        with patch("webbrowser.open", side_effect=AssertionError("no website testing")):
            chosen = api.choose_scan(args, lambda: pytest.fail("update"),
                                     stdin=Terminal("3\n"), stderr=Terminal())
        assert chosen and args.scan_type == "browser"
        assert not hasattr(api, "_mn_open_page")
        assert not hasattr(api, "_mn_adblock")
