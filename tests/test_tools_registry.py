"""The P1-3 tool capability registry: every capability is PROBED or RECORDED —
nothing is asserted by roster membership. Honest counts, honest matrix."""
import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "live"))

from tools_registry import TOOLS, ToolRegistry          # noqa: E402
from adapters import ADAPTERS                            # noqa: E402


def test_every_catalogued_tool_has_an_entry_and_a_lane():
    for name, spec in TOOLS.items():
        assert spec["cls"] in ("web.recon", "web.exploit")
    # the nine Laboratory tools all have a typed adapter; ffuf/sqlmap/httpx do not
    # (they are policy-gated or fold via other paths — that is the honest shape)
    assert {n for n, s in TOOLS.items() if s["adapter"]} == set(ADAPTERS)


def test_nothing_is_installed_without_a_probe():
    reg = ToolRegistry(which=lambda b: None,             # nothing on this host
                       module_available=lambda n: False)
    for name in TOOLS:
        assert reg.status(name)["installed"] is False
    s = reg.summary()
    assert s["runnable"] == 0 and s["verified"] == 0
    assert s["catalogued"] == len(TOOLS)                 # the roster alone is never more


def test_installed_and_version_verified_are_probed(tmp_path):
    reg = ToolRegistry(which=lambda b: "/usr/bin/" + b,
                       verifier=lambda path: "v1.2.3")
    st = reg.status("nuclei")
    assert st["installed"] and st["version_verified"] and st["version"] == "v1.2.3"
    # installed but silent on version -> installed, NOT verified
    reg2 = ToolRegistry(which=lambda b: "/usr/bin/" + b,
                        verifier=lambda path: None)
    assert reg2.status("nuclei")["version_verified"] is False


def test_adapter_and_runner_flags_follow_the_typed_path():
    reg = ToolRegistry()
    assert reg.status("nuclei")["adapter_compatible"] is True
    assert reg.status("nuclei")["runner_configured"] is True
    assert reg.status("ffuf")["adapter_compatible"] is False   # no adapter -> no runner


def test_governed_capable_reads_the_real_seam_caps(tmp_path):
    reg = ToolRegistry(seam_caps={"web.recon", "net.recon"})
    assert reg.status("nuclei")["governed_capable"] is True
    assert reg.status("sqlmap")["governed_capable"] is False   # exploit lane not minted


def test_enabled_derives_from_the_charter():
    recon_charter = {"actions": {"allowed": ["web.recon", "net.recon"]}}
    full_charter = {"actions": {"allowed": ["web.recon", "web.exploit"]}}
    assert ToolRegistry(charter=recon_charter).status("sqlmap")["enabled"] is False
    assert ToolRegistry(charter=full_charter).status("sqlmap")["enabled"] is True


def test_smoke_tested_is_recorded_not_assumed(tmp_path):
    reg = ToolRegistry(smoke_file=str(tmp_path / "smoke.json"))
    assert reg.status("nuclei")["smoke_tested"] is False
    reg.smoke_passed("nuclei")
    assert reg.status("nuclei")["smoke_tested"] is True
    # and the record survives a fresh registry instance (it happened, durably)
    reg2 = ToolRegistry(smoke_file=str(tmp_path / "smoke.json"))
    assert reg2.status("nuclei")["smoke_tested"] is True
    assert reg2.summary()["smoke_tested"] == 1


def test_summary_counts_are_separate_vocabulary():
    reg = ToolRegistry(which=lambda b: None,
                       module_available=lambda n: False,
                       seam_caps={"web.recon"},
                       charter={"actions": {"allowed": ["web.recon"]}})
    s = reg.summary()
    assert set(s) == {"catalogued", "routable", "runnable", "verified",
                      "governed_capable", "smoke_tested", "applicable_now"}
    assert s["catalogued"] == len(TOOLS)
    assert s["routable"] == len(ADAPTERS)                # exactly the typed nine
    assert s["runnable"] <= s["catalogued"]
    assert s["verified"] <= s["runnable"]
    # enabled: every web.recon tool except sqlmap (exploit lane, charter forbids)
    assert s["applicable_now"] == len(TOOLS) - 1


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
