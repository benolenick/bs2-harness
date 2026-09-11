from bs2.benchmark import restart_benchmark


def test_restart_contract(tmp_path):
    result = restart_benchmark(tmp_path)
    assert result["real_process_restart"]
    assert result["capsules_only"]["retained_facts"] == 1
    assert result["capsules_plus_cairn"] == {"retained_facts": 3, "redundant_checks": 0, "unsupported_conclusions": 0}
    assert result["changed_generation_reopens"]
