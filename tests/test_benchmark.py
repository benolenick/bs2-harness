import importlib.util
import os


def _bench_module():
    path = os.path.join(os.path.dirname(__file__), "..", "scripts", "bench_platform.py")
    spec = importlib.util.spec_from_file_location("bench_platform", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_seeded_bola_is_detected():
    result = _bench_module().run_benchmark()
    assert result["flaws"]["BOLA"] is True
