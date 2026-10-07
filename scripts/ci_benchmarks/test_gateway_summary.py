#!/usr/bin/env python3
"""Exercise the benchmark's report gate without root, network or a running proxy."""
from pathlib import Path
import subprocess
import tempfile

script = Path(__file__).with_name("ci_bench_gateway.sh").read_text()
report = script.split('<<PYEOF\n', 1)[1].split('\nPYEOF', 1)[0]
values = {"CLK_TCK": "100", "REPEAT": "1", "DIRECTIONS[*]": "download upload",
          "STREAM_COUNTS[*]": "1 4 16", "CI_BENCH_COMMIT": "test",
          "BIN_RUST": "/test/mqproxy", "DURATION": "1", "BLOB_BYTES": "8388608"}
for key, value in values.items():
    report = report.replace("${" + key + "}", value)
rows = [f"rust {d} {p} 1 8388608 1000000000 10 10 0\n"
        for d in ("download", "upload") for p in (1, 4, 16)]
with tempfile.TemporaryDirectory() as tmp:
    raw, out = Path(tmp) / "raw", Path(tmp) / "out.json"
    for name, data, expected in [
        ("complete", rows, 0),
        ("missing cell", rows[:-1], 1),
        ("failed transfer", [r.rstrip()[:-1] + "1\n" for r in rows], 1),
        ("empty run", [r.replace("8388608", "0") for r in rows], 1),
    ]:
        raw.write_text("".join(data))
        result = subprocess.run(["python3", "-c", report, str(raw), str(out)], capture_output=True)
        assert result.returncode == expected, (name, result.stdout, result.stderr)
print("PASS: gateway report accepts complete runs and rejects missing, failed and empty runs")
