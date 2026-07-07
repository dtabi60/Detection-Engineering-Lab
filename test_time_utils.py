from utils.time_utils import normalize_timestamp

samples = [
    "/Date(1783260455973)/",
    "Date(1783260455973)/",
    "1783260455973",
    "1783260455",
    "2026-07-05T21:00:00",
    None
]

for sample in samples:
    print(sample, "=>", normalize_timestamp(sample))