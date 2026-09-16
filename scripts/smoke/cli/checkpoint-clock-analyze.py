import csv, json, pathlib, sys
p = pathlib.Path(sys.argv[1])
rows = [list(map(int, r)) for r in csv.reader((p / 'records.csv').open()) if len(r) == 9]
gaps = [(a,b) for a,b in zip(rows, rows[1:]) if (b[1]-a[1])-(b[2]-a[2]) > 4_000_000_000]
assert len(gaps) == 1, f'expected one wall-only restore gap, found {len(gaps)}'
a,b = gaps[0]
start = int((p/'restore-start.ns').read_text()); end = int((p/'restore-end.ns').read_text())
assert start-100_000_000 <= b[1] <= end+100_000_000, ('first resumed wall time', b[1],start,end)
assert 0 <= b[2]-a[2] < 2_000_000_000, ('monotonic gap',b[2]-a[2])
assert 0 <= b[3]-a[3] < 2_000_000_000, ('boottime gap',b[3]-a[3])
assert all(r[7] == 0 for r in rows), 'cross-thread monotonic clock went backwards'
assert b[4] == 0, 'relative timer expired during offline interval'
fired = next(r for r in rows if r[4])
assert 5_000_000_000 <= fired[2]-fired[8] < 6_000_000_000, ('relative deadline',fired)
assert rows[-1][4:7] == [1,1,1], ('timer expiration/cancellation totals',rows[-1])
assert all(y[2] >= x[2] and y[3] >= x[3] for x,y in zip(rows,rows[1:])), 'elapsed clocks regressed'
print(json.dumps({'pass':True,'samples':len(rows),'restore_ms':(end-start)/1e6,
 'wall_gap_ms':(b[1]-a[1])/1e6,'monotonic_gap_ms':(b[2]-a[2])/1e6,
 'boottime_gap_ms':(b[3]-a[3])/1e6,'relative_timer_elapsed_ms':(fired[2]-fired[8])/1e6,
 'first_restored_sample':b,'last_sample':rows[-1]}, indent=2))
