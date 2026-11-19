"""Exercise CLI command resolution on the exact shared staging fixture."""
import json
import os
import subprocess
from pathlib import Path
assert os.environ.get("MSB_REMOTE_AUDIT") == "1"
name = json.loads(Path(os.environ["MSB_INSPECTION_FIXTURE"]).read_text())["name"]
rows=[]
for feature,args,want in [
    ("exec_explicit",["exec",name,"--no-stdin","--","printf","explicit-ok"],"explicit-ok"),
    ("exec_default",["exec",name,"--no-stdin"],"configured-default"),
    ("exec_workdir",["exec",name,"--no-stdin","--","pwd"],"/tmp"),
    ("run_existing_default",["run","--name",name,"--no-stdin"],"configured-default"),
]:
    r=subprocess.run([os.environ["MSB_CLI"],"--remote",*args],capture_output=True,text=True,timeout=180)
    row={"feature":feature,"verdict":"PASS" if r.returncode==0 and r.stdout.strip()==want else "FAIL","exit":r.returncode}
    if row["verdict"]=="FAIL":row["reason"]=r.stderr.replace(os.environ["MSB_API_KEY"],"[redacted]")
    rows.append(row)
    Path(os.environ["MSB_AUDIT_REPORT"]).write_text(json.dumps({"sdk":"cli","rows":rows},indent=2)+"\n")
raise SystemExit(any(r["verdict"]=="FAIL" for r in rows))
