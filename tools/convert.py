from pathlib import Path
from sigma.collection import SigmaCollection
from sigma.backends.kusto import KustoBackend

# ======== ENV SETTINGS (edit to fit your data) ========
TABLE_SYSWIN   = "Event"          # Sysmon/Sysinternals landing table
TABLE_SECURITY = "SecurityEvent"  # Windows Security log table
USE_EVENTDATA  = True             # True if fields are under EventData.*
# =====================================================

# Try Kusto-specific Windows pipeline; fall back to none
try:
    from sigma.pipelines.kusto.windows import windows_pipeline
    pipeline = windows_pipeline()
except Exception:
    pipeline = None

SRC = Path("detections/sigma")
DST = Path("detections/kusto")
DST.mkdir(parents=True, exist_ok=True)

backend = KustoBackend(pipeline=pipeline) if pipeline else KustoBackend()

def wrap_query(where_clause: str, is_security: bool) -> str:
    """
    Turn a PySigma WHERE-clause into a runnable KQL query for the right table/shape.
    Heuristic: if it references EventID 4624/4625/etc assume SecurityEvent; else assume Sysmon/Event.
    """
    table = TABLE_SECURITY if is_security else TABLE_SYSWIN
    if is_security:
        return f"{table}\n| where {where_clause}"
    if USE_EVENTDATA:
        # add EventData mapping for common Sysmon columns
        extend = (
            " | extend "
            "Image=tostring(EventData.Image), "
            "CommandLine=tostring(EventData.CommandLine), "
            "ParentImage=tostring(EventData.ParentImage), "
            "ParentCommandLine=tostring(EventData.ParentCommandLine)"
        )
        return f"{table}\n| where {where_clause}{extend}"
    else:
        return f"{table}\n| where {where_clause}"

for rule_file in SRC.rglob("*.yml"):
    try:
        rules = SigmaCollection.from_yaml(rule_file.read_text(encoding="utf-8"))
        where_clauses = backend.convert(rules)

        final_queries = []
        for qc in where_clauses:
            qstr = qc.strip()

            # If backend already produced a full query (starts with table), keep it.
            if qstr.startswith(("Event", "SysmonEvent", "SecurityEvent")):
                final_queries.append(qstr)
                continue

            # Simple heuristic: 4625/4624 → Security; else Sysmon/Event
            is_security = "4625" in qstr or "4624" in qstr or "SecurityEvent" in qstr
            final_queries.append(wrap_query(qstr, is_security))

        out = DST / (rule_file.stem + ".kql")
        header = (
            f"// Converted from Sigma: {rule_file.name}\n"
            f"// Backend: Kusto (PySigma)\n"
            f"// Note: Adjust table names / USE_EVENTDATA above if your schema differs.\n\n"
        )
        out.write_text(header + "\n\n".join(final_queries) + "\n", encoding="utf-8")
        print(f"[+] {rule_file} -> {out}")
    except Exception as e:
        print(f"[!] Failed {rule_file}: {e}")