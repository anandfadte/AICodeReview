# Sample Genealogy — INTENTIONALLY BUGGY
def save_part(part_id: str, machine: str, order_id: str, lot_id: str = None):
    # BUG: Allows saving a part with NO lot_id -> orphan, breaks IATF 16949 traceability
    # Should: require lot_id, machine, order_id, and write audit log, reject if missing
    record = {"part_id": part_id, "machine": machine, "order_id": order_id, "lot_id": lot_id}
    # db.save(record) — no log, no validation
    return record
