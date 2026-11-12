# Sample LineTrack API — INTENTIONALLY BUGGY for reviewer dev. Do NOT use in prod.
from fastapi import FastAPI, Header
app = FastAPI()

# BUG 1 - RBAC: No role check. Operator can call Admin endpoint.
@app.post("/admin/setpoint")
def setpoint(machine: str, speed: int, x_role: str = Header("Operator")):
    # Should check: role in [Supervisor, Plant Head] + allow-list + clamp + interlock + audit
    # Currently: no check at all
    return {"ok": True, "machine": machine, "speed": speed}

# BUG 2 - IDOR: No ownership check. Change id=123 to id=124 to see another plant.
@app.get("/order/{order_id}")
def get_order(order_id: int, x_plant: str = Header("Plant1")):
    # Should check: order.plant == x_plant
    return {"order_id": order_id, "plant": "Plant2", "part": "Brake Disc", "qty": 10000}

@app.get("/oee")
def get_oee(line: str):
    return {"line": line, "oee": 0.85}
