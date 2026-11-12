# Sample OEE — INTENTIONALLY BUGGY
def calc_oee(planned_time: float, downtime: float, ideal_rate: float, actual_output: float, good_parts: float):
    # BUG: uses calendar time not planned time, can return >1, div-by-zero if downtime == planned
    availability = (planned_time - downtime) / planned_time if planned_time else 0
    # BUG: Performance can exceed 1 if actual > ideal, no clamp
    performance = (actual_output / ideal_rate) if ideal_rate else 0
    # BUG: If actual_output == 0, div-by-zero
    quality = good_parts / actual_output
    oee = availability * performance * quality
    return oee  # Should be in 0..1, uses planned time, handles 0 safely
