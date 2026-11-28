"""Bounded review profiles from authenticated synthetic fixture receipts.
Not executable mutations, ML retraining, attack discovery or enforcement.
"""
def summarize(rows, allowed, now):
    profiles=[]
    for lane,reason,count,last in rows:
        if lane not in allowed or reason not in allowed[lane] or reason=="UNSPECIFIED_RULE":
            continue
        if not isinstance(count,int) or not 1<=count<=8:
            raise ValueError("Invalid confirmation count")
        version=1+sum(count>=n for n in (2,4,8))
        profiles.append({"lane":lane,"reason":reason,"confirmations":count,"version":version,
                         "review_state":("new","repeated","established","saturated")[version-1],
                         "last_seen":float(last)})
    return {"source":"authenticated_fixture_pattern_memory_v1","scope":"synthetic_fixture_only",
            "observed_at":now,"patterns_saved":len(profiles),
            "candidate_revisions":sum(p["version"]-1 for p in profiles),
            "profiles":profiles,"automatic_containment":False,"model_retrained":False}
