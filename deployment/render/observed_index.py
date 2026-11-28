"""A bounded descriptive HTTP-fixture risk index; NOT a forecast or attack probability."""
import math
def observed_index(requests_5m,denials_5m,latest_denial_age):
    if type(requests_5m) is not int or requests_5m<0 or type(denials_5m) is not int or denials_5m<0:
        raise ValueError("Invalid counts")
    baseline=min(3,requests_5m)
    if not denials_5m:
        return baseline
    if not isinstance(latest_denial_age,(int,float)) or not math.isfinite(latest_denial_age) or latest_denial_age<0 or latest_denial_age>=300:
        raise ValueError("Invalid denial age")
    # 0..100 descriptive index: recent fixture denials elevate it, decay over five minutes.
    elevated=min(95,35+15*min(4,denials_5m))
    return min(100,baseline+math.ceil(elevated*(1-latest_denial_age/300)))
