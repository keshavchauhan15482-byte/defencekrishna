import unittest
from garuda_v3.dashboard_lab import DashboardLab
class LabTests(unittest.TestCase):
    def forecast(self,p,route="arjuna"):
        return {"trajectory":[{"malicious_flow_probability":p}],"defence_signal":{"route":route}}
    def test_threshold_and_unknown_gate(self):
        lab=DashboardLab()
        for risk,route,status in [(.749,"arjuna",200),(.75,"arjuna",403),(.99,"krishna",200)]:
            ticket=lab.issue(self.forecast(risk,route))["ticket"]
            self.assertEqual(lab.probe(ticket)[0],status)
        self.assertEqual(lab.confirmed,1)
    def test_idempotent_and_expired(self):
        lab=DashboardLab(); ticket=lab.issue(self.forecast(.9))["ticket"]
        lab.probe(ticket);lab.probe(ticket)
        self.assertEqual(lab.confirmed,1)
        lab.tickets[ticket]["expires"]=0
        self.assertEqual(lab.probe(ticket)[0],410)
    def test_invalid_is_not_clean(self):
        lab=DashboardLab();ticket=lab.issue(self.forecast(float("nan")))["ticket"]
        self.assertEqual(lab.probe(ticket)[0],422)
