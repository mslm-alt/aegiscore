from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ui.i18n import current_language, set_language, tr


def test_i18n_defaults_to_english():
    set_language("en")
    assert current_language() == "en"
    assert tr("Alerts") == "Alerts"


def test_i18n_switches_to_turkish():
    set_language("tr")
    assert current_language() == "tr"
    assert tr("Alerts") == "Alarmlar"
    assert tr("Refresh") == "Yenile"
    assert tr("System OK") == "Sistem sağlıklı"
    assert tr("Degraded") == "Bozulmuş"
    assert tr("Session preview") == "Oturum önizlemesi"
    assert tr("No alert selected. Select an alert from Alerts or paste alert context.").startswith("Alarm seçilmedi.")
