import numpy as np
from xai_ids.data import jour, echantillon

def test_jour():
    assert jour('Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv') == 'Fri_DDoS'
    assert jour('Monday-WorkingHours.pcap_ISCX.csv') == 'Mon'
    assert jour('Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv') == 'Thu_PM'

def test_echantillon_plafonne():
    lab = np.array(['BENIGN'] * 1000 + ['DoS'] * 50)
    out = echantillon(np.arange(len(lab)), lab, cap=20, cap_benign=100)
    assert (lab[out] == 'BENIGN').sum() == 100
    assert (lab[out] == 'DoS').sum() == 20
    assert len(set(out)) == len(out)   # pas de doublons