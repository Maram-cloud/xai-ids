import numpy as np, pandas as pd
from xai_ids.prompt import construire_prompt
from xai_ids.verify import verifier, nb_problemes

def test_prompt():
    cols = ['A', 'B', 'C', 'D', 'E', 'F']
    ligne = pd.Series({'Protocol': 6.0, 'Source IP': '1.2.3.4', 'Source Port': 5555.0,
                       'Destination IP': '5.6.7.8', 'Destination Port': 80.0,
                       'Timestamp': '7/7/2017 3:30',
                       'A': 1.0, 'B': 2.0, 'C': 3.0, 'D': 4.0, 'E': 5.0, 'F': 6.0})
    sv = np.array([0.1, -0.2, 0.3, -0.4, 0.5, 0.01])
    p = construire_prompt(ligne, 0.93, 0.3, 0.4, sv, cols)
    assert '0.500' in p
    assert p.count('SHAP = ') == 5          # 5 facteurs exactement
    assert 'E = 5' in p and 'F = 6' not in p  # E est le plus influent, F est hors du top 5
    assert 'anomalie = non' in p
    assert 'moyenne' not in p.lower()

def test_verifier():
    prompt = 'seuil 0.500 proba 0.930 anomalie = non'
    ok = 'Verdict Facteurs confiance Action 0.93'
    assert nb_problemes(verifier(ok, prompt)) == 0
    v = verifier('Verdict Facteurs confiance Action 42', prompt)
    assert v['chiffres_inventes'] == ['42.0']
    v = verifier('Verdict Facteurs confiance Action. Isolation Forest signale une anomalie forte.', prompt)
    assert v['contradiction_IF']