import numpy as np, pandas as pd
from xai_ids.prompt import construire_prompt, construire_prompt_v2
from xai_ids.verify import verifier, nb_problemes

COLS = ['A', 'B', 'C', 'D', 'E', 'F']
LIGNE = pd.Series({'Protocol': 6.0, 'Source IP': '1.2.3.4', 'Source Port': 5555.0,
                   'Destination IP': '5.6.7.8', 'Destination Port': 80.0,
                   'Timestamp': '7/7/2017 3:30',
                   'A': 1.0, 'B': 2.0, 'C': 3.0, 'D': 4.0, 'E': 5.0, 'F': 6.0})
SV = np.array([0.1, -0.2, 0.3, -0.4, 0.5, 0.01])

def test_prompt():
    p = construire_prompt(LIGNE, 0.93, 0.3, 0.4, SV, COLS)
    assert '0.500' in p
    assert p.count('SHAP = ') == 5
    assert 'E = 5' in p and 'F = 6' not in p
    assert 'anomalie = non' in p

def test_prompt_v2():
    p = construire_prompt_v2(LIGNE, 0.93, 0.3, 0.4, SV, COLS)
    assert '0.500' in p
    assert sum(1 for l in p.splitlines() if ' : valeur ' in l) == 5
    assert '- E (' in p and '- F (' not in p
    assert 'anomalie = non' in p

def test_verifier():
    prompt = 'seuil 0.500 proba 0.930 anomalie = non'
    ok = 'Verdict Facteurs confiance Action 0.93'
    assert nb_problemes(verifier(ok, prompt)) == 0
    v = verifier('Verdict Facteurs confiance Action 42', prompt)
    assert v['chiffres_inventes'] == ['42.0']
    v = verifier('Verdict Facteurs confiance Action. Isolation Forest signale une anomalie forte.', prompt)
    assert v['contradiction_IF']

def test_recopie_et_IF():
    prompt = "1. Init_Win_bytes_forward = 283 | SHAP = +0.044 (pousse vers Attack)\nanomalie = non"
    texte = "Verdict\n1. Init_Win_bytes_forward = 283 | SHAP = +0.044 (pousse vers Attack)\n"
    assert verifier(texte, prompt)['recopie'] == 1
    v = verifier("Isolation Forest : anomalie = oui", prompt)
    assert v['IF_mentionnee'] and v['IF_incoherente']