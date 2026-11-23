import os
import numpy as np
import pandas as pd

JOURS = {
    'Monday': 'Mon', 'Tuesday': 'Tue', 'Wednesday': 'Wed',
    'Thursday-WorkingHours-Morning': 'Thu_AM',
    'Thursday-WorkingHours-Afternoon': 'Thu_PM',
    'Friday-WorkingHours-Morning': 'Fri_AM',
    'Friday-WorkingHours-Afternoon-PortScan': 'Fri_PS',
    'Friday-WorkingHours-Afternoon-DDos': 'Fri_DDoS',
}

def jour(nom):
    """Nom de fichier CSV -> code du jour (ex. 'Fri_DDoS')."""
    return next(v for k, v in JOURS.items() if nom.startswith(k))

def charger(path):
    """Charge un CSV CIC-IDS2017 : colonnes nettoyées, labels lisibles, float32."""
    d = pd.read_csv(path, encoding='latin1', low_memory=False)
    d.columns = d.columns.str.strip()
    d = d.drop(columns=['Flow ID'])
    d['Label'] = d['Label'].str.strip().str.replace('[^ -~]', '-', regex=True)
    num = d.select_dtypes(include=[np.number]).columns
    d[num] = d[num].astype('float32')
    d['day'] = jour(os.path.basename(path))
    return d

def echantillon(idx, lab, cap=150_000, cap_benign=400_000, seed=42):
    """Plafonne le nombre de lignes par label (cap pour les attaques, cap_benign pour BENIGN)."""
    idx = np.asarray(idx)
    rng = np.random.RandomState(seed)
    out = []
    for l in np.unique(lab[idx]):
        sel = idx[lab[idx] == l]
        c = cap_benign if l == 'BENIGN' else cap
        out.append(sel if len(sel) <= c else rng.choice(sel, c, replace=False))
    return np.concatenate(out)