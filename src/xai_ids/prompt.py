import numpy as np

PROTOS = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}

def construire_prompt(ligne, proba, s_if, seuil_if, sv_row, cols, k=5):
    decision = 'Attack' if proba >= 0.5 else 'Normal'
    flag = 'oui' if s_if > seuil_if else 'non'
    proto = PROTOS.get(int(ligne['Protocol']), str(int(ligne['Protocol'])))
    src = str(ligne['Source IP']) + ':' + str(int(ligne['Source Port']))
    dst = str(ligne['Destination IP']) + ':' + str(int(ligne['Destination Port']))
    ts = ligne['Timestamp']
    valeurs = ligne[cols].to_numpy(dtype=float)
    lignes = []
    for rang, j in enumerate(np.argsort(-np.abs(sv_row))[:k], 1):
        sens = 'vers Attack' if sv_row[j] > 0 else 'vers Normal'
        lignes.append(str(rang) + '. ' + cols[j] + ' = ' + format(valeurs[j], 'g')
                      + ' | SHAP = ' + format(sv_row[j], '+.3f') + ' (pousse ' + sens + ')')
    bloc = chr(10).join(lignes)
    return f'''Tu es un analyste SOC. Un détecteur d'intrusion (Random Forest) a analysé un flux réseau. Explique sa décision à un analyste, en français.

DÉCISION DU MODÈLE
- Classe prédite : {decision}
- Probabilité d'attaque : {proba:.3f} (seuil de décision : 0.500 ; le flux est classé Attack si la probabilité est ≥ 0.500)
- Avis secondaire (Isolation Forest) : anomalie = {flag} (score {s_if:.3f}, seuil {seuil_if:.3f})

CONTEXTE DU FLUX
- Source : {src} -> Destination : {dst}
- Protocole : {proto}
- Horodatage : {ts}

FACTEURS LES PLUS INFLUENTS (SHAP : positif = pousse vers Attack, négatif = pousse vers Normal)
{bloc}

CONSIGNES
- Réponds en 4 parties : 1) Verdict, 2) Facteurs clés, 3) Niveau de confiance, 4) Action conseillée.
- Utilise uniquement les valeurs ci-dessus : n'invente aucun chiffre ni aucune caractéristique.
- Pour chaque facteur cité, donne son nom, sa valeur et le sens de son influence ; le signe SHAP décrit l'influence du facteur, pas la valeur de la variable.
- Le seul seuil de décision est celui indiqué plus haut : n'en mentionne aucun autre.
- L'Isolation Forest signale une anomalie uniquement si la ligne indique anomalie = oui ; ne mentionne que ce oui ou non.
- Ces 5 facteurs ne représentent qu'une partie de la décision du modèle : formule avec prudence.
- Maximum 120 mots.'''

GLOSSAIRE = {
    'Init_Win_bytes_forward': "fenêtre TCP initiale annoncée par la source",
    'Init_Win_bytes_backward': "fenêtre TCP initiale annoncée par la destination",
    'Fwd Packet Length Max': "taille maximale des paquets envoyés par la source, en octets de données",
    'Max Packet Length': "taille maximale des paquets du flux",
    'Average Packet Size': "taille moyenne des paquets du flux",
    'Packet Length Mean': "taille moyenne des paquets du flux",
    'Packet Length Std': "variabilité (écart-type) de la taille des paquets",
    'Packet Length Variance': "variance de la taille des paquets",
    'Bwd Packet Length Std': "variabilité de la taille des paquets envoyés par la destination",
    'Bwd Packet Length Mean': "taille moyenne des paquets envoyés par la destination",
    'Bwd Packet Length Min': "taille minimale des paquets envoyés par la destination",
    'Avg Fwd Segment Size': "taille moyenne des segments envoyés par la source",
    'Avg Bwd Segment Size': "taille moyenne des segments envoyés par la destination",
    'min_seg_size_forward': "taille minimale de segment côté source",
    'Fwd Header Length': "total des octets d'en-têtes côté source",
    'Subflow Bwd Bytes': "octets envoyés par la destination dans le sous-flux",
}

def construire_prompt_v2(ligne, proba, s_if, seuil_if, sv_row, cols, k=5):
    decision = 'Attack' if proba >= 0.5 else 'Normal'
    flag = 'oui' if s_if > seuil_if else 'non'
    proto = PROTOS.get(int(ligne['Protocol']), str(int(ligne['Protocol'])))
    src = str(ligne['Source IP']) + ':' + str(int(ligne['Source Port']))
    dst = str(ligne['Destination IP']) + ':' + str(int(ligne['Destination Port']))
    ts = ligne['Timestamp']
    valeurs = ligne[cols].to_numpy(dtype=float)
    lignes = []
    for j in np.argsort(-np.abs(sv_row))[:k]:
        desc = GLOSSAIRE.get(cols[j], 'caractéristique du flux')
        sens = 'Attack' if sv_row[j] > 0 else 'Normal'
        lignes.append('- ' + cols[j] + ' (' + desc + ') : valeur ' + format(valeurs[j], 'g')
                      + ', contribution ' + format(sv_row[j], '+.3f') + ', pousse vers ' + sens)
    bloc = chr(10).join(lignes)
    return f'''Tu es un analyste SOC. Un détecteur d'intrusion (Random Forest) a analysé un flux réseau. Explique sa décision à un analyste, en français, en langage clair.

DÉCISION DU MODÈLE
- Classe prédite : {decision}
- Probabilité d'attaque : {proba:.3f} (seuil de décision : 0.500 ; le flux est classé Attack si la probabilité est ≥ 0.500)
- Avis secondaire (Isolation Forest) : anomalie = {flag} (score {s_if:.3f}, seuil {seuil_if:.3f})

CONTEXTE DU FLUX
- Source : {src} -> Destination : {dst}
- Protocole : {proto}
- Horodatage : {ts}

FACTEURS LES PLUS INFLUENTS (contribution positive = pousse vers Attack, négative = pousse vers Normal)
{bloc}

FORMAT DE RÉPONSE (remplace chaque <...> par ton texte, sans écrire les chevrons)
1) Verdict : <une phrase : classe prédite et probabilité>
2) Facteurs clés : <une phrase courte pour chacun des 3 facteurs les plus influents : ce qu'il mesure, sa valeur, son sens>
3) Niveau de confiance : <une phrase prudente qui reprend l'avis secondaire sous la forme exacte « Isolation Forest : anomalie = {flag} »>
4) Action conseillée : <une action concrète pour l'analyste>

CONSIGNES
- Reformule dans tes propres mots : ne recopie pas les lignes de la liste des facteurs.
- Utilise uniquement les valeurs ci-dessus ; recopie chaque nombre exactement, sans l'arrondir ni en inventer.
- Le signe de la contribution décrit l'influence du facteur, pas la valeur de la variable.
- Le seul seuil de décision est celui indiqué plus haut : n'en mentionne aucun autre.
- Ces 5 facteurs ne représentent qu'une partie de la décision du modèle : formule avec prudence.
- Maximum 120 mots.'''