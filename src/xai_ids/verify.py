import re

def nombres(t):
    return {str(abs(float(m))) for m in re.findall('-?[0-9]+(?:[.][0-9]+)?', t.replace(',', '.'))}

def recopie(texte, prompt):
    """Nombre de lignes de la réponse recopiées telles quelles depuis le prompt."""
    n = 0
    for l in texte.splitlines():
        core = re.sub(r'^[\s\-\*\d\.\)]+', '', l).strip()
        if len(core) > 25 and core in prompt:
            n += 1
    return n

def verifier(texte, prompt):
    inventes = nombres(texte) - nombres(prompt)
    fen = texte.split('Isolation Forest')[1][:150].lower() if 'Isolation Forest' in texte else ''
    mots = set(re.findall('[a-zéèà]+', fen))
    negation = bool(mots & {'pas', 'aucune', 'aucun', 'non', 'ne', 'n'})
    attendu = 'oui' if 'anomalie = oui' in prompt else 'non'
    m = re.search(r'anomalie\s*=\s*(oui|non)', texte.lower())
    return {
        '4_parties': all(k in texte for k in ['Verdict', 'Facteurs', 'confiance', 'Action']),
        'mots_ok': len(texte.split()) <= 130,
        'chiffres_inventes': sorted(inventes),
        'contradiction_IF': 'anomalie = non' in prompt and 'anomalie' in fen and not negation,
        'recopie': recopie(texte, prompt),
        'IF_mentionnee': 'Isolation' in texte,
        'IF_incoherente': bool(m) and m.group(1) != attendu,
    }

def nb_problemes(v):
    """Les 4 contrôles d'origine (comparables au guide)."""
    return (int(not v['4_parties']) + int(not v['mots_ok'])
            + len(v['chiffres_inventes']) + int(v['contradiction_IF']))

def nb_problemes_v2(v):
    """Contrôles d'origine + recopie, IF absent, IF incohérent."""
    return (nb_problemes(v) + int(v['recopie'] >= 3)
            + int(not v['IF_mentionnee']) + int(v['IF_incoherente']))