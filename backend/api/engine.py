from cvss import CVSS3
import re

# Regole di mitigazione contestuale e sicura per ciascuna contromisura.
# Le metriche vengono modificate SOLO se applicabili e senza MAI peggiorare lo score.
def apply_countermeasure_modifiers(cm_id, base_metrics, modified_metrics):
    """
    Applica i modificatori ambientali al vettore CVSS in modo contestuale,
    evitando gli errori tipici (es. impostare MA=L quando la vulnerabilità ha A=N).
    """
    justifications = []
    
    # 1. WAF - Web Application Firewall
    if cm_id == "CTRL-WAF":
        modified_metrics["MAC"] = "H"
        effect = "MAC impostato a High"
        # Mitiga la disponibilità solo se originariamente compromessa (es. DoS/Crash applicativo)
        if base_metrics.get("A") == "H":
            modified_metrics["MA"] = "L"
            effect += ", MA mitigato a Low"
        justifications.append({
            "countermeasure": cm_id,
            "effect": effect,
            "justification": "Il WAF filtra payload noti ed evasioni standard. L'attaccante deve sviluppare tecniche di offuscamento o zero-day bypass (MAC=H)."
        })

    # 2. CSP - Content Security Policy
    elif cm_id == "CTRL-CSP":
        modified_metrics["MAC"] = "H"
        # CSP rigido impedisce l'esecuzione di script iniettati e l'esfiltrazione dati non autorizzata
        if base_metrics.get("C") in ["H", "L"]:
            modified_metrics["MC"] = "N"
        if base_metrics.get("I") in ["H", "L"]:
            modified_metrics["MI"] = "N"
        justifications.append({
            "countermeasure": cm_id,
            "effect": "MAC impostato a High, MC e MI azzerati a None",
            "justification": "Una Content Security Policy restrittiva blocca l'esecuzione di inline script e la connessione a domini di esfiltrazione, neutralizzando l'impatto di furto dati e manipolazione DOM."
        })

    # 3. Prepared Statements / ORM
    elif cm_id == "CTRL-PREP-STMT":
        modified_metrics["MAC"] = "H"
        if base_metrics.get("C") in ["H", "L"]:
            modified_metrics["MC"] = "N"
        if base_metrics.get("I") in ["H", "L"]:
            modified_metrics["MI"] = "N"
        if base_metrics.get("A") == "H":
            modified_metrics["MA"] = "N"
        justifications.append({
            "countermeasure": cm_id,
            "effect": "MAC impostato a High, MC/MI/MA neutralizzati a None",
            "justification": "I Prepared Statements separano radicalmente i comandi SQL dai parametri input utente a livello di driver/database, annullando la possibilità di iniezione logica."
        })

    # 4. Anti-Bruteforce & Rate Limiting
    elif cm_id == "CTRL-RATE-LIMIT":
        modified_metrics["MAC"] = "H"
        effect = "MAC impostato a High"
        if base_metrics.get("A") == "H":
            modified_metrics["MA"] = "L"
            effect += ", MA mitigato a Low"
        justifications.append({
            "countermeasure": cm_id,
            "effect": effect,
            "justification": "Il rate limiting impedisce l'enumerazione di massa e il credential stuffing automatizzato, costringendo l'attaccante a richieste lente e distribuite."
        })

    # 5. Multi-Factor Authentication (MFA)
    elif cm_id == "CTRL-MFA":
        modified_metrics["MAC"] = "H"
        effect = "MAC impostato a High"
        if base_metrics.get("PR") in ["N", "L"]:
            modified_metrics["MPR"] = "H"
            effect += ", MPR impostato a High"
        justifications.append({
            "countermeasure": cm_id,
            "effect": effect,
            "justification": "L'MFA rompe la catena di attacco basata su sole credenziali rubate o deboli, richiedendo l'intercettazione o bypass di un secondo fattore in tempo reale."
        })

    # 6. Privileged Access Management (PAM)
    elif cm_id == "CTRL-PAM":
        modified_metrics["MPR"] = "H"
        justifications.append({
            "countermeasure": cm_id,
            "effect": "MPR forzato a High",
            "justification": "La rotazione continua delle credenziali e l'accesso Just-In-Time (JIT) impediscono l'abuso diretto di utenze privilegiate statiche."
        })

    # 7. Network Segmentation & Microsegmentation
    elif cm_id == "CTRL-NET-SEG":
        modified_metrics["MAC"] = "H"
        # Se c'era cambio di contesto/scope verso la rete, lo confina
        if base_metrics.get("S") == "C":
            modified_metrics["MS"] = "U"
            effect = "MAC impostato a High, MS confinato a Unchanged"
        else:
            effect = "MAC impostato a High"
        justifications.append({
            "countermeasure": cm_id,
            "effect": effect,
            "justification": "La segmentazione di rete confina il raggio d'azione dell'attaccante impedendo il movimento laterale verso subnet adiacenti o l'host node."
        })

    # 8. Anti-DDoS Protection
    elif cm_id == "CTRL-DDOS":
        if base_metrics.get("A") == "H":
            modified_metrics["MA"] = "L"
            effect = "MA mitigato da High a Low"
        else:
            effect = "Controllo attivo (nessun impatto su Availability originariamente assente)"
        justifications.append({
            "countermeasure": cm_id,
            "effect": effect,
            "justification": "La protezione anti-DDoS assorbe volumi anomali di traffico preservando la continuità operativa del servizio core."
        })

    # 9. API Gateway con Schema Validation
    elif cm_id == "CTRL-API-GW":
        modified_metrics["MAC"] = "H"
        justifications.append({
            "countermeasure": cm_id,
            "effect": "MAC impostato a High",
            "justification": "La validazione di conformità allo schema OpenAPI scarta a monte payload con parametri imprevisti o malformati."
        })

    # 10. Cifratura at Rest
    elif cm_id == "CTRL-ENC-REST":
        if base_metrics.get("C") == "H":
            modified_metrics["MC"] = "L"
            effect = "MC mitigato da High a Low"
        else:
            effect = "MC preservato"
        justifications.append({
            "countermeasure": cm_id,
            "effect": effect,
            "justification": "I volumi e i file di database cifrati impediscono la lettura in chiaro dei dati in caso di esfiltrazione di snapshot, backup o dischi."
        })

    # 11. Cifratura in Transit (TLS 1.2+)
    elif cm_id == "CTRL-ENC-TRANSIT":
        if base_metrics.get("C") == "H":
            modified_metrics["MC"] = "L"
            effect = "MC mitigato da High a Low"
        else:
            effect = "Canale cifrato sicuro"
        justifications.append({
            "countermeasure": cm_id,
            "effect": effect,
            "justification": "La cifratura TLS robusta impedisce lo sniffing passivo e l'alterazione del traffico in transito (Man-in-the-Middle)."
        })

    # 12. Firma Digitale / JWT Validation
    elif cm_id == "CTRL-DIG-SIGN":
        if base_metrics.get("I") in ["H", "L"]:
            modified_metrics["MI"] = "L"
        justifications.append({
            "countermeasure": cm_id,
            "effect": "MI mitigato a Low",
            "justification": "La verifica crittografica di firma asimmetrica rende palese qualsiasi manomissione o alterazione del token/payload."
        })

    # 13. OS & Container Hardening
    elif cm_id == "CTRL-HARDENING":
        modified_metrics["MAC"] = "H"
        if base_metrics.get("PR") == "N":
            modified_metrics["MPR"] = "L"
        justifications.append({
            "countermeasure": cm_id,
            "effect": "MAC impostato a High, MPR a Low",
            "justification": "L'esecuzione in container non-root e la rimozione di binari di sistema ostacolano l'escalation locale e la stabilizzazione di backdoor."
        })

    # 14. Runtime Application Self-Protection (RASP)
    elif cm_id == "CTRL-RASP":
        modified_metrics["MAC"] = "H"
        if base_metrics.get("C") == "H": modified_metrics["MC"] = "L"
        if base_metrics.get("I") == "H": modified_metrics["MI"] = "L"
        justifications.append({
            "countermeasure": cm_id,
            "effect": "MAC a High, MC e MI mitigati a Low",
            "justification": "L'agente RASP monitora chiamate critiche e reflection all'interno del processo, bloccando exploit e manipolazioni in-memory."
        })

    # 15. EDR / XDR (Detective)
    elif cm_id == "CTRL-EDR":
        justifications.append({
            "countermeasure": cm_id,
            "effect": "Controllo Detective (0.0 variazione CVSS)",
            "justification": "Monitora costantemente endpoint e workload. Rileva esecuzioni sospette, accelerando l'Incident Response e abbattendo l'MTTD."
        })

    # 16. SIEM & Centralized Logging (Detective)
    elif cm_id == "CTRL-SIEM":
        justifications.append({
            "countermeasure": cm_id,
            "effect": "Controllo Detective (0.0 variazione CVSS)",
            "justification": "Correlazione centralizzata degli eventi di sicurezza con allarmi SOC real-time. Garantisce tracciabilità forense e allerta precoce."
        })

    return justifications

def parse_vector_to_dict(vector_str):
    res = {}
    parts = vector_str.split('/')
    for p in parts[1:]:
        if ':' in p:
            k, v = p.split(':', 1)
            res[k] = v
    return res

def calculate_real_risk(original_vector_str, active_countermeasures, technical_answers=None):
    try:
        cvss_obj = CVSS3(original_vector_str)
    except Exception as e:
        return {"error": f"Invalid CVSS Vector: {str(e)}"}
        
    original_score = float(cvss_obj.base_score)
    base_metrics = parse_vector_to_dict(original_vector_str)
    
    # Inizializziamo i modified metrics con i valori base o Not Defined (X)
    modified_metrics = {}
    applied_mitigations = []
    
    for cm_id in active_countermeasures:
        justs = apply_countermeasure_modifiers(cm_id, base_metrics, modified_metrics)
        applied_mitigations.extend(justs)
        
    # Costruiamo il vettore ambientale modificato
    # CVSS:3.1/AV:N/AC:L/.../MAC:H/MPR:H/MC:L...
    parts = original_vector_str.split("/")
    
    # Rimuoviamo eventuali metriche ambientali pre-esistenti per rigenerarle pulite
    clean_parts = [p for p in parts if not p.startswith(('MAV:', 'MAC:', 'MPR:', 'MUI:', 'MS:', 'MC:', 'MI:', 'MA:', 'CR:', 'IR:', 'AR:'))]
    
    for k, v in modified_metrics.items():
        clean_parts.append(f"{k}:{v}")
        
    modified_vector_str = "/".join(clean_parts)
    
    try:
        new_cvss_obj = CVSS3(modified_vector_str)
        calc_environmental = float(new_cvss_obj.environmental_score)
        severity_rating = new_cvss_obj.severities()[2]
    except Exception:
        calc_environmental = original_score
        severity_rating = cvss_obj.severities()[0]
        
    # REGOLA AUREA: una contromisura tecnica di mitigazione non può MAI peggiorare lo score
    real_risk_score = min(original_score, calc_environmental)
    
    # Calcolo Action Priority per la riunione tecnica con Ingegneria
    if real_risk_score >= 9.0:
        action_priority = "P1 - Critical Priority"
        action_guidance = "Severità critica non sufficientemente mitigata dalle difese attive: richiede rilascio hotfix o blocco perimetrale prioritario."
    elif real_risk_score >= 7.0:
        action_priority = "P2 - High Priority"
        action_guidance = "Severità elevata: pianificare la remediation strutturale nel ciclo di sprint corrente."
    elif real_risk_score >= 4.0:
        action_priority = "P3 - Medium Priority"
        action_guidance = "Rischio moderato / ben controllato dalle contromisure attive: gestione ordinaria a backlog."
    elif real_risk_score > 0.0:
        action_priority = "P4 - Low / Mitigated"
        action_guidance = "Rischio residuale minimo: contromisure compensative efficaci, monitoraggio standard."
    else:
        action_priority = "P4 - Fully Contained"
        action_guidance = "Rischio neutralizzato a zero dalle contromisure attive (es. CSP o Prepared Statements). Nessuna azione immediata richiesta."

    res = {
        "original_score": original_score,
        "real_risk_score": real_risk_score,
        "contextualized_severity_score": real_risk_score,
        "severity_rating": severity_rating,
        "original_vector": original_vector_str,
        "modified_vector": modified_vector_str,
        "applied_mitigations": applied_mitigations,
        "action_priority": action_priority,
        "action_guidance": action_guidance,
        "technical_answers": technical_answers
    }
        
    return res
