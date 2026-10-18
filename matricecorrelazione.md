---

### 1. Vettore di Attacco (Attack Vector - AV)

| Metrica Nativa | Valore CVSS | Sotto-Label Operativa | Descrizione e Perimetro di Accesso |
| --- | --- | --- | --- |
| **Attack Vector (AV)** | `Network (N)` | **Public Internet-Facing** | Esposto direttamente su indirizzi IP/FQDN pubblici senza protezioni di rete perimetrali. |
|  | `Network (N)` | **ISP Backbone / Carrier Transit** | Infrastruttura di routing core/transito ISP o peering pubblico (BGP, router perimetrali di transito). |
|  | `Network (N)` | **Internal Routable LAN** | Rete interna aziendale o subnet di datacenter raggiungibile da altri segmenti interni tramite normale routing L3. |
|  | `Adjacent (A)` | **Corporate VPN / Tunnel Gateway** | Accesso condizionato all'autenticazione preventiva a una VPN aziendale (client-to-site o concentratore remoto). |
|  | `Adjacent (A)` | **Intercompany Peering / B2B MPLS** | Connessioni dedicate chiuse verso partner terzi, fornitori o filiali (circuiti MPLS privati, cross-connect). |
|  | `Adjacent (A)` | **Same L2 Broadcast Domain** | Richiede presenza sullo stesso switch, VLAN o dominio di broadcast locale (ARP spoofing, LLMNR, mDNS). |
|  | `Adjacent (A)` | **Wireless / Radio Proximity** | Richiede raggio d'azione radio diretto (Wi-Fi Corporate/Guest, Bluetooth, BLE, Zigbee, RFID). |
|  | `Local (L)` | **Interactive Shell Access** | Richiede una sessione di login locale/remota già attiva sul target (SSH, RDP, terminale interattivo). |
|  | `Local (L)` | **Desktop / Endpoint Client** | Vulnerabilità in software desktop/CLI che richiede l'apertura o l'invocazione locale da parte dell'operatore. |
|  | `Physical (P)` | **Hardware Interface / Console** | Accesso tramite porte fisiche dirette (USB, JTAG, Thunderbolt) o console rack/laptop incustodito. |

---

### 2. Complessità di Attacco (Attack Complexity - AC)

| Metrica Nativa | Valore CVSS | Sotto-Label Operativa | Profilo Attaccante e Tooling Richiesto |
| --- | --- | --- | --- |
| **Attack Complexity (AC)** | `Low (L)` | **No Technical Experience Needed** | Exploit "1-click" o zero interazione tecnica; automatismi reperibili pubblicamente, interfacce web point-and-click. |
|  | `Low (L)` | **Script Kiddie / Commodity Tooling** | Utilizzo di moduli Metasploit precompilati, script Python pronti su GitHub, scanner automatizzati con payload integrati. |
|  | `High (H)` | **Senior Exploit Developer / Expert** | Richiede scrittura di shellcode personalizzato, reverse-engineering del binario, bypass di protezioni (ASLR, DEP/W^X) o race condition temporali strette. |
|  | `High (H)` | **Nation-State / APT / Tier-1 Actor** | Richiede catene multi-exploit (chain 0-day), risorse computazionali estese per attacchi crittografici, bypass di protezioni hardware proprietarie o posizionamento su dorsali statali. |

---

### 3. Ambito di Sicurezza (Scope - S)

*Evidenzia il salto di contesto di sicurezza tra componente vulnerabile e componente impattato.*

| Metrica Nativa | Valore CVSS | Sotto-Label Operativa | Limite di Contesto e Privilegio |
| --- | --- | --- | --- |
| **Scope (S)** | `Unchanged (U)` | **Strict Application Sandbox** | L'attacco è isolato nel runtime applicativo (es. un DoS che crasha solo il thread dell'app o SQLi confinata a un DB dedicato). |
|  | `Unchanged (U)` | **Intra-Service / Local Isolation** | L'impatto non scavalca il set di permessi del processo vulnerabile né coinvolge altri tenant/sistemi. |
|  | `Changed (C)` | **App-to-Host RCE (Breakout)** | **Vulnerabilità applicativa (es. deserialization/command injection) che fornisce un accesso a riga di comando sull'OS host, scavalcando la sandbox applicativa.** |
|  | `Changed (C)` | **Container / VM Escape** | Fuga dal container Docker/K8s verso l'host node, o da VM guest verso l'hypervisor (KVM/ESXi). |
|  | `Changed (C)` | **Cross-Tenant Cloud / IAM Pivot** | Sfruttamento dell'asset per rubare token temporanei (es. SSRF verso IMDSv1/v2) ed eseguire chiamate API autorizzate sul control plane Cloud. |
|  | `Changed (C)` | **Cross-User Session (Stored XSS)** | Codice iniettato nell'applicazione che viene eseguito nel contesto di sicurezza del browser di altri utenti ignari. |

---

 |
| **Privileges Required (PR)** | `None (N)` | **Anonymous / Public User** | Nessuna autenticazione necessaria; sfruttabile da chiunque raggiunga l'endpoint. |
|  | `Low (L)` | **Standard End-User / Customer** | Richiede credenziali base (es. utente registrato su un portale e-commerce, account AD standard senza diritti admin). |
|  | `Low (L)` | **Service Account / Low Scope** | Credenziali di un microservizio o API key con permessi minimi di sola lettura o funzioni limitate. |
|  | `High (H)` | **Domain / Enterprise Admin** | Richiede privilegi massimi sull'infrastruttura (Domain Admin in Active Directory, root su Linux, Cloud IAM Global Admin). |
|  | `High (H)` | **Application / Database DBA** | Privilegi amministrativi confinati alla singola applicazione o al database di backend. |
| **User Interaction (UI)** | `None (N)` | **Zero-Click / Autonomous** | Sfruttabile automaticamente all'arrivo del payload (demoni di rete, wormable). |
|  | `Required (R)` | **1-Click Phishing / Link Click** | La vittima deve cliccare su un link malevolo, visitare una pagina specifica o autorizzare un prompt (es. OAuth consent). |
|  | `Required (R)` | **File Download & Execution** | La vittima deve scaricare e aprire manualmente un file (es. macro Office, archivio malevolo, installer ingannevole). |

---

### Metriche di Ambito e Impatto (Scope & Impact)

| Metrica Nativa | Valore CVSS | Sotto-Label Operativa | Definizione e Scenario Pratico |
| --- | --- | --- | --- |
| **Scope (S)** | `Unchanged (U)` | **Contained in Component** | L'impatto resta confinato al runtime dell'applicazione o all'istanza vulnerabile (es. SQLi che impatta solo il DB dell'app). |
|  | `Changed (C)` | **Container Breakout / Virtual Escape** | Fuga dal container verso l'host OS o da una Virtual Machine verso l'hypervisor. |
|  | `Changed (C)` | **Cross-Context (es. Stored XSS)** | Esecuzione di codice arbitrario nel contesto di sicurezza del browser di altri utenti. |
|  | `Changed (C)` | **IAM Pivot / Metadata Service** | Compromissione di un servizio che permette di estrarre credenziali cloud (es. SSRF verso AWS IMDS per assumere ruoli IAM). |
| **Confidentiality (C)** | `None (N)` | **No Data Disclosure** | Nessuna perdita di riservatezza. |
|  | `Low (L)` | **System Metadata / Error Leaks** | Esposizione di versioni software, stack trace, percorsi interni o enumerazione di username. |
|  | `High (H)` | **PII / Sensitive Business Data** | Esfiltrazione di dati personali (GDPR), carte di pagamento (PCI-DSS), segreti industriali o sorgenti core. |
|  | `High (H)` | **Critical Cryptographic Secrets** | Compromissione di chiavi private TLS, token di firma JWT, credenziali di accesso master. |
| **Integrity (I)** | `None (N)` | **No Modification** | I dati e i file di sistema non possono essere alterati. |
|  | `Low (L)` | **Non-Critical Data Alteration** | Modifica di preferenze utente, commenti, log superficiali o defacement cosmetico non strutturale. |
|  | `High (H)` | **Arbitrary Code Execution (RCE)** | Capacità di scrivere file arbitrari, alterare binari di sistema, installare backdoor o modificare record di database transazionali. |
| **Availability (A)** | `None (N)` | **No Impact** | La disponibilità e i tempi di risposta non subiscono variazioni. |
|  | `Low (L)` | **Degraded Performance / Thread Hang** | Rallentamenti delle risposte, consumo elevato di CPU per singolo processo senza blocco del servizio globale. |
|  | `High (H)` | **Full System Crash / Outage** | Kernel panic, esaurimento totale delle risorse, cancellazione di dischi/storage o disservizio totale del servizio critico. |

---
