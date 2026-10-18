<script setup>
import { ref, onMounted, watch, computed } from 'vue'
import axios from 'axios'

const apiBaseUrl = 'http://localhost:8000/api'
const loading = ref(true)

// Core Collections
const vulnerabilities = ref([])
const countermeasures = ref([])
const submetricsData = ref(null)
const technicalQuestionsData = ref(null)

// Navigation: Fluid Tabs (No heavy wizard)
const activeTab = ref(1)
const tabs = [
  { id: 1, name: '1. Profilazione & CVSS', short: 'Profilazione' },
  { id: 2, name: '2. Domande Triage Ingegneria', short: 'Domande Triage' },
  { id: 3, name: '3. Contromisure Pertinenti', short: 'Contromisure' },
  { id: 4, name: '4. Sintesi & Verbale', short: 'Sintesi & Score' }
]

// State: Selected Vulnerability
const selectedVuln = ref(null)
const filteredVulns = ref([])

// State: CVSS Base Metrics & Selected Submetrics
const baseMetrics = ref({
  AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'N', I: 'N', A: 'N'
})

const selectedSubmetrics = ref({
  AV: '', AC: '', PR: '', UI: '', S: '', C: '', I: '', A: ''
})

// State: Technical Triage Questions Answers
const triageAnswers = ref({})

// State: Active Countermeasures
const activeCMs = ref({})
const cmFilterType = ref('ALL') // 'ALL', 'PREVENTIVE', 'DETECTIVE'

// State: Calculation Output
const currentRisk = ref(null)
const copyFeedback = ref(false)

// Metric metadata with junior-friendly Italian descriptions and questions
const metricMeta = {
  AV: {
    code: 'AV',
    title: 'Vettore d\'Attacco (Accesso)',
    hint: 'Da dove può colpire l\'attaccante?',
    values: ['N', 'A', 'L', 'P'],
    valueLabels: { N: 'Network', A: 'Adjacent', L: 'Local', P: 'Physical' }
  },
  AC: {
    code: 'AC',
    title: 'Complessità d\'Attacco',
    hint: 'Quanto è difficile preparare ed eseguire l\'exploit?',
    values: ['L', 'H'],
    valueLabels: { L: 'Low (Facile)', H: 'High (Complesso)' }
  },
  PR: {
    code: 'PR',
    title: 'Privilegi Richiesti',
    hint: 'Quali credenziali servono prima di lanciare l\'attacco?',
    values: ['N', 'L', 'H'],
    valueLabels: { N: 'None (Anonimo)', L: 'Low (Utente Base)', H: 'High (Admin / DBA)' }
  },
  UI: {
    code: 'UI',
    title: 'Interazione Utente',
    hint: 'Serve che una vittima compia un\'azione (es. click o download)?',
    values: ['N', 'R'],
    valueLabels: { N: 'None (Zero-Click)', R: 'Required (Serve Click)' }
  },
  S: {
    code: 'S',
    title: 'Scope (Salto di Contesto)',
    hint: 'L\'attacco può evadere dal componente iniziale (es. container o app)?',
    values: ['U', 'C'],
    valueLabels: { U: 'Unchanged (Confinato)', C: 'Changed (Fuga/Pivot)' }
  },
  C: {
    code: 'C',
    title: 'Impatto Confidenzialità',
    hint: 'Cosa può leggere o esfiltrare l\'attaccante?',
    values: ['N', 'L', 'H'],
    valueLabels: { N: 'None (Zero)', L: 'Low (Metadati/Parziale)', H: 'High (Tutto/PII)' }
  },
  I: {
    code: 'I',
    title: 'Impatto Integrità',
    hint: 'Cosa può alterare, cancellare o eseguire?',
    values: ['N', 'L', 'H'],
    valueLabels: { N: 'None (Zero)', L: 'Low (Modifiche Minori)', H: 'High (RCE/Alterazione DB)' }
  },
  A: {
    code: 'A',
    title: 'Impatto Disponibilità',
    hint: 'Il servizio può bloccarsi, crashare o rallentare?',
    values: ['N', 'L', 'H'],
    valueLabels: { N: 'None (Zero)', L: 'Low (Rallentamento)', H: 'High (Crash/Disservizio)' }
  }
}

// Submetrics grouped by Metric and CVSS Value
const groupedSubmetrics = computed(() => {
  if (!submetricsData.value || !submetricsData.value.metrics) return {}
  const res = {}
  for (const [mKey, mObj] of Object.entries(submetricsData.value.metrics)) {
    res[mKey] = {}
    for (const [vKey, vObj] of Object.entries(mObj.values || {})) {
      res[mKey][vKey] = vObj.submetrics || []
    }
  }
  return res
})

// Custom Base Vector computed property
const customVector = computed(() => {
  if (!selectedVuln.value || typeof selectedVuln.value === 'string') return null
  return `CVSS:3.1/AV:${baseMetrics.value.AV}/AC:${baseMetrics.value.AC}/PR:${baseMetrics.value.PR}/UI:${baseMetrics.value.UI}/S:${baseMetrics.value.S}/C:${baseMetrics.value.C}/I:${baseMetrics.value.I}/A:${baseMetrics.value.A}`
})

// Detect Vulnerability Family for targeted technical questions
const detectedFamily = computed(() => {
  if (!selectedVuln.value || typeof selectedVuln.value === 'string') return 'generic'
  const text = [
    selectedVuln.value.name || '',
    selectedVuln.value.threat || '',
    selectedVuln.value.cwe_id || '',
    selectedVuln.value.domain || '',
    selectedVuln.value.root_cause || ''
  ].join(' ').toLowerCase()

  if (text.includes('xss') || text.includes('cross-site') || text.includes('scripting')) return 'xss'
  if (text.includes('sql') || text.includes('database injection')) return 'sqli'
  if (text.includes('ssrf') || text.includes('request forgery')) return 'ssrf'
  if (text.includes('auth') || text.includes('password') || text.includes('brute') || text.includes('credential') || text.includes('jwt') || text.includes('session')) return 'auth_session'
  if (text.includes('cloud') || text.includes('s3') || text.includes('bucket') || text.includes('iam') || text.includes('azure') || text.includes('aws')) return 'cloud_misconfig'
  return 'generic'
})

// Active technical questions for the selected family
const activeTechnicalQuestions = computed(() => {
  if (!technicalQuestionsData.value || !technicalQuestionsData.value.families) return []
  const famKey = detectedFamily.value
  const fam = technicalQuestionsData.value.families[famKey] || technicalQuestionsData.value.families['generic']
  return fam ? fam.questions : []
})

const activeFamilyName = computed(() => {
  if (!technicalQuestionsData.value || !technicalQuestionsData.value.families) return 'Generale'
  const fam = technicalQuestionsData.value.families[detectedFamily.value]
  return fam ? fam.name : 'Generale'
})

// Strictly filtered pertinent countermeasures (NO blanket domain dumping!)
const pertinentCountermeasures = computed(() => {
  if (!selectedVuln.value || typeof selectedVuln.value === 'string') return []
  
  const text = [
    selectedVuln.value.name || '',
    selectedVuln.value.threat || '',
    selectedVuln.value.cwe_id || '',
    selectedVuln.value.domain || '',
    selectedVuln.value.root_cause || ''
  ].join(' ').toLowerCase()

  const list = countermeasures.value.filter(cm => {
    // 1. Detective universal controls always available
    if (cm.cwe_affinity && cm.cwe_affinity.includes('All')) return true

    // 2. Exact affinity match on CWE ID or specific vulnerability tags
    const affs = (cm.cwe_affinity || []).map(a => a.toLowerCase())
    
    // XSS
    if ((text.includes('xss') || text.includes('cross-site') || text.includes('scripting')) && 
        affs.some(a => ['xss', 'cwe-79', 'data injection'].includes(a))) {
      return true
    }
    // SQL / NoSQL Injection
    if ((text.includes('sql') || text.includes('injection')) && 
        affs.some(a => ['sql injection', 'nosql injection', 'injection', 'cwe-89', 'cwe-943'].includes(a))) {
      return true
    }
    // SSRF
    if ((text.includes('ssrf') || text.includes('request forgery')) && 
        affs.some(a => ['ssrf', 'cwe-918', 'lateral movement'].includes(a))) {
      return true
    }
    // Authentication / Brute force / Credential Stuffing
    if ((text.includes('auth') || text.includes('password') || text.includes('credential') || text.includes('brute') || text.includes('session')) && 
        affs.some(a => ['broken authentication', 'credential stuffing', 'brute force', 'cwe-287', 'cwe-307'].includes(a))) {
      return true
    }
    // Cloud Misconfigurations / Buckets / Storage
    if ((text.includes('cloud') || text.includes('s3') || text.includes('bucket') || text.includes('iam')) && 
        affs.some(a => ['misconfiguration', 'insecure storage', 'sensitive data exposure', 'privilege escalation'].includes(a))) {
      return true
    }
    // Generic match on specific CWE code if present
    if (selectedVuln.value.cwe_id && affs.includes(selectedVuln.value.cwe_id.toLowerCase())) {
      return true
    }

    return false
  })

  if (cmFilterType.value === 'PREVENTIVE') {
    return list.filter(c => c.type === 'Preventive')
  } else if (cmFilterType.value === 'DETECTIVE') {
    return list.filter(c => c.type === 'Detective')
  }
  return list
})

// Fetch initial data
const fetchInitialData = async () => {
  try {
    const res = await axios.get(`${apiBaseUrl}/data/`)
    vulnerabilities.value = res.data.vulnerabilities.map(v => ({ ...v, name: v.id }))
    countermeasures.value = res.data.countermeasures
    submetricsData.value = res.data.cvss_submetrics
    technicalQuestionsData.value = res.data.technical_triage_questions
    loading.value = false
  } catch (err) {
    console.error('Failed to load initial data:', err)
  }
}

// Search autocomplete
const searchVuln = (event) => {
  setTimeout(() => {
    if (!event.query.trim().length) {
      filteredVulns.value = [...vulnerabilities.value]
    } else {
      filteredVulns.value = vulnerabilities.value.filter((vuln) => {
        const searchName = vuln.name || vuln.id || ''
        return searchName.toLowerCase().includes(event.query.toLowerCase())
      })
    }
  }, 200)
}

// Calculate Risk
const calculateRisk = async () => {
  if (!customVector.value) return
  const activeIds = Object.keys(activeCMs.value).filter(id => activeCMs.value[id])
  
  try {
    const res = await axios.post(`${apiBaseUrl}/calculate/`, {
      cvss_vector: customVector.value,
      active_countermeasures: activeIds,
      technical_answers: triageAnswers.value
    })
    currentRisk.value = res.data
  } catch (e) {
    console.error('Calculate error:', e)
  }
}

// Select a CVSS Value macro-branch
const selectMacroValue = (metricKey, valKey) => {
  baseMetrics.value[metricKey] = valKey
  const subList = groupedSubmetrics.value[metricKey]?.[valKey] || []
  if (subList.length > 0) {
    selectedSubmetrics.value[metricKey] = subList[0].id
  }
}

// Select a specific sub-metric option
const selectSubmetric = (metricKey, sub) => {
  baseMetrics.value[metricKey] = sub.cvss_value
  selectedSubmetrics.value[metricKey] = sub.id
}

// Sync submetrics when a vulnerability is selected
const syncSubmetricsFromVector = (vectorStr) => {
  if (!vectorStr) return
  const parts = vectorStr.split('/')
  parts.forEach(p => {
    const [k, v] = p.split(':')
    if (baseMetrics.value[k] !== undefined) {
      baseMetrics.value[k] = v
      const subList = groupedSubmetrics.value[k]?.[v] || []
      if (subList.length > 0) {
        selectedSubmetrics.value[k] = subList[0].id
      }
    }
  })
}

// Copy Meeting Summary for Engineering Minutes
const copyMeetingSummary = () => {
  if (!selectedVuln.value || !currentRisk.value) return
  
  const mitigationsText = currentRisk.value.applied_mitigations.length > 0 
    ? currentRisk.value.applied_mitigations.map(m => `- **${m.countermeasure}**: ${m.effect} (${m.justification})`).join('\n')
    : '_Nessuna contromisura tecnica attiva._'

  const triageText = Object.keys(triageAnswers.value).length > 0
    ? Object.entries(triageAnswers.value).map(([k, v]) => `- **${k}**: ${v.label} _(${v.posture})_`).join('\n')
    : '_Nessun chiarimento tecnico annotato._'

  const summary = `### Verbale di Condivisione Vulnerabilità: ${selectedVuln.value.name}
- **Dominio / Causa Radice**: ${selectedVuln.value.domain} | ${selectedVuln.value.root_cause}
- **Vettore Base CVSS 3.1**: \`${currentRisk.value.original_vector}\` (Score: **${currentRisk.value.original_score}**)
- **Vettore Ambientale**: \`${currentRisk.value.modified_vector}\`
- **Contextualized Severity**: **${currentRisk.value.contextualized_severity_score}** (${currentRisk.value.severity_rating})
- **Priorità Remediation**: **${currentRisk.value.action_priority}**
- **Guida Operativa Ingegneria**: ${currentRisk.value.action_guidance}

#### Domande di Triage & Chiarimenti con Ingegneria / Pentester:
${triageText}

#### Contromisure Tecniche Applicate:
${mitigationsText}
`
  navigator.clipboard.writeText(summary)
  copyFeedback.value = true
  setTimeout(() => { copyFeedback.value = false }, 3000)
}

// Watchers
watch(selectedVuln, (newVal) => {
  if (newVal && typeof newVal === 'object' && newVal.cvss_vector) {
    syncSubmetricsFromVector(newVal.cvss_vector)
    activeCMs.value = {}
    triageAnswers.value = {}
    calculateRisk()
  } else {
    currentRisk.value = null
  }
})

watch(activeCMs, () => {
  calculateRisk()
}, { deep: true })

watch(triageAnswers, () => {
  calculateRisk()
}, { deep: true })

watch(customVector, () => {
  calculateRisk()
})

onMounted(() => {
  fetchInitialData()
})
</script>

<template>
  <div class="min-h-screen bg-slate-900 text-slate-100 font-sans selection:bg-blue-600 selection:text-white pb-20">
    
    <!-- Top Persistent Summary Header -->
    <header class="sticky top-0 z-50 bg-slate-900/95 backdrop-blur-md border-b border-slate-800 px-6 py-3.5 shadow-lg">
      <div class="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-3">
        
        <!-- Brand & Mentor Persona -->
        <div class="flex items-center space-x-3">
          <div class="w-10 h-10 rounded-xl bg-gradient-to-br from-blue-500 to-indigo-600 flex items-center justify-center font-black text-xl shadow-md text-white">
            W
          </div>
          <div>
            <h1 class="text-lg font-bold tracking-tight text-white flex items-center gap-2">
              What If <span class="text-blue-400 font-mono text-xs px-2 py-0.5 rounded bg-blue-950 border border-blue-800">Triage Copilot</span>
            </h1>
            <p class="text-[11px] text-slate-400">Guida esperta per analisti di sicurezza nei tavoli tecnici con Ingegneria</p>
          </div>
        </div>

        <!-- Real-time Score Pill Summary -->
        <div v-if="currentRisk" class="flex items-center gap-3 bg-slate-800/90 border border-slate-700 px-4 py-2 rounded-xl shadow-inner">
          <div class="text-right border-r border-slate-700 pr-3">
            <div class="text-[9px] uppercase font-bold tracking-wider text-slate-400">Base CVSS</div>
            <div class="text-sm font-bold font-mono text-slate-300">{{ currentRisk.original_score }}</div>
          </div>

          <div class="text-right border-r border-slate-700 pr-3">
            <div class="text-[9px] uppercase font-bold tracking-wider text-blue-400">Contextualized</div>
            <div class="text-lg font-black font-mono" :class="[
              currentRisk.contextualized_severity_score >= 9.0 ? 'text-red-400' :
              currentRisk.contextualized_severity_score >= 7.0 ? 'text-orange-400' :
              currentRisk.contextualized_severity_score >= 4.0 ? 'text-yellow-400' : 'text-emerald-400'
            ]">
              {{ currentRisk.contextualized_severity_score }}
            </div>
          </div>

          <div class="text-right border-r border-slate-700 pr-3">
            <div class="text-[9px] uppercase font-bold tracking-wider text-slate-400">Delta</div>
            <span class="text-xs font-bold font-mono text-emerald-400">
              -{{ (currentRisk.original_score - currentRisk.contextualized_severity_score).toFixed(1) }}
            </span>
          </div>

          <div>
            <div class="text-[9px] uppercase font-bold tracking-wider text-slate-400">Priorità</div>
            <span class="text-xs font-bold font-mono px-2 py-0.5 rounded bg-blue-900/60 text-blue-200 border border-blue-700/60">
              {{ currentRisk.action_priority?.split(' - ')[0] || 'P3' }}
            </span>
          </div>
        </div>

      </div>

      <!-- Fluid Tab Bar (Fast & Non-blocking) -->
      <div class="max-w-7xl mx-auto mt-3 pt-2.5 border-t border-slate-800 flex items-center justify-between overflow-x-auto gap-2">
        <div class="flex items-center gap-2">
          <button 
            v-for="t in tabs" 
            :key="t.id" 
            @click="activeTab = t.id"
            class="px-4 py-2 rounded-xl text-xs font-bold tracking-wide transition-all cursor-pointer flex items-center gap-2"
            :class="[
              activeTab === t.id 
                ? 'bg-blue-600 text-white shadow-md shadow-blue-500/25' 
                : 'bg-slate-800/60 text-slate-400 hover:text-slate-200 hover:bg-slate-800'
            ]"
          >
            <span>{{ t.name }}</span>
            <span v-if="t.id === 2 && Object.keys(triageAnswers).length > 0" class="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
            <span v-if="t.id === 3 && Object.values(activeCMs).filter(Boolean).length > 0" class="w-4 h-4 rounded-full bg-blue-900 text-blue-300 text-[10px] flex items-center justify-center font-mono">
              {{ Object.values(activeCMs).filter(Boolean).length }}
            </span>
          </button>
        </div>

        <button 
          v-if="selectedVuln && currentRisk"
          @click="copyMeetingSummary" 
          class="px-3.5 py-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-600 rounded-lg text-xs font-bold text-slate-200 flex items-center gap-1.5 transition-all cursor-pointer shadow whitespace-nowrap"
        >
          <span>📋</span>
          <span>{{ copyFeedback ? 'Copiato!' : 'Copia Verbale' }}</span>
        </button>
      </div>
    </header>

    <!-- Main Container -->
    <main class="max-w-7xl mx-auto px-6 pt-6">

      <!-- Loading State -->
      <div v-if="loading" class="text-center py-24 text-slate-400">
        <div class="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500 mb-4"></div>
        <p class="font-medium text-sm">Caricamento Catalogo Vulnerabilità, Matrice Sotto-Parametri e Domande di Triage...</p>
      </div>

      <div v-else>

        <!-- TAB 1: Profilazione & Sotto-Parametri con Selettori Raggruppati -->
        <div v-show="activeTab === 1" class="space-y-6">
          
          <!-- Search & Vulnerability Card -->
          <div class="bg-slate-800/60 border border-slate-700 rounded-2xl p-5 shadow-sm">
            <div class="flex flex-col md:flex-row md:items-center justify-between gap-3 mb-4">
              <div>
                <h2 class="text-lg font-bold text-white flex items-center gap-2">
                  <span class="text-blue-400">1.</span> Ricerca & Profilazione della Vulnerabilità
                </h2>
                <p class="text-xs text-slate-400 mt-0.5">
                  Digita il nome o il CWE per importare la vulnerabilità a catalogo con il suo vettore base standard.
                </p>
              </div>
              <span v-if="selectedVuln" class="px-3 py-1 bg-blue-950 text-blue-300 text-xs font-mono font-semibold rounded-full border border-blue-800 self-start md:self-auto">
                {{ selectedVuln.domain }} | {{ selectedVuln.root_cause }}
              </span>
            </div>

            <AutoComplete 
              v-model="selectedVuln" 
              :suggestions="filteredVulns" 
              @complete="searchVuln" 
              optionLabel="name" 
              placeholder="Cerca vulnerabilità a catalogo (es. Reflected Cross-Site Scripting, SQL Injection, S3 Bucket...)"
              class="w-full"
              inputClass="w-full px-4 py-3 bg-slate-900 border border-slate-700 text-white placeholder-slate-500 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm font-medium"
            />

            <!-- Vulnerability Details Box -->
            <div v-if="selectedVuln && typeof selectedVuln === 'object'" class="mt-4 p-4 bg-slate-900/90 rounded-xl border border-slate-700/80">
              <div class="flex items-center justify-between">
                <h3 class="font-bold text-sm text-slate-100">{{ selectedVuln.name }}</h3>
                <span class="text-xs font-mono text-slate-400">CWE: {{ selectedVuln.cwe_id || 'CWE Standard' }}</span>
              </div>
              <p class="text-xs text-slate-400 mt-1.5 leading-relaxed">{{ selectedVuln.threat || 'Nessuna descrizione a catalogo disponibile.' }}</p>
            </div>
          </div>

          <!-- Grouped Submetrics Selector Grid -->
          <div v-if="selectedVuln && typeof selectedVuln === 'object'" class="bg-slate-800/60 border border-slate-700 rounded-2xl p-5 shadow-sm space-y-4">
            <div>
              <h3 class="text-base font-bold text-white">Declinazione Operativa dei Parametri CVSS</h3>
              <p class="text-xs text-slate-400 mt-0.5">
                Seleziona prima la branca CVSS (es. <em>Network</em> o <em>Adjacent</em>) e poi clicca sulla situazione architetturale reale. Il calcolo rimarrà rigorosamente aderente al CVSS.
              </p>
            </div>

            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
              
              <!-- Metric Card Component -->
              <div 
                v-for="(meta, mKey) in metricMeta" 
                :key="mKey" 
                class="p-4 bg-slate-900/80 border border-slate-700/80 rounded-xl flex flex-col justify-between"
              >
                <!-- Metric Header -->
                <div>
                  <div class="flex items-center justify-between mb-1">
                    <span class="text-xs font-bold text-slate-200 flex items-center gap-1.5">
                      <span class="text-blue-400 font-mono font-black">{{ meta.code }}</span>
                      <span>{{ meta.title }}</span>
                    </span>
                    <span class="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-blue-300 border border-slate-700 font-bold">
                      Valore: {{ baseMetrics[mKey] }}
                    </span>
                  </div>
                  <p class="text-[11px] text-slate-400 mb-3">{{ meta.hint }}</p>

                  <!-- Level 1: Macro-Branch Selector (Network, Adjacent, Local, etc.) -->
                  <div class="flex flex-wrap gap-1 mb-3">
                    <button 
                      v-for="val in meta.values" 
                      :key="val"
                      @click="selectMacroValue(mKey, val)"
                      class="px-2.5 py-1 text-[11px] font-bold rounded-lg transition-all cursor-pointer border"
                      :class="[
                        baseMetrics[mKey] === val
                          ? 'bg-blue-600 text-white border-blue-500 shadow-sm'
                          : 'bg-slate-800 text-slate-400 border-slate-700 hover:text-slate-200'
                      ]"
                    >
                      {{ meta.valueLabels[val] || val }}
                    </button>
                  </div>

                  <!-- Level 2: Clickable Operational Sub-options for the Active Branch -->
                  <div class="space-y-1.5">
                    <div 
                      v-for="sub in (groupedSubmetrics[mKey]?.[baseMetrics[mKey]] || [])" 
                      :key="sub.id"
                      @click="selectSubmetric(mKey, sub)"
                      class="p-2.5 rounded-lg border transition-all cursor-pointer flex items-start justify-between gap-2"
                      :class="[
                        selectedSubmetrics[mKey] === sub.id 
                          ? 'bg-blue-950/80 border-blue-500 ring-1 ring-blue-500/50 text-white' 
                          : 'bg-slate-800/40 border-slate-800 hover:bg-slate-800/80 text-slate-300'
                      ]"
                    >
                      <div class="flex-1">
                        <div class="text-xs font-bold leading-tight flex items-center gap-1.5">
                          <span>{{ sub.label }}</span>
                          <span v-if="selectedSubmetrics[mKey] === sub.id" class="text-blue-400 font-bold text-[11px]">✓</span>
                        </div>
                        <div class="text-[10px] text-slate-400 mt-1 leading-snug">{{ sub.description }}</div>
                      </div>
                    </div>
                  </div>
                </div>

              </div>

            </div>

            <!-- Vector String Banner -->
            <div class="p-3 bg-slate-950 rounded-xl border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-3">
              <div>
                <span class="text-[10px] font-bold uppercase tracking-wider text-slate-500">Vettore CVSS Calcolato</span>
                <div class="font-mono text-xs text-blue-300 break-all">{{ customVector }}</div>
              </div>
              <button 
                @click="activeTab = 2" 
                class="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold rounded-lg transition-all cursor-pointer shadow whitespace-nowrap"
              >
                Vai alle Domande di Triage &rarr;
              </button>
            </div>
          </div>

        </div>

        <!-- TAB 2: Domande di Triage Tecnico & Pentest Challenge (Vulnerability-Specific) -->
        <div v-show="activeTab === 2" class="space-y-6">
          <div class="bg-slate-800/60 border border-slate-700 rounded-2xl p-5 shadow-sm">
            <div class="flex flex-col md:flex-row md:items-center justify-between gap-3 mb-4">
              <div>
                <h2 class="text-lg font-bold text-white flex items-center gap-2">
                  <span class="text-blue-400">2.</span> Guida Domande di Triage & Pentest Challenge
                </h2>
                <p class="text-xs text-slate-400 mt-0.5">
                  Domande tecniche specifiche per <strong class="text-blue-300">{{ activeFamilyName }}</strong> per condurre la riunione con Ingegneria, evitare silenzi imbarazzanti e validare tecnicamente le affermazioni del report.
                </p>
              </div>

              <span class="px-3 py-1 rounded-full text-xs font-mono font-bold bg-indigo-950 text-indigo-300 border border-indigo-800">
                Categoria: {{ activeFamilyName }}
              </span>
            </div>

            <!-- Technical Questions List -->
            <div class="space-y-5 mt-4">
              <div 
                v-for="(q, qIdx) in activeTechnicalQuestions" 
                :key="q.id"
                class="p-4 bg-slate-900/80 border border-slate-800 rounded-xl space-y-3"
              >
                <!-- Title & Question to Ask -->
                <div class="border-b border-slate-800 pb-2.5">
                  <div class="flex items-center justify-between text-xs text-slate-400 mb-1">
                    <span class="font-mono font-bold text-blue-400">Punto di Confronto #{{ qIdx + 1 }}</span>
                    <span class="font-semibold text-slate-300">{{ q.title }}</span>
                  </div>
                  <div class="text-sm font-bold text-white bg-slate-950/70 p-3 rounded-lg border border-slate-800/80 flex items-start gap-2.5">
                    <span class="text-blue-400 text-base">💬</span>
                    <div>
                      <div class="text-[10px] uppercase font-bold text-blue-400 tracking-wider">Cosa Chiedere in Riunione:</div>
                      <div class="text-xs text-slate-200 mt-0.5">{{ q.question_to_ask }}</div>
                    </div>
                  </div>
                </div>

                <!-- Guidance for Junior Analyst -->
                <div class="bg-amber-950/30 border border-amber-800/40 p-2.5 rounded-lg flex items-start gap-2">
                  <span class="text-amber-400 text-sm">💡</span>
                  <div class="text-[11px] text-amber-200/90 leading-relaxed">
                    <strong class="text-amber-300">Cosa deve ascoltare l'analista:</strong> {{ q.analyst_guidance }}
                  </div>
                </div>

                <!-- Selectable Response Options -->
                <div>
                  <div class="text-[10px] uppercase font-bold text-slate-500 mb-1.5 tracking-wider">Risposta / Riscontro Tecnico del Team:</div>
                  <div class="grid grid-cols-1 md:grid-cols-3 gap-2">
                    <button 
                      v-for="opt in q.options" 
                      :key="opt.label"
                      @click="triageAnswers[q.id] = opt"
                      type="button"
                      class="p-2.5 rounded-lg border text-left transition-all cursor-pointer flex flex-col justify-between"
                      :class="[
                        triageAnswers[q.id]?.label === opt.label
                          ? 'bg-blue-950/80 border-blue-500 ring-1 ring-blue-500 text-white'
                          : 'bg-slate-800/50 border-slate-700/80 hover:bg-slate-800 text-slate-300'
                      ]"
                    >
                      <div>
                        <div class="flex items-center justify-between mb-1">
                          <span class="text-xs font-bold">{{ opt.label }}</span>
                          <span 
                            class="text-[9px] font-mono px-1.5 py-0.2 rounded font-bold"
                            :class="[
                              opt.posture === 'Mitigante' ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' :
                              opt.posture === 'Aggravante' ? 'bg-red-950 text-red-300 border border-red-800' :
                              'bg-slate-800 text-slate-300'
                            ]"
                          >
                            {{ opt.posture }}
                          </span>
                        </div>
                        <p class="text-[10px] text-slate-400 leading-snug">{{ opt.details }}</p>
                      </div>
                    </button>
                  </div>
                </div>

              </div>
            </div>

            <!-- Tab Navigation Footer -->
            <div class="mt-6 flex items-center justify-between pt-4 border-t border-slate-800">
              <button 
                @click="activeTab = 1" 
                class="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-bold rounded-lg transition-all cursor-pointer"
              >
                &larr; Torna alla Profilazione
              </button>
              <button 
                @click="activeTab = 3" 
                class="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold rounded-lg transition-all cursor-pointer shadow"
              >
                Procedi alle Contromisure &rarr;
              </button>
            </div>
          </div>
        </div>

        <!-- TAB 3: Contromisure Pertinenti (Strict Filtering & Exact CVSS Math) -->
        <div v-show="activeTab === 3" class="space-y-6">
          <div class="bg-slate-800/60 border border-slate-700 rounded-2xl p-5 shadow-sm">
            <div class="flex flex-col md:flex-row md:items-center justify-between gap-3 mb-4">
              <div>
                <h2 class="text-lg font-bold text-white flex items-center gap-2">
                  <span class="text-blue-400">3.</span> Contromisure Tecniche Pertinenti
                </h2>
                <p class="text-xs text-slate-400 mt-0.5">
                  Filtrate rigorosamente per la vulnerabilità in esame. I controlli <strong class="text-emerald-400">Preventive</strong> riducono il CVSS; i controlli <strong class="text-purple-400">Detective</strong> abbattono l'MTTD senza falsare lo score.
                </p>
              </div>

              <!-- Filter Pills -->
              <div class="flex items-center gap-1 bg-slate-900 p-1 rounded-lg border border-slate-800 self-start md:self-auto">
                <button 
                  @click="cmFilterType = 'ALL'" 
                  class="px-2.5 py-1 text-xs font-semibold rounded-md transition-all cursor-pointer"
                  :class="cmFilterType === 'ALL' ? 'bg-blue-600 text-white' : 'text-slate-400 hover:text-white'"
                >
                  Tutte ({{ pertinentCountermeasures.length }})
                </button>
                <button 
                  @click="cmFilterType = 'PREVENTIVE'" 
                  class="px-2.5 py-1 text-xs font-semibold rounded-md transition-all cursor-pointer"
                  :class="cmFilterType === 'PREVENTIVE' ? 'bg-emerald-600 text-white' : 'text-slate-400 hover:text-white'"
                >
                  Preventive
                </button>
                <button 
                  @click="cmFilterType = 'DETECTIVE'" 
                  class="px-2.5 py-1 text-xs font-semibold rounded-md transition-all cursor-pointer"
                  :class="cmFilterType === 'DETECTIVE' ? 'bg-purple-600 text-white' : 'text-slate-400 hover:text-white'"
                >
                  Detective
                </button>
              </div>
            </div>

            <!-- Zero State if no pertinent countermeasure -->
            <div v-if="pertinentCountermeasures.length === 0" class="p-8 text-center bg-slate-900/60 rounded-xl border border-slate-800 text-slate-400 text-xs">
              Nessuna contromisura tecnica specifica a catalogo per questa tipologia di vulnerabilità.
            </div>

            <!-- Countermeasure List -->
            <div v-else class="grid grid-cols-1 md:grid-cols-2 gap-3.5">
              <div 
                v-for="cm in pertinentCountermeasures" 
                :key="cm.id"
                class="p-4 rounded-xl border transition-all flex items-start justify-between gap-3"
                :class="[
                  activeCMs[cm.id] 
                    ? 'bg-slate-900 border-blue-500/80 shadow-md ring-1 ring-blue-500/30' 
                    : 'bg-slate-900/50 border-slate-800 hover:border-slate-700'
                ]"
              >
                <div class="flex-1">
                  <div class="flex items-center gap-2 mb-1">
                    <span class="text-xs font-mono font-bold text-slate-400">{{ cm.id }}</span>
                    <span 
                      class="text-[9px] font-semibold px-2 py-0.5 rounded-full"
                      :class="cm.type === 'Preventive' ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' : 'bg-purple-950 text-purple-300 border border-purple-800'"
                    >
                      {{ cm.type }}
                    </span>
                    <span class="text-[10px] text-slate-500 font-mono">{{ cm.category }}</span>
                  </div>

                  <h3 class="font-bold text-sm text-slate-200 cursor-pointer" @click="activeCMs[cm.id] = !activeCMs[cm.id]">
                    {{ cm.name }}
                  </h3>

                  <p class="text-xs text-slate-400 mt-1 leading-relaxed">{{ cm.description }}</p>

                  <div v-if="cm.technical_specification" class="mt-2 text-[10px] text-slate-500 bg-slate-950/70 p-2 rounded-lg border border-slate-800/80 font-mono">
                    {{ cm.technical_specification }}
                  </div>
                </div>

                <div class="pt-1">
                  <ToggleSwitch v-model="activeCMs[cm.id]" />
                </div>
              </div>
            </div>

            <!-- Tab Navigation Footer -->
            <div class="mt-6 flex items-center justify-between pt-4 border-t border-slate-800">
              <button 
                @click="activeTab = 2" 
                class="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-bold rounded-lg transition-all cursor-pointer"
              >
                &larr; Torna alle Domande di Triage
              </button>
              <button 
                @click="activeTab = 4" 
                class="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold rounded-lg transition-all cursor-pointer shadow"
              >
                Visualizza Sintesi & Score &rarr;
              </button>
            </div>
          </div>
        </div>

        <!-- TAB 4: Sintesi & Contextualized Severity -->
        <div v-show="activeTab === 4" class="space-y-6">
          <div v-if="!currentRisk" class="text-center py-20 text-slate-400">
            Seleziona una vulnerabilità al Tab 1 per visualizzare la severità contestualizzata.
          </div>

          <div v-else class="space-y-6">
            
            <!-- Hero Dashboard Banner -->
            <div class="bg-gradient-to-br from-slate-900 via-slate-850 to-slate-900 border border-slate-700 rounded-3xl p-6 shadow-xl">
              <div class="grid grid-cols-1 lg:grid-cols-3 gap-6 items-center">
                
                <!-- Score Dial Display -->
                <div class="flex flex-col items-center justify-center text-center">
                  <div 
                    class="relative w-40 h-40 rounded-full flex flex-col items-center justify-center border-8 shadow-inner transition-all duration-500"
                    :class="[
                      currentRisk.contextualized_severity_score >= 9.0 ? 'border-red-500 bg-red-950/20' :
                      currentRisk.contextualized_severity_score >= 7.0 ? 'border-orange-500 bg-orange-950/20' :
                      currentRisk.contextualized_severity_score >= 4.0 ? 'border-yellow-400 bg-yellow-950/20' : 'border-emerald-400 bg-emerald-950/20'
                    ]"
                  >
                    <div class="text-4xl font-black font-mono tracking-tight text-white">
                      {{ currentRisk.contextualized_severity_score }}
                    </div>
                    <div class="text-xs font-bold uppercase tracking-wider text-slate-400 mt-0.5">
                      {{ currentRisk.severity_rating }}
                    </div>
                  </div>
                  <div class="mt-2 text-xs font-bold uppercase tracking-wider text-blue-400">
                    Contextualized Severity Score
                  </div>
                </div>

                <!-- Metrics & Prioritization Box -->
                <div class="lg:col-span-2 space-y-3.5">
                  <div class="flex flex-wrap items-center justify-between gap-2">
                    <div>
                      <span class="text-[10px] font-bold uppercase tracking-wider text-slate-400">Vulnerabilità Valutata</span>
                      <h2 class="text-xl font-bold text-white mt-0.5">{{ selectedVuln?.name }}</h2>
                    </div>

                    <button 
                      @click="copyMeetingSummary" 
                      class="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-xl text-xs font-bold flex items-center gap-1.5 transition-all cursor-pointer shadow"
                    >
                      <span>📋</span>
                      <span>{{ copyFeedback ? 'Copiato!' : 'Copia Verbale per Ingegneria' }}</span>
                    </button>
                  </div>

                  <!-- Metric Comparison Badges -->
                  <div class="grid grid-cols-3 gap-3 pt-1">
                    <div class="p-3 bg-slate-950/80 rounded-xl border border-slate-800">
                      <div class="text-[9px] font-bold text-slate-500 uppercase tracking-wider">Base CVSS</div>
                      <div class="text-lg font-bold font-mono text-slate-300 mt-0.5">{{ currentRisk.original_score }}</div>
                      <div class="text-[10px] text-slate-500">Score teorico</div>
                    </div>

                    <div class="p-3 bg-slate-950/80 rounded-xl border border-slate-800">
                      <div class="text-[9px] font-bold text-slate-500 uppercase tracking-wider">Riduzione Reale</div>
                      <div class="text-lg font-bold font-mono text-emerald-400 mt-0.5">
                        -{{ (currentRisk.original_score - currentRisk.contextualized_severity_score).toFixed(1) }}
                      </div>
                      <div class="text-[10px] text-slate-500">Da contromisure attive</div>
                    </div>

                    <div class="p-3 bg-slate-950/80 rounded-xl border border-slate-800">
                      <div class="text-[9px] font-bold text-slate-500 uppercase tracking-wider">Priorità Concordata</div>
                      <div class="text-sm font-bold font-mono text-blue-300 mt-0.5 truncate">
                        {{ currentRisk.action_priority?.split(' - ')[0] }}
                      </div>
                      <div class="text-[10px] text-slate-500">Remediation SLA</div>
                    </div>
                  </div>

                  <!-- Action Guidance Banner -->
                  <div class="p-3 bg-blue-950/40 border border-blue-800/60 rounded-xl">
                    <div class="text-[10px] font-bold uppercase tracking-wider text-blue-400 mb-0.5">Guida Operativa Ingegneria:</div>
                    <p class="text-xs text-slate-200 leading-relaxed">{{ currentRisk.action_guidance }}</p>
                  </div>
                </div>

              </div>
            </div>

            <!-- Detail Grid: Vectors & Triage Answers -->
            <div class="grid grid-cols-1 lg:grid-cols-2 gap-5">
              
              <!-- Left: Vector Traceability -->
              <div class="bg-slate-800/60 border border-slate-700 rounded-2xl p-5 shadow-sm space-y-3">
                <h3 class="text-sm font-bold text-white flex items-center gap-2">
                  <span>📐</span> Tracciabilità Tecnica dei Vettori CVSS
                </h3>

                <div class="space-y-2">
                  <div class="p-2.5 bg-slate-950 rounded-xl border border-slate-800">
                    <div class="text-[9px] font-bold uppercase text-slate-500">Vettore Base</div>
                    <code class="text-xs font-mono text-slate-300 break-all">{{ currentRisk.original_vector }}</code>
                  </div>

                  <div class="p-2.5 bg-slate-950 rounded-xl border border-slate-800">
                    <div class="text-[9px] font-bold uppercase text-blue-400">Vettore Ambientale Modificato</div>
                    <code class="text-xs font-mono text-blue-300 break-all">{{ currentRisk.modified_vector }}</code>
                  </div>
                </div>

                <!-- Applied Mitigations list -->
                <div class="pt-2">
                  <div class="text-[10px] font-bold uppercase tracking-wider text-slate-400 mb-2">Effetti delle Contromisure Attive:</div>
                  <div v-if="currentRisk.applied_mitigations.length > 0" class="space-y-2 max-h-[180px] overflow-y-auto pr-1">
                    <div 
                      v-for="m in currentRisk.applied_mitigations" 
                      :key="m.countermeasure"
                      class="p-2.5 bg-slate-900 rounded-lg border border-slate-800"
                    >
                      <div class="flex items-center justify-between text-xs mb-1">
                        <span class="font-bold text-slate-200">{{ m.countermeasure }}</span>
                        <span class="text-[10px] font-mono text-emerald-400">{{ m.effect }}</span>
                      </div>
                      <p class="text-[11px] text-slate-400 leading-snug">{{ m.justification }}</p>
                    </div>
                  </div>
                  <div v-else class="text-xs text-slate-500 italic p-3 bg-slate-950/40 rounded-lg border border-slate-800">
                    Nessuna contromisura tecnica attiva.
                  </div>
                </div>
              </div>

              <!-- Right: Triage Questions Verified in Meeting -->
              <div class="bg-slate-800/60 border border-slate-700 rounded-2xl p-5 shadow-sm space-y-3">
                <h3 class="text-sm font-bold text-white flex items-center gap-2">
                  <span>💬</span> Riscontri Tecnici della Condivisione
                </h3>

                <div v-if="Object.keys(triageAnswers).length > 0" class="space-y-2 max-h-[300px] overflow-y-auto pr-1">
                  <div 
                    v-for="(ans, qKey) in triageAnswers" 
                    :key="qKey"
                    class="p-2.5 bg-slate-900 rounded-lg border border-slate-800"
                  >
                    <div class="flex items-center justify-between text-xs mb-0.5">
                      <span class="font-bold text-slate-200">{{ ans.label }}</span>
                      <span 
                        class="text-[9px] font-mono px-1.5 py-0.2 rounded font-bold"
                        :class="ans.posture === 'Mitigante' ? 'bg-emerald-950 text-emerald-300' : 'bg-red-950 text-red-300'"
                      >
                        {{ ans.posture }}
                      </span>
                    </div>
                    <p class="text-[11px] text-slate-400">{{ ans.details }}</p>
                  </div>
                </div>

                <div v-else class="text-xs text-slate-500 italic p-6 text-center bg-slate-950/40 rounded-xl border border-slate-800">
                  Nessuna domanda di triage annotata. Vai al Tab 2 per consultare le domande specifiche per {{ activeFamilyName }}.
                </div>
              </div>

            </div>

            <!-- Tab Navigation Footer -->
            <div class="flex items-center justify-between pt-4 border-t border-slate-800">
              <button 
                @click="activeTab = 3" 
                class="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-bold rounded-lg transition-all cursor-pointer"
              >
                &larr; Modifica Contromisure
              </button>
              <button 
                @click="activeTab = 1" 
                class="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold rounded-lg transition-all cursor-pointer shadow"
              >
                Nuova Vulnerabilità &rarr;
              </button>
            </div>

          </div>
        </div>

      </div>
    </main>

  </div>
</template>
