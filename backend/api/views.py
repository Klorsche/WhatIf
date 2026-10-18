
from rest_framework.decorators import api_view
from rest_framework.response import Response
import json
from .engine import calculate_real_risk
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VULN_FILE = os.path.join(BASE_DIR, 'sn_vul_app_vul_entry_cleaned.json')
CM_FILE = os.path.join(BASE_DIR, 'countermeasures.json')
SUBMETRICS_FILE = os.path.join(BASE_DIR, 'cvss_submetrics.json')
QUESTIONS_FILE = os.path.join(BASE_DIR, 'context_questions.json')
TECH_QUESTIONS_FILE = os.path.join(BASE_DIR, 'technical_triage_questions.json')

@api_view(['GET'])
def get_data(request):
    vulns = []
    if os.path.exists(VULN_FILE):
        with open(VULN_FILE, 'r', encoding='utf-8') as f:
            vulns = json.load(f).get('records', [])
            
    cms = []
    if os.path.exists(CM_FILE):
        with open(CM_FILE, 'r', encoding='utf-8') as f:
            cms = json.load(f).get('countermeasures', [])
            
    submetrics = {}
    if os.path.exists(SUBMETRICS_FILE):
        with open(SUBMETRICS_FILE, 'r', encoding='utf-8') as f:
            submetrics = json.load(f)

    questions = {}
    if os.path.exists(QUESTIONS_FILE):
        with open(QUESTIONS_FILE, 'r', encoding='utf-8') as f:
            questions = json.load(f)
            
    tech_questions = {}
    if os.path.exists(TECH_QUESTIONS_FILE):
        with open(TECH_QUESTIONS_FILE, 'r', encoding='utf-8') as f:
            tech_questions = json.load(f)
        
    # clean up missing vectors for the UI to not crash
    valid_vulns = [v for v in vulns if v.get('cvss_vector') and v['cvss_vector'].startswith('CVSS')]
    return Response({
        "vulnerabilities": valid_vulns,
        "countermeasures": cms,
        "cvss_submetrics": submetrics,
        "context_questions": questions,
        "technical_triage_questions": tech_questions
    })

@api_view(['GET'])
def get_submetrics(request):
    if os.path.exists(SUBMETRICS_FILE):
        with open(SUBMETRICS_FILE, 'r', encoding='utf-8') as f:
            return Response(json.load(f))
    return Response({"error": "cvss_submetrics.json not found"}, status=404)

@api_view(['GET'])
def get_context_questions(request):
    if os.path.exists(QUESTIONS_FILE):
        with open(QUESTIONS_FILE, 'r', encoding='utf-8') as f:
            return Response(json.load(f))
    return Response({"error": "context_questions.json not found"}, status=404)

@api_view(['POST'])
def calculate_risk(request):
    data = request.data
    vector = data.get('cvss_vector')
    active_cms = data.get('active_countermeasures', [])
    context_answers = data.get('context_answers', None)
    if not vector:
        return Response({"error": "Missing cvss_vector"}, status=400)
        
    result = calculate_real_risk(vector, active_cms, context_answers)
    return Response(result)

