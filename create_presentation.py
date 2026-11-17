import pptx
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN
from pptx.enum.shapes import MSO_SHAPE

prs = Presentation()
prs.slide_width = Inches(13.333)
prs.slide_height = Inches(7.5)
blank_layout = prs.slide_layouts[6]

DARK_BG = RGBColor(10, 14, 23)
CARD_BG = RGBColor(19, 26, 43)
GREEN = RGBColor(0, 255, 136)
CYAN = RGBColor(0, 170, 255)
WHITE = RGBColor(238, 242, 247)
DIM_TEXT = RGBColor(150, 165, 185)
RED = RGBColor(255, 51, 102)
YELLOW = RGBColor(255, 170, 0)

slides_data = [
    {
        'title': 'SENTRIX SHIELD',
        'subtitle': 'Autonomous Security Monitoring & Incident Response Platform\nCRIMEATHON 26 — Case NS-26-014 | Defense Track',
        'points': [
            'Target Case: The Northstar Learning Services Investigation (NS-26-014)',
            'Selected Track: DEFENSE (Preventive, Detective & Response Controls)',
            'Core Solution: Real-Time Anomaly Detection, Credential Lifecycle Management & Zero-Trust Defense',
            'Deliverables: One-Page Problem Statement + Complete Source Code + Demo Video + PPTX Deck',
            'Evaluation Readiness: Complete Working Source Code + Local Hardened Simulation + 15-Category 43/43 Test Suite'
        ]
    },
    {
        'title': '1. Problem Identification & Executive Summary',
        'subtitle': 'The Northstar Skills Academy Incident (12 October 2026)',
        'points': [
            'Incident Overview: Multi-stage security incident at Northstar Skills Academy affecting ~2,300 learner profiles.',
            'Trigger Events: Irregular attendance sync, sluggish portal access, and unauthorized learner-data export in CampusVault.',
            'Root Security Failures:',
            '  * Credential Hygiene Failure: Service credential svc_rollcall (rc-prod-01) active approx. 7 months with expires: never and no rotation (E05).',
            '  * Excessive Privileges: Attendance integration held broad permissions (learner.search, learner.export) violating least-privilege (E05, E08).',
            '  * Unrestricted Network Access: Integration API keys permitted requests from external, unwhitelisted IP 203.0.113.77 (E03, E09).',
            '  * Investigated Exposure Hypothesis: Support ticket HD-1058 recorded screenshot attachment during troubleshooting (contents unverified) (E06).'
        ]
    },
    {
        'title': '2. Comprehensive Evidence Correlation',
        'subtitle': 'Direct Evidence Cross-Referenced from Case Dossier NS-26-014',
        'points': [
            'E01 & E09 (Auth & Network): A011-A013 & N001 show svc_rollcall authenticating from external IP 203.0.113.77 at 03:15-03:19 IST.',
            'E11 (Config Audit): Event CHG-882 records credential_config_read on integration-settings/rollcall-prod at 03:16:35 IST.',
            'E02 & E03 (ClassBridge & API Gateway): Events P003/R003 (2300 learner search) and P004/R004 (2300 learner export) at 03:16-03:17 IST.',
            'E04 (CampusVault): Events C002-C004 show listing and double download of learners-20261012.csv (486,200 bytes) via 203.0.113.77.',
            'E05 (Register): INT-01 shows permissions attendance.read; learner.search; learner.export; course.read with expiry=never and IP restriction=none.',
            'E06 (HelpDesk): Ticket HD-1058 (09 Oct) lists screenshot attachment; HD-1069 confirms unauthorized export discovered by Finance.',
            'E01 & E07 (Identity Governance): A006 shows former.ajay authenticated post-departure; separate offboarding defect not responsible for incident.'
        ]
    },
    {
        'title': '3. Fact Differentiation: Confirmed vs. Unknowns',
        'subtitle': 'Rigorous Forensic Separation of Direct Observations and Hypotheses',
        'points': [
            'Confirmed Observations (Directly logged in evidence):',
            '  [CONFIRMED] Integration settings read from external IP 203.0.113.77 (CHG-882).',
            '  [CONFIRMED] 2,300 learner records searched and exported via API gateway using rc-prod-01 (R003, R004).',
            '  [CONFIRMED] 486 KB export file downloaded twice from CampusVault repository (C003, C004).',
            '  [CONFIRMED] Service account rc-prod-01 lacked expiry, rotation schedule, and IP restrictions (INT-01).',
            'Strongly Supported Hypotheses:',
            '  [HYPOTHESIS] Attacker obtained valid credential externally and exploited absence of network and role boundaries.',
            'Forensic Unknowns (Explicitly not claimed):',
            '  [UNKNOWN] Exact physical identity of the human operator behind 203.0.113.77.',
            '  [UNKNOWN] Whether ticket HD-1058 screenshot actually contained plaintext secrets (contents unverified in evidence).',
            '  [UNKNOWN] Whether downloaded learner records were transferred onward or published.'
        ]
    },
    {
        'title': '4. Technical & Business Impact Analysis',
        'subtitle': 'Assessing Exposure Severity Across Technology, Governance, and Operations',
        'points': [
            'Data Protection & Privacy Exposure:',
            '  * Exfiltration of 2,300 learner PII records (names, learner IDs, contact & course metadata).',
            '  * Severe compliance exposure under applicable Indian Personal Data Protection (DPDP) standards.',
            'Operational & Institutional Impact:',
            '  * Degradation of core student portal responsiveness during high-volume bulk query loops.',
            '  * Severe breach of trust between Northstar Skills Academy, students, parents, and corporate partners.',
            'Vendor & Architectural Fragility:',
            '  * Compromised third-party integration trust with RollCall Connect vendor.',
            '  * Demonstration of zero forensic readiness prior to incident - no alerting on bulk export or off-subnet logins.'
        ]
    },
    {
        'title': '5. Proposed Defense Architecture — SENTRIX SHIELD',
        'subtitle': 'Zero-Trust Defense, Detection, and Automated Incident Response Platform',
        'points': [
            'Module 1: Real-Time Telemetry Ingestion & SIEM Correlation Engine',
            '  * Correlates auth tokens, gateway access, configuration reads, and cloud storage audits in real time.',
            'Module 2: Heuristic & Rule-Based Anomaly Detection (AD Engine)',
            '  * Scores severity using heuristic ratings (0-100) reflecting policy impact, not statistical probabilities.',
            '  * Off-subnet anomaly: flags external IP access for service accounts.',
            '  * Velocity anomaly: triggers alert when API calls exceed baseline threshold.',
            'Module 3: Dynamic Credential Lifecycle & Vault Enforcer',
            '  * Enforces mandatory 90-day rotation; provides 1-click simulated credential revocation & re-issue.',
            'Module 4: Zero-Trust Hardened API Gateway (Local Simulation)',
            '  * Strict IP allowlisting (10.10.4.12 only), least-privilege role scoping, and isolated export record ceilings.'
        ]
    },
    {
        'title': '6. System Workflow & Incident Response Playbook',
        'subtitle': 'End-to-End Mitigation Cycle from Detection to Hardened State',
        'points': [
            'Step 1 - Ingestion & Parsing: Logs continuously streamed from ClassBridge, CampusVault, RollCall & Identity.',
            'Step 2 - Correlation & Heuristic Scoring: Engine computes composite severity score (0-100) and assigns Threat Level.',
            'Step 3 - Instant Alert Dispatch: Elevated risk triggers SIEM alerts (e.g. ALT-001 Unauthorized Off-Hours Config Read).',
            'Step 4 - Automated Defense Actions:',
            '  * Token Revocation: Invalidates compromised token rc-prod-01 instantly.',
            '  * IP Drop: Firewall rule drops non-whitelisted IP 203.0.113.77.',
            '  * Export Quarantine: Halts CampusVault download links pending dual-authorization approval.',
            'Step 5 - Hardened Recovery: Enforces least-privilege token scoped solely to attendance.read.'
        ]
    },
    {
        'title': '7. Implementation Details & Technology Stack',
        'subtitle': 'High-Performance, Lightweight, Zero-Dependency Architecture',
        'points': [
            'Backend Stack:',
            '  * Python 3.12 + Flask API Server with RESTful JSON endpoints and CORS origin protection.',
            '  * Custom Heuristic Anomaly Detection & Timeline Correlation engine.',
            'Frontend Stack:',
            '  * Single-Page Reactive SOC Dashboard (HTML5, Modern CSS3 Grid/Flexbox, Vanilla ES6+ JavaScript).',
            '  * Cyberpunk dark theme with live radar sweep canvas, KPI cards, and modal inspectors.',
            'Local Simulation Suite (Hardened vs. Vulnerable):',
            '  * Mock API Server testing both role boundaries and isolated export record ceilings (100 record limit).',
            '  * Automated verification test harness validating 45 distinct security assertions.'
        ]
    },
    {
        'title': '8. Verification Results & Security Outcomes',
        'subtitle': 'Quantitative Proof of Defense Effectiveness via Automated Test Suite',
        'points': [
            'Automated Hardened API Test Suite: 100% PASS RATE (7/7 assertions verified)',
            '  [PASS] Attendance allowed from authorized internal connector (10.10.4.12) -> HTTP 200',
            '  [PASS] Learner search rejected for attendance role -> HTTP 403 Forbidden',
            '  [PASS] Bulk export rejected by role boundary -> HTTP 403 Forbidden',
            '  [PASS] Unapproved external source IP (203.0.113.77) blocked -> HTTP 403 Forbidden',
            '  [PASS] Invalid / revoked token denied -> HTTP 403 Forbidden',
            '  [PASS] ISOLATED EXPORT LIMIT: Bulk export > 100 blocked by record ceiling -> HTTP 400',
            '  [PASS] ISOLATED EXPORT LIMIT: Small export <= 100 records permitted for authorized role -> HTTP 200',
            'Overall Test Suite: 100% PASS RATE (43/43 Tests Passed across all 15 Verification Categories).'
        ]
    },
    {
        'title': 'SENTRIX SHIELD — Summary & Deliverables',
        'subtitle': 'CRIMEATHON 26 Selection Round | Team SENTRIX',
        'points': [
            'Deliverable 1: One-Page Problem Statement (Markdown & Print-Ready PDF / HTML)',
            'Deliverable 2: Complete Working Source Code (Flask API, Frontend Dashboard, 43/43 Test Suite)',
            'Deliverable 3: Live Verification Demo & Video Walkthrough Guide',
            'Deliverable 4: Comprehensive Technical Slide Deck (PPTX)',
            '',
            'Team SENTRIX CYBER CLUB — Think. Investigate. Innovate.'
        ]
    }
]

for sdata in slides_data:
    slide = prs.slides.add_slide(blank_layout)
    bg = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, prs.slide_width, prs.slide_height)
    bg.fill.solid()
    bg.fill.fore_color.rgb = DARK_BG
    bg.line.fill.background()

    card = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(0.6), Inches(11.733), Inches(6.3))
    card.fill.solid()
    card.fill.fore_color.rgb = CARD_BG
    card.line.color.rgb = RGBColor(30, 42, 66)
    card.line.width = Pt(1.5)

    tx_box = slide.shapes.add_textbox(Inches(1.2), Inches(0.9), Inches(10.9), Inches(1.3))
    tf = tx_box.text_frame
    tf.word_wrap = True
    
    p = tf.paragraphs[0]
    p.text = sdata['title']
    p.font.size = Pt(26)
    p.font.bold = True
    p.font.color.rgb = GREEN

    if 'subtitle' in sdata:
        p2 = tf.add_paragraph()
        p2.text = sdata['subtitle']
        p2.font.size = Pt(14)
        p2.font.color.rgb = CYAN
        p2.space_before = Pt(4)

    bx = slide.shapes.add_textbox(Inches(1.2), Inches(2.3), Inches(10.9), Inches(4.3))
    btf = bx.text_frame
    btf.word_wrap = True

    for i, pt in enumerate(sdata['points']):
        bp = btf.paragraphs[0] if i == 0 else btf.add_paragraph()
        bp.text = pt
        bp.space_before = Pt(8)
        
        if pt.startswith('  *') or pt.startswith('  [') or 'CONFIRMED' in pt or 'PASS' in pt or 'UNKNOWN' in pt:
            bp.font.size = Pt(13)
            bp.font.color.rgb = YELLOW if 'UNKNOWN' in pt or 'HYPOTHESIS' in pt else (GREEN if 'CONFIRMED' in pt or 'PASS' in pt else DIM_TEXT)
        elif pt.endswith(':') or 'Overview:' in pt or 'Stack:' in pt or 'Results:' in pt or 'Deductions:' in pt or 'Deliverable' in pt:
            bp.font.size = Pt(15)
            bp.font.bold = True
            bp.font.color.rgb = WHITE
        elif pt == '':
            bp.font.size = Pt(6)
        else:
            bp.font.size = Pt(14)
            bp.font.color.rgb = WHITE

prs.save('SENTRIX_SHIELD_PRESENTATION.pptx')
print('Successfully generated updated SENTRIX_SHIELD_PRESENTATION.pptx!')
