import os
import pptx
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.enum.shapes import MSO_SHAPE

def create_deck():
    prs = Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)
    blank_layout = prs.slide_layouts[6]

    # Theme Palette
    C_BG = RGBColor(10, 14, 23)          # Dark space background
    C_CARD = RGBColor(17, 24, 39)        # Card container background
    C_CARD_ALT = RGBColor(24, 33, 54)    # Alternate card background
    C_BORDER = RGBColor(31, 41, 55)      # Border
    C_GREEN = RGBColor(16, 185, 129)     # Emerald Green (#10b981)
    C_CYAN = RGBColor(6, 182, 212)       # Neon Cyan (#06b6d4)
    C_AMBER = RGBColor(245, 158, 11)     # Amber (#f59e0b)
    C_RED = RGBColor(239, 68, 68)        # Red (#ef4444)
    C_WHITE = RGBColor(249, 250, 251)    # Crisp White
    C_MUTED = RGBColor(156, 163, 175)    # Gray (#9ca3af)
    C_DARK_TEXT = RGBColor(17, 24, 39)

    def add_base_slide():
        slide = prs.slides.add_slide(blank_layout)
        # Background
        bg = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, prs.slide_width, prs.slide_height)
        bg.fill.solid()
        bg.fill.fore_color.rgb = C_BG
        bg.line.fill.background()
        return slide

    def add_header(slide, title_text, category_text, subtitle_text):
        # Category / Track Pill
        cat_box = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(0.4), Inches(3.2), Inches(0.36))
        cat_box.fill.solid()
        cat_box.fill.fore_color.rgb = RGBColor(16, 185, 129)
        cat_box.line.fill.background()
        tf_cat = cat_box.text_frame
        tf_cat.word_wrap = False
        p_cat = tf_cat.paragraphs[0]
        p_cat.text = f"  {category_text}  "
        p_cat.font.size = Pt(11)
        p_cat.font.bold = True
        p_cat.font.color.rgb = C_DARK_TEXT
        p_cat.alignment = PP_ALIGN.CENTER

        # Title
        tbox = slide.shapes.add_textbox(Inches(0.8), Inches(0.78), Inches(11.733), Inches(0.65))
        tf = tbox.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = title_text
        p.font.size = Pt(22)
        p.font.bold = True
        p.font.color.rgb = C_WHITE

        # Subtitle
        p2 = tf.add_paragraph()
        p2.text = subtitle_text
        p2.font.size = Pt(12)
        p2.font.color.rgb = C_CYAN
        p2.space_before = Pt(3)

    # =========================================================================
    # SLIDE 1: Title / Hero Slide
    # =========================================================================
    s1 = add_base_slide()
    # Central Hero Card
    hero = s1.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(0.8), Inches(11.733), Inches(5.9))
    hero.fill.solid()
    hero.fill.fore_color.rgb = C_CARD
    hero.line.color.rgb = C_GREEN
    hero.line.width = Pt(2)

    # Top Pill
    pill = s1.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(1.3), Inches(1.3), Inches(5.8), Inches(0.45))
    pill.fill.solid()
    pill.fill.fore_color.rgb = RGBColor(6, 182, 212)
    pill.line.fill.background()
    p_pill = pill.text_frame.paragraphs[0]
    p_pill.text = " CRIMEATHON'26 SELECTION ROUND | DEFENSE TRACK "
    p_pill.font.size = Pt(12)
    p_pill.font.bold = True
    p_pill.font.color.rgb = C_DARK_TEXT
    p_pill.alignment = PP_ALIGN.CENTER

    # Main Title Box
    tbox1 = s1.shapes.add_textbox(Inches(1.3), Inches(1.9), Inches(10.7), Inches(2.2))
    tf1 = tbox1.text_frame
    tf1.word_wrap = True
    
    p = tf1.paragraphs[0]
    p.text = "SENTRIX SHIELD"
    p.font.size = Pt(44)
    p.font.bold = True
    p.font.color.rgb = C_GREEN

    p_sub = tf1.add_paragraph()
    p_sub.text = "Autonomous Security Monitoring, Threat Correlation & Zero-Trust Defense Platform"
    p_sub.font.size = Pt(16)
    p_sub.font.color.rgb = C_WHITE
    p_sub.space_before = Pt(6)

    p_case = tf1.add_paragraph()
    p_case.text = "Incident Investigation Case NS-26-014: Northstar Learning Services Investigation"
    p_case.font.size = Pt(13)
    p_case.font.color.rgb = C_CYAN
    p_case.space_before = Pt(4)

    # 3 Metadata Badges Across Bottom of Hero
    meta_data = [
        ("👥 Team Identity", "Team SENTRIX\nSIMATS Cyber Club", C_CYAN),
        ("🧪 Test Verification", "63/63 Passing (100% Rate)\n20 Security Categories", C_GREEN),
        ("📦 Deliverables", "Problem Statement + Code\nDemo Guide + Presentation", C_AMBER),
    ]
    for i, (m_title, m_desc, m_col) in enumerate(meta_data):
        m_card = s1.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(1.3 + i * 3.6), Inches(4.3), Inches(3.4), Inches(1.8))
        m_card.fill.solid()
        m_card.fill.fore_color.rgb = C_CARD_ALT
        m_card.line.color.rgb = m_col
        m_card.line.width = Pt(1.5)

        mtf = m_card.text_frame
        mtf.word_wrap = True
        mp1 = mtf.paragraphs[0]
        mp1.text = m_title
        mp1.font.size = Pt(13)
        mp1.font.bold = True
        mp1.font.color.rgb = m_col

        mp2 = mtf.add_paragraph()
        mp2.text = m_desc
        mp2.font.size = Pt(12)
        mp2.font.color.rgb = C_WHITE
        mp2.space_before = Pt(8)

    # =========================================================================
    # SLIDE 2: Incident Summary & KPI Cards
    # =========================================================================
    s2 = add_base_slide()
    add_header(s2, "1. Executive Summary & Incident Metrics", "INCIDENT PROFILE", "Forensic analysis of the 12 October 2026 data breach at Northstar Skills Academy")

    # 4 KPI Cards
    kpis = [
        ("2,300", "RECORDS LOGGED", "Learner PII profiles dumped via API & storage", C_RED),
        ("~7 Months", "KEY ACTIVE LIFETIME", "Created 04-Mar-2026 with expires: never", C_AMBER),
        ("486 KB", "EXFILTRATED PAYLOAD", "learners-20261012.csv downloaded twice", C_CYAN),
        ("0 Allowed IPs", "NETWORK INGRESS GAP", "Gateway permitted requests from 203.0.113.77", C_GREEN)
    ]
    for i, (val, title, desc, col) in enumerate(kpis):
        kcard = s2.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8 + i * 2.98), Inches(1.6), Inches(2.8), Inches(1.6))
        kcard.fill.solid()
        kcard.fill.fore_color.rgb = C_CARD
        kcard.line.color.rgb = col
        kcard.line.width = Pt(1.5)
        ktf = kcard.text_frame
        ktf.word_wrap = True
        kp1 = ktf.paragraphs[0]
        kp1.text = val
        kp1.font.size = Pt(26)
        kp1.font.bold = True
        kp1.font.color.rgb = col
        kp2 = ktf.add_paragraph()
        kp2.text = title
        kp2.font.size = Pt(10)
        kp2.font.bold = True
        kp2.font.color.rgb = C_WHITE
        kp3 = ktf.add_paragraph()
        kp3.text = desc
        kp3.font.size = Pt(9)
        kp3.font.color.rgb = C_MUTED
        kp3.space_before = Pt(2)

    # 2 Detail Cards Below
    c_left = s2.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(3.4), Inches(5.75), Inches(3.5))
    c_left.fill.solid()
    c_left.fill.fore_color.rgb = C_CARD
    c_left.line.color.rgb = C_BORDER
    ltf = c_left.text_frame
    ltf.word_wrap = True
    lp = ltf.paragraphs[0]
    lp.text = "🚨 Observed Breach Timeline (Direct Evidence)"
    lp.font.size = Pt(14)
    lp.font.bold = True
    lp.font.color.rgb = C_AMBER

    points_left = [
        "03:15 IST — Initial external ingress from 203.0.113.77 using svc_rollcall (A011, N001).",
        "03:16 IST — Configuration read (CHG-882) on integration-settings/rollcall-prod.",
        "03:16–03:17 IST — Mass query (P003/R003) & export job created (P004/R004/CHG-883).",
        "03:20–03:24 IST — 486 KB archive downloaded twice from CampusVault (C003, C004).",
        "10:45 IST — Incident discovered hours later by Finance reporting slow portal (HD-1069)."
    ]
    for pt in points_left:
        p_pt = ltf.add_paragraph()
        p_pt.text = "• " + pt
        p_pt.font.size = Pt(10)
        p_pt.font.color.rgb = C_WHITE
        p_pt.space_before = Pt(8)

    c_right = s2.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(6.78), Inches(3.4), Inches(5.75), Inches(3.5))
    c_right.fill.solid()
    c_right.fill.fore_color.rgb = C_CARD
    c_right.line.color.rgb = C_BORDER
    rtf = c_right.text_frame
    rtf.word_wrap = True
    rp = rtf.paragraphs[0]
    rp.text = "⚙️ Confirmed Vulnerabilities (Root Causes)"
    rp.font.size = Pt(14)
    rp.font.bold = True
    rp.font.color.rgb = C_RED

    points_right = [
        "Unexpiring Credential: INT-01 active ~7 months (created 04-Mar-2026) with expires: never and no rotation schedule (E05, E12).",
        "Excessive Privileges: Connector held learner.export & learner.search when only attendance.read was required (NS-SEC-04 Rule 2).",
        "Zero Ingress Boundaries: Gateway lacked source IP allowlist, accepting connections from external IP 203.0.113.77 (E03, E09).",
        "No Telemetry or Velocity Limits: Absent SIEM alerts or record-export approval workflows enabled unmonitored mass dumping.",
        "Unverified Hypothesis: Ticket HD-1058 listed screenshot attachment; actual image contents and exposure path remain unverified (E06)."
    ]
    for pt in points_right:
        p_pt = rtf.add_paragraph()
        p_pt.text = "• " + pt
        p_pt.font.size = Pt(10)
        p_pt.font.color.rgb = C_WHITE
        p_pt.space_before = Pt(8)

    # =========================================================================
    # SLIDE 3: Evidence Dossier Correlation Matrix (E01–E12)
    # =========================================================================
    s3 = add_base_slide()
    add_header(s3, "2. Comprehensive Evidence Correlation", "GROUND TRUTH", "Synthesizing authentic findings across all 12 case dossier files (E01–E12)")

    # Table of evidence
    rows = 7
    cols = 4
    left = Inches(0.8)
    top = Inches(1.6)
    width = Inches(11.733)
    height = Inches(5.3)

    table_shape = s3.shapes.add_table(rows, cols, left, top, width, height)
    table = table_shape.table
    table.columns[0].width = Inches(1.5)
    table.columns[1].width = Inches(2.2)
    table.columns[2].width = Inches(2.6)
    table.columns[3].width = Inches(5.433)

    headers = ["Evidence ID", "Log Source / System", "Correlated Events", "Key Forensic Determination"]
    for j, h in enumerate(headers):
        cell = table.cell(0, j)
        cell.fill.solid()
        cell.fill.fore_color.rgb = C_CARD_ALT
        p = cell.text_frame.paragraphs[0]
        p.text = h
        p.font.size = Pt(11)
        p.font.bold = True
        p.font.color.rgb = C_CYAN

    data_rows = [
        ("E01 / E09", "Auth & Network Logs", "A011–A013, N001, N002", "External authentication using svc_rollcall token from unapproved IP 203.0.113.77; former staff A006 authenticated post-departure (separate offboarding defect)."),
        ("E11", "Configuration Audit", "CHG-882, CHG-883", "Read of integration-settings/rollcall-prod at 03:16:35 IST immediately prior to API queries; export job job-883 created at 03:17:30 IST."),
        ("E02 / E03", "ClassBridge & API Gateway", "P003–P006, R003–R006", "Client rollcall-prod executed bulk search & export on 2,300 learner profiles; gateway returned HTTP 200 due to excessive role scopes."),
        ("E04", "CampusVault Storage", "C002, C003, C004", "Object learners-20261012.csv (486,200 bytes) listed and downloaded twice to external IP 203.0.113.77 with no dual authorization."),
        ("E05", "Integration Register", "INT-01 (RollCall)", "Active ~7 months (created 04-Mar-2026); expires: never; ip_restriction: not configured; assigned learner.export instead of attendance.read."),
        ("E06 / E10", "HelpDesk & Vendor Comms", "HD-1058, HD-1069, VND-221", "Ticket HD-1058 listed config screenshot (contents unverified); vendor confirmed no export planned and node 10.10.4.12 was idle.")
    ]

    for i, row in enumerate(data_rows, start=1):
        for j, val in enumerate(row):
            cell = table.cell(i, j)
            cell.fill.solid()
            cell.fill.fore_color.rgb = C_CARD if i % 2 == 1 else RGBColor(14, 20, 33)
            p = cell.text_frame.paragraphs[0]
            p.text = val
            p.font.size = Pt(10)
            if j == 0:
                p.font.bold = True
                p.font.color.rgb = C_GREEN
            elif j == 2:
                p.font.bold = True
                p.font.color.rgb = C_AMBER
            else:
                p.font.color.rgb = C_WHITE

    # =========================================================================
    # SLIDE 4: Forensic Truth Categorization
    # =========================================================================
    s4 = add_base_slide()
    add_header(s4, "3. Fact Differentiation: Confirmed vs. Hypotheses vs. Unknowns", "FORENSIC RIGOR", "Rigorous boundary between direct observations and unverified assumptions")

    cats = [
        ("CONFIRMED OBSERVATIONS", "Direct Log Evidence (E01–E12)", C_GREEN, [
            "External Auth: Key rc-prod-01 authenticated from 203.0.113.77 (A011).",
            "Config Access: Settings resource read at 03:16:35 IST (CHG-882).",
            "Bulk Exfiltration: 2,300 learner records searched & exported (P003, P004, R003, R004).",
            "Repository Download: 486 KB CSV downloaded twice to external IP (C003, C004).",
            "Lifecycle Gaps: INT-01 created 04-Mar-2026, expires: never, zero IP allowlist (E05)."
        ]),
        ("SUPPORTED HYPOTHESES", "High-Confidence Deductions", C_CYAN, [
            "External Credential Acquisition: External entity obtained valid static API secret.",
            "Opportunistic Exploitation: Attacker exploited missing perimeter allowlist and over-permissioned scopes.",
            "Offboarding Isolation: Former technician login (A006) was a distinct identity defect; no evidence links it to the external exfiltration.",
            "Vendor Node Inactivity: Vendor node 10.10.4.12 was verified idle (E10)."
        ]),
        ("FORENSIC UNKNOWNS", "Strictly Not Claimed", C_AMBER, [
            "Human Identity: Physical person behind IP 203.0.113.77 remains unproven.",
            "Screenshot Secret Contents: HD-1058 listed screenshot attachment, but whether secrets were visible is unverified in evidence.",
            "Data Distribution: Whether the downloaded CSV was published or transferred onward is unrecorded in logs.",
            "Unique Individuals: 2,300 is logged records; unique victim count unproven."
        ])
    ]

    for i, (head, subh, col, items) in enumerate(cats):
        card = s4.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8 + i * 3.98), Inches(1.6), Inches(3.75), Inches(5.3))
        card.fill.solid()
        card.fill.fore_color.rgb = C_CARD
        card.line.color.rgb = col
        card.line.width = Pt(1.5)

        ctf = card.text_frame
        ctf.word_wrap = True
        cp1 = ctf.paragraphs[0]
        cp1.text = head
        cp1.font.size = Pt(13)
        cp1.font.bold = True
        cp1.font.color.rgb = col

        cp2 = ctf.add_paragraph()
        cp2.text = subh
        cp2.font.size = Pt(10)
        cp2.font.color.rgb = C_MUTED
        cp2.space_before = Pt(2)

        for item in items:
            p_item = ctf.add_paragraph()
            p_item.text = "• " + item
            p_item.font.size = Pt(9.5)
            p_item.font.color.rgb = C_WHITE
            p_item.space_before = Pt(10)

    # =========================================================================
    # SLIDE 5: Four Defense Pillars of SENTRIX SHIELD
    # =========================================================================
    s5 = add_base_slide()
    add_header(s5, "4. The Four Pillars of SENTRIX SHIELD", "DEFENSE ARCHITECTURE", "End-to-end zero-trust detection, prevention, and incident response architecture")

    pillars = [
        ("1. Real-Time SIEM", "Detection & Telemetry", C_CYAN, [
            "Multi-Log Ingestion: Normalizes auth, API gateway, config audits & cloud storage.",
            "Heuristic Severity (0-100): Measures policy impact, not statistical probabilities.",
            "Sub-Second Alerts: Flags off-subnet logins, rate velocity spikes, and bulk downloads."
        ]),
        ("2. Zero-Trust Gateway", "Access & Scoping", C_GREEN, [
            "Source IP Allowlisting: Strict Python ipaddress containment (10.10.4.12 only).",
            "Least-Privilege Scoping: Restricts connector strictly to attendance.read (403 on export).",
            "Record Ceilings: Isolated export limit enforces HTTP 400 rejection on > 100 records."
        ]),
        ("3. Vault Lifecycle", "Credential Governance", C_AMBER, [
            "90-Day Auto Rotation: Eliminates static unexpiring credentials.",
            "Short-Lived JIT Tokens: Replaces unexpiring keys with time-bounded tokens.",
            "Simulated Rotation Workflow: Automated SOP demonstration without false claims."
        ]),
        ("4. Cyber Command SOC", "Operations & Response", C_RED, [
            "Interactive Dashboard: Live radar sweep, event stream & threat gauges.",
            "Universal API Security: Bearer token auth + RBAC on all /api routes.",
            "Compliance Test Lab: In-browser execution of 63-point automated security suite."
        ])
    ]

    for i, (p_title, p_sub, col, p_items) in enumerate(pillars):
        card = s5.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8 + i * 2.98), Inches(1.6), Inches(2.8), Inches(5.3))
        card.fill.solid()
        card.fill.fore_color.rgb = C_CARD
        card.line.color.rgb = col
        card.line.width = Pt(1.5)

        ctf = card.text_frame
        ctf.word_wrap = True
        cp1 = ctf.paragraphs[0]
        cp1.text = p_title
        cp1.font.size = Pt(14)
        cp1.font.bold = True
        cp1.font.color.rgb = col

        cp2 = ctf.add_paragraph()
        cp2.text = p_sub
        cp2.font.size = Pt(10)
        cp2.font.color.rgb = C_MUTED
        cp2.space_before = Pt(2)

        for item in p_items:
            p_item = ctf.add_paragraph()
            p_item.text = "• " + item
            p_item.font.size = Pt(9.5)
            p_item.font.color.rgb = C_WHITE
            p_item.space_before = Pt(12)

    # =========================================================================
    # SLIDE 6: MITRE ATT&CK Kill-Chain & Defense Interception
    # =========================================================================
    s6 = add_base_slide()
    add_header(s6, "5. Attack Kill-Chain & Defense Interception Points", "TACTICAL DEFENSE", "Mapping observed attacker actions to automated preventive and detective controls")

    stages = [
        ("STAGE 1: INGRESS", "Initial Access (T1078)", "Auth from external IP 203.0.113.77 via static key rc-prod-01 (A011).", "🛡️ INTERCEPTION 1: Zero-Trust Perimeter drops off-subnet IP with RULE-FW-DROP-EXTERNAL.", C_RED),
        ("STAGE 2: CONFIG READ", "Discovery (T1087)", "Off-hours read of integration settings at 03:16:35 IST (CHG-882).", "🛡️ INTERCEPTION 2: Vault encryption & JIT token; triggers SIEM alert ALT-CFG-04.", C_AMBER),
        ("STAGE 3: MASS QUERY", "Collection (T1114)", "Mass learner query returning all 2,300 profiles (P003, R003).", "🛡️ INTERCEPTION 3: API Gateway velocity rate-limiting (20 req/min threshold).", C_CYAN),
        ("STAGE 4: EXPORT TRIGGER", "Exfiltration (T1567)", "POST /v1/learners/export triggers 486 KB archive creation (P004, R004).", "🛡️ INTERCEPTION 4: Least-privilege boundary returns 403 Forbidden; export ceiling 400 Bad Request.", C_GREEN),
        ("STAGE 5: CLOUD EXTRACTION", "Exfiltration (T1537)", "Two downloads of learners-20261012.csv from CampusVault (C003, C004).", "🛡️ INTERCEPTION 5: Dual-custody authorization + storage link expiration stops unauthorized pull.", C_GREEN)
    ]

    for i, (title, mitre, obs, inter, col) in enumerate(stages):
        top_pos = Inches(1.6 + i * 1.05)
        # Stage Box
        sbox = s6.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), top_pos, Inches(11.733), Inches(0.95))
        sbox.fill.solid()
        sbox.fill.fore_color.rgb = C_CARD
        sbox.line.color.rgb = col
        sbox.line.width = Pt(1.5)

        stf = sbox.text_frame
        stf.word_wrap = True
        sp1 = stf.paragraphs[0]
        sp1.text = f"{title} | MITRE: {mitre}"
        sp1.font.size = Pt(11)
        sp1.font.bold = True
        sp1.font.color.rgb = col

        sp2 = stf.add_paragraph()
        sp2.text = f"Observed: {obs}  -->  {inter}"
        sp2.font.size = Pt(9.5)
        sp2.font.color.rgb = C_WHITE
        sp2.space_before = Pt(3)

    # =========================================================================
    # SLIDE 7: Technical Implementation & Backend Security
    # =========================================================================
    s7 = add_base_slide()
    add_header(s7, "6. Technical Implementation & Backend Security", "FULL-STACK ARCHITECTURE", "Hardened REST API, strict typing, token middleware, and interactive SOC dashboard")

    tech_cards = [
        ("Flask API & Security Middleware", "Backend Hardening", C_GREEN, [
            "Universal Bearer Token Middleware (@require_auth): All /api endpoints require cryptographic Bearer tokens; returns HTTP 401 on missing/invalid token.",
            "Role-Based Access Control (@require_role): Segregates admin vs analyst roles; unauthorized actions return HTTP 403 Forbidden.",
            "Explicit CORS Configuration: Strictly bounded to trusted local origins (127.0.0.1:5000, localhost:5000) with zero wildcards (*).",
            "Python ipaddress Network Validation: Strict IPv4/IPv6 syntax checks and subnet containment; returns HTTP 400 on malformed IP inputs."
        ]),
        ("Forensics & Anomaly Engine", "Analytics Engine", C_CYAN, [
            "Dynamic SHA-256 Ingestion (loader.py): Automatically computes cryptographic hashes and validates integrity across all 12 evidence files.",
            "Chronological Event Correlator (timeline.py): Synthesizes multi-source telemetry in ascending IST timestamps (+05:30).",
            "Heuristic Severity Scorer (anomaly.py): 8 specialized rules scoring policy impact (0-100) and mapping confidence classifications."
        ]),
        ("Single-Page SOC Dashboard", "Frontend Architecture", C_AMBER, [
            "Modern Cyberpunk Interface: HTML5 Canvas threat radar sweep, responsive CSS Grid, audio feedback synthesizer.",
            "Automatic Token Injection: Client-side fetch interceptor attaches Bearer token header to all outbound API calls seamlessly.",
            "Downloadable Forensic Reports: Generates authenticated structured JSON case dossier and comprehensive multi-table CSV report."
        ])
    ]

    for i, (head, sub, col, items) in enumerate(tech_cards):
        card = s7.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8 + i * 3.98), Inches(1.6), Inches(3.75), Inches(5.3))
        card.fill.solid()
        card.fill.fore_color.rgb = C_CARD
        card.line.color.rgb = col
        card.line.width = Pt(1.5)

        ctf = card.text_frame
        ctf.word_wrap = True
        cp1 = ctf.paragraphs[0]
        cp1.text = head
        cp1.font.size = Pt(13)
        cp1.font.bold = True
        cp1.font.color.rgb = col

        cp2 = ctf.add_paragraph()
        cp2.text = sub
        cp2.font.size = Pt(10)
        cp2.font.color.rgb = C_MUTED
        cp2.space_before = Pt(2)

        for item in items:
            p_item = ctf.add_paragraph()
            p_item.text = "• " + item
            p_item.font.size = Pt(9.5)
            p_item.font.color.rgb = C_WHITE
            p_item.space_before = Pt(12)

    # =========================================================================
    # SLIDE 8: Quantitative Verification & Test Results
    # =========================================================================
    s8 = add_base_slide()
    add_header(s8, "7. Automated Security Verification Results", "TEST HARNESS", "Empirical proof of defense efficacy via comprehensive automated test runner (run_tests.py)")

    # Banner
    banner = s8.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(1.5), Inches(11.733), Inches(0.8))
    banner.fill.solid()
    banner.fill.fore_color.rgb = C_CARD_ALT
    banner.line.color.rgb = C_GREEN
    banner.line.width = Pt(2)
    btf = banner.text_frame
    bp = btf.paragraphs[0]
    bp.text = "🎯 63 / 63 TESTS PASSED (100.0% SUCCESS RATE) ACROSS 20 SECURITY CATEGORIES"
    bp.font.size = Pt(15)
    bp.font.bold = True
    bp.font.color.rgb = C_GREEN
    bp.alignment = PP_ALIGN.CENTER

    test_groups = [
        ("Evidence Integrity (Cat 1–3, 11)", "Dossier Verification", C_CYAN, [
            "All 12 files verified present, non-empty, and SHA-256 validated.",
            "Case event IDs preserved (A011, R004, C003; zero invented EVT-).",
            "Chronological ordering verified across 11 phases in IST (+05:30)."
        ]),
        ("Detection & Telemetry (Cat 4–10)", "SIEM Correlation", C_AMBER, [
            "Authentic external IP 203.0.113.77 flagged with 95/100 severity.",
            "Detects 2,300 record bulk query (R003) and export (R004).",
            "Flags double CampusVault download (C003, C004) with 100/100 severity.",
            "Identifies ~7 mos credential age and disclaims Ajay Prakash attribution."
        ]),
        ("Gateway & Record Limits (Cat 12–15)", "Hardened Gateway", C_GREEN, [
            "Vulnerable API allows external IP (200 OK); Hardened API drops it (403).",
            "Isolated Export Limit: > 100 records rejected (400 Bad Request).",
            "Isolated Export Limit: <= 100 records approved and dispatched (200 OK).",
            "Perimeter filter drops untrusted IP; least-privilege boundary denies export."
        ]),
        ("Authentication & RBAC (Cat 16–20)", "Backend Security", C_RED, [
            "Negative Test: Missing token to dashboard/logs/audit rejected (HTTP 401).",
            "Negative Test: Invalid token rejected (HTTP 401); unauth rotation rejected.",
            "RBAC Negative Test: Analyst role denied admin rotation route (HTTP 403).",
            "Strict Typing: Malformed IP string rejected by ipaddress (HTTP 400).",
            "CORS: Returns trusted origin for localhost without wildcard (*)."
        ])
    ]

    for i, (g_title, g_sub, col, g_items) in enumerate(test_groups):
        card = s8.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8 + i * 2.98), Inches(2.45), Inches(2.8), Inches(4.45))
        card.fill.solid()
        card.fill.fore_color.rgb = C_CARD
        card.line.color.rgb = col
        card.line.width = Pt(1.5)

        ctf = card.text_frame
        ctf.word_wrap = True
        cp1 = ctf.paragraphs[0]
        cp1.text = g_title
        cp1.font.size = Pt(11)
        cp1.font.bold = True
        cp1.font.color.rgb = col

        cp2 = ctf.add_paragraph()
        cp2.text = g_sub
        cp2.font.size = Pt(9)
        cp2.font.color.rgb = C_MUTED
        cp2.space_before = Pt(2)

        for item in g_items:
            p_item = ctf.add_paragraph()
            p_item.text = "• " + item
            p_item.font.size = Pt(8.8)
            p_item.font.color.rgb = C_WHITE
            p_item.space_before = Pt(7)

    # =========================================================================
    # SLIDE 9: Comparative Security Posture (Pre vs Post Hardening)
    # =========================================================================
    s9 = add_base_slide()
    add_header(s9, "8. Defense Impact: Vulnerable Baseline vs. SENTRIX SHIELD", "COMPARATIVE MATRIX", "Side-by-side evaluation of security controls before and after implementing SENTRIX SHIELD")

    # Table of comparison
    t_shape = s9.shapes.add_table(7, 3, Inches(0.8), Inches(1.6), Inches(11.733), Inches(5.3))
    comp_table = t_shape.table
    comp_table.columns[0].width = Inches(2.5)
    comp_table.columns[1].width = Inches(4.6)
    comp_table.columns[2].width = Inches(4.633)

    c_headers = ["Security Control Dimension", "Pre-Hardening (Vulnerable Baseline)", "Post-Hardening (SENTRIX SHIELD)"]
    for j, h in enumerate(c_headers):
        cell = comp_table.cell(0, j)
        cell.fill.solid()
        cell.fill.fore_color.rgb = C_CARD_ALT
        p = cell.text_frame.paragraphs[0]
        p.text = h
        p.font.size = Pt(11)
        p.font.bold = True
        p.font.color.rgb = C_CYAN if j == 0 else (C_RED if j == 1 else C_GREEN)

    comparisons = [
        ("Source IP Ingress Control", "No IP restriction configured; external host 203.0.113.77 permitted direct ingress.", "Strict Python ipaddress allowlist (10.10.4.12 only); external IPs dropped immediately."),
        ("Credential Lifecycle", "Active ~7 months with expires: never; no scheduled rotation configured (INT-01).", "Mandatory 90-day automated rotation; short-lived tokens; simulated vault SOP workflow."),
        ("Role & Scope Boundaries", "svc_rollcall assigned learner.export & learner.search beyond attendance sync.", "Least-privilege scoping strictly to attendance.read; export requests return HTTP 403."),
        ("Bulk Export Governance", "Uncapped query velocity; 2,300 full profiles dumped in a single unmonitored request.", "Isolated record limit ceiling (max 100); larger exports require dual approval (HTTP 400)."),
        ("SIEM Anomaly Telemetry", "Absent real-time monitoring; incident discovered hours later by Finance (HD-1069).", "Real-time log ingestion with heuristic severity scoring (0-100) and sub-second SIEM alerts."),
        ("API Security & CORS", "Unauthenticated routes; client role headers trusted; wildcard CORS allowed.", "Universal Bearer token auth; server-side RBAC matrix; explicit origin CORS without wildcards.")
    ]

    for i, row in enumerate(comparisons, start=1):
        for j, val in enumerate(row):
            cell = comp_table.cell(i, j)
            cell.fill.solid()
            cell.fill.fore_color.rgb = C_CARD if i % 2 == 1 else RGBColor(14, 20, 33)
            p = cell.text_frame.paragraphs[0]
            p.text = val
            p.font.size = Pt(10)
            if j == 0:
                p.font.bold = True
                p.font.color.rgb = C_WHITE
            elif j == 1:
                p.font.color.rgb = RGBColor(252, 165, 165)  # Light Red
            else:
                p.font.color.rgb = RGBColor(167, 243, 208)  # Light Green

    # =========================================================================
    # SLIDE 10: Summary & Submission Deliverables
    # =========================================================================
    s10 = add_base_slide()
    add_header(s10, "9. CRIMEATHON'26 Mandatory Deliverables", "SUBMISSION READINESS", "All competition requirements completed, verified, and ready for immediate evaluation")

    delivs = [
        ("1. Problem Statement (1 Page)", "Mandatory Deliverable 1", C_CYAN, [
            "Complete 1-page document in PROBLEM_STATEMENT.md & print-ready PROBLEM_STATEMENT.html.",
            "Strictly grounded in authentic case evidence E01–E12 without factual embellishments.",
            "Clearly defines Problem Identification, Evidence Correlation, Technical Impact, and Solution Scope."
        ]),
        ("2. Complete Source Code (GitHub)", "Mandatory Deliverable 2", C_GREEN, [
            "Published at: https://github.com/kandukurijagan1/crimeathon (Branch: main).",
            "Universal Bearer token authentication + RBAC decorators on all /api routes.",
            "Includes local hardened API simulation, SHA-256 evidence integrity loader, and anomaly engine."
        ]),
        ("3. Verification Test Suite & Demo", "Mandatory Deliverable 3", C_AMBER, [
            "Comprehensive 63-test automated security verification suite (run_tests.py) with 100% pass rate.",
            "Interactive Single-Page SOC Dashboard with live radar sweep and in-browser test lab.",
            "Structured demonstration guide for video walkthrough recording."
        ]),
        ("4. Technical Presentation Deck", "Mandatory Deliverable 4", C_RED, [
            "Professional 10-slide PowerPoint slide deck (SENTRIX_SHIELD_PRESENTATION.pptx).",
            "Full project offline archive packaged in SENTRIX_SHIELD_FULL_PACK.zip.",
            "Team SENTRIX CYBER CLUB — Think. Investigate. Innovate."
        ])
    ]

    for i, (d_title, d_sub, col, d_items) in enumerate(delivs):
        card = s10.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8 + i * 2.98), Inches(1.6), Inches(2.8), Inches(5.3))
        card.fill.solid()
        card.fill.fore_color.rgb = C_CARD
        card.line.color.rgb = col
        card.line.width = Pt(1.5)

        ctf = card.text_frame
        ctf.word_wrap = True
        cp1 = ctf.paragraphs[0]
        cp1.text = d_title
        cp1.font.size = Pt(13)
        cp1.font.bold = True
        cp1.font.color.rgb = col

        cp2 = ctf.add_paragraph()
        cp2.text = d_sub
        cp2.font.size = Pt(10)
        cp2.font.color.rgb = C_MUTED
        cp2.space_before = Pt(2)

        for item in d_items:
            p_item = ctf.add_paragraph()
            p_item.text = "• " + item
            p_item.font.size = Pt(9.5)
            p_item.font.color.rgb = C_WHITE
            p_item.space_before = Pt(14)

    output_path = "SENTRIX_SHIELD_PRESENTATION.pptx"
    prs.save(output_path)
    print(f"Successfully generated world-class presentation: {output_path} ({os.path.getsize(output_path)} bytes)")

if __name__ == "__main__":
    create_deck()
