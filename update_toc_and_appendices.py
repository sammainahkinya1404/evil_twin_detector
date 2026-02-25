"""
Update Table of Contents, add List of Figures, List of Tables, and Appendices.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from docx import Document
from docx.shared import Pt, RGBColor, Inches, Cm, Emu
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml.ns import qn
from docx.oxml import OxmlElement

from scanner.detector import EvilTwinDetector, KNOWN_VENDORS, COMMONLY_SPOOFED_SSIDS
from scanner.simulator import ThreatSimulator
from scanner.wifi_scanner import WiFiScanner


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def add_paragraph_to_body(doc, text, style_name=None, bold=False, font_size=None,
                          alignment=None, space_after=None, space_before=None,
                          italic=False, font_name=None, color=None, indent_left=None):
    """Add a paragraph at the end of the document body."""
    p = doc.add_paragraph()
    if style_name:
        try:
            p.style = style_name
        except KeyError:
            pass
    run = p.add_run(text)
    if bold:
        run.bold = True
    if italic:
        run.italic = True
    if font_size:
        run.font.size = Pt(font_size)
    if font_name:
        run.font.name = font_name
    if color:
        run.font.color.rgb = RGBColor(*color)
    if alignment is not None:
        p.alignment = alignment
    if space_after is not None:
        p.paragraph_format.space_after = Pt(space_after)
    if space_before is not None:
        p.paragraph_format.space_before = Pt(space_before)
    if indent_left is not None:
        p.paragraph_format.left_indent = Cm(indent_left)
    return p


def add_heading_to_body(doc, text, level=1):
    """Add a heading paragraph at end of document using style_id directly."""
    p = doc.add_paragraph(text)
    # Set style via XML to avoid style name lookup issues
    pPr = p._element.get_or_add_pPr()
    pStyle = OxmlElement('w:pStyle')
    pStyle.set(qn('w:val'), f'Heading{level}')
    pPr.insert(0, pStyle)
    return p


def insert_paragraph_before(target_para, text, style_name=None, bold=False,
                            font_size=None, alignment=None, italic=False,
                            space_after=None, indent_left=None, font_name=None):
    """Insert a new paragraph before a target paragraph."""
    new_p = OxmlElement('w:p')
    target_para._element.addprevious(new_p)

    # Apply style
    if style_name:
        pPr = OxmlElement('w:pPr')
        pStyle = OxmlElement('w:pStyle')
        pStyle.set(qn('w:val'), style_name)
        pPr.append(pStyle)
        if alignment is not None:
            jc = OxmlElement('w:jc')
            align_map = {
                WD_ALIGN_PARAGRAPH.CENTER: 'center',
                WD_ALIGN_PARAGRAPH.LEFT: 'left',
                WD_ALIGN_PARAGRAPH.RIGHT: 'right',
            }
            jc.set(qn('w:val'), align_map.get(alignment, 'left'))
            pPr.append(jc)
        if indent_left is not None:
            ind = OxmlElement('w:ind')
            ind.set(qn('w:left'), str(int(indent_left * 567)))  # cm to twips
            pPr.append(ind)
        if space_after is not None:
            spacing = OxmlElement('w:spacing')
            spacing.set(qn('w:after'), str(int(space_after * 20)))
            pPr.append(spacing)
        new_p.insert(0, pPr)
    else:
        pPr = OxmlElement('w:pPr')
        if alignment is not None:
            jc = OxmlElement('w:jc')
            align_map = {
                WD_ALIGN_PARAGRAPH.CENTER: 'center',
                WD_ALIGN_PARAGRAPH.LEFT: 'left',
                WD_ALIGN_PARAGRAPH.RIGHT: 'right',
            }
            jc.set(qn('w:val'), align_map.get(alignment, 'left'))
            pPr.append(jc)
        if indent_left is not None:
            ind = OxmlElement('w:ind')
            ind.set(qn('w:left'), str(int(indent_left * 567)))
            pPr.append(ind)
        if space_after is not None:
            spacing = OxmlElement('w:spacing')
            spacing.set(qn('w:after'), str(int(space_after * 20)))
            pPr.append(spacing)
        if len(pPr):
            new_p.insert(0, pPr)

    # Add run
    r = OxmlElement('w:r')
    rPr = OxmlElement('w:rPr')
    if bold:
        rPr.append(OxmlElement('w:b'))
    if italic:
        rPr.append(OxmlElement('w:i'))
    if font_size:
        sz = OxmlElement('w:sz')
        sz.set(qn('w:val'), str(int(font_size * 2)))
        rPr.append(sz)
        szCs = OxmlElement('w:szCs')
        szCs.set(qn('w:val'), str(int(font_size * 2)))
        rPr.append(szCs)
    if font_name:
        rFonts = OxmlElement('w:rFonts')
        rFonts.set(qn('w:ascii'), font_name)
        rFonts.set(qn('w:hAnsi'), font_name)
        rPr.append(rFonts)
    r.append(rPr)
    t = OxmlElement('w:t')
    t.set(qn('xml:space'), 'preserve')
    t.text = text
    r.append(t)
    new_p.append(r)
    return new_p


def insert_heading_before(target_para, text, level=1):
    """Insert a heading paragraph before a target paragraph."""
    new_p = OxmlElement('w:p')
    target_para._element.addprevious(new_p)

    # Style
    pPr = OxmlElement('w:pPr')
    pStyle = OxmlElement('w:pStyle')
    pStyle.set(qn('w:val'), f'Heading{level}')
    pPr.append(pStyle)
    new_p.insert(0, pPr)

    # Run
    r = OxmlElement('w:r')
    rPr = OxmlElement('w:rPr')
    r.append(rPr)
    t = OxmlElement('w:t')
    t.set(qn('xml:space'), 'preserve')
    t.text = text
    r.append(t)
    new_p.append(r)
    return new_p


def insert_after_element(after_elem, text, bold=False, font_size=None,
                         italic=False, indent_left=None, space_after=None,
                         font_name=None, alignment=None):
    """Insert paragraph after an XML element."""
    new_p = OxmlElement('w:p')
    after_elem.addnext(new_p)

    pPr = OxmlElement('w:pPr')
    if indent_left is not None:
        ind = OxmlElement('w:ind')
        ind.set(qn('w:left'), str(int(indent_left * 567)))
        pPr.append(ind)
    if space_after is not None:
        spacing = OxmlElement('w:spacing')
        spacing.set(qn('w:after'), str(int(space_after * 20)))
        pPr.append(spacing)
    if alignment is not None:
        jc = OxmlElement('w:jc')
        align_map = {
            WD_ALIGN_PARAGRAPH.CENTER: 'center',
            WD_ALIGN_PARAGRAPH.LEFT: 'left',
            WD_ALIGN_PARAGRAPH.RIGHT: 'right',
        }
        jc.set(qn('w:val'), align_map.get(alignment, 'left'))
        pPr.append(jc)
    if len(pPr):
        new_p.insert(0, pPr)

    r = OxmlElement('w:r')
    rPr = OxmlElement('w:rPr')
    if bold:
        rPr.append(OxmlElement('w:b'))
    if italic:
        rPr.append(OxmlElement('w:i'))
    if font_size:
        sz = OxmlElement('w:sz')
        sz.set(qn('w:val'), str(int(font_size * 2)))
        rPr.append(sz)
    if font_name:
        rFonts = OxmlElement('w:rFonts')
        rFonts.set(qn('w:ascii'), font_name)
        rFonts.set(qn('w:hAnsi'), font_name)
        rPr.append(rFonts)
    r.append(rPr)
    t = OxmlElement('w:t')
    t.set(qn('xml:space'), 'preserve')
    t.text = text
    r.append(t)
    new_p.append(r)
    return new_p


def add_page_break(doc):
    """Add a page break paragraph at end of doc."""
    p = doc.add_paragraph()
    run = p.add_run()
    br = OxmlElement('w:br')
    br.set(qn('w:type'), 'page')
    run._element.append(br)
    return p


def set_cell_shading(cell, color_hex):
    shading = OxmlElement('w:shd')
    shading.set(qn('w:val'), 'clear')
    shading.set(qn('w:color'), 'auto')
    shading.set(qn('w:fill'), color_hex)
    cell._tc.get_or_add_tcPr().append(shading)


def add_bordered_table(doc, headers, rows, header_bg='2F5496'):
    """Add a bordered table at end of doc body."""
    tbl = doc.add_table(rows=1 + len(rows), cols=len(headers))
    tbl.alignment = WD_TABLE_ALIGNMENT.CENTER

    # Borders
    tbl_element = tbl._tbl
    tblPr = tbl_element.tblPr if tbl_element.tblPr is not None else OxmlElement('w:tblPr')
    borders = OxmlElement('w:tblBorders')
    for edge in ['top', 'left', 'bottom', 'right', 'insideH', 'insideV']:
        border = OxmlElement(f'w:{edge}')
        border.set(qn('w:val'), 'single')
        border.set(qn('w:sz'), '4')
        border.set(qn('w:space'), '0')
        border.set(qn('w:color'), '000000')
        borders.append(border)
    tblPr.append(borders)
    if tbl_element.tblPr is None:
        tbl_element.insert(0, tblPr)

    # Header
    for i, h in enumerate(headers):
        cell = tbl.rows[0].cells[i]
        cell.text = ''
        run = cell.paragraphs[0].add_run(h)
        run.bold = True
        run.font.size = Pt(9)
        run.font.color.rgb = RGBColor(255, 255, 255)
        set_cell_shading(cell, header_bg)

    # Data
    for r_idx, row_data in enumerate(rows):
        for c_idx, val in enumerate(row_data):
            cell = tbl.rows[r_idx + 1].cells[c_idx]
            cell.text = ''
            run = cell.paragraphs[0].add_run(str(val))
            run.font.size = Pt(9)
            if r_idx % 2 == 1:
                set_cell_shading(cell, 'D6E4F0')
    return tbl


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────

def main():
    doc = Document('EvilTwinGuard_Report (1).docx')
    paras = doc.paragraphs

    # ═══════════════════════════════════════════
    # Find the "Contents" heading (P10) and the
    # first chapter heading to know where to insert
    # ═══════════════════════════════════════════

    # Find key paragraph indices
    contents_idx = None
    chapter4_idx = None
    references_idx = None

    for i, p in enumerate(paras):
        txt = p.text.strip()
        if p.style and p.style.name == 'Heading 1':
            if txt == 'Contents':
                contents_idx = i
            elif 'CHAPTER 4' in txt:
                chapter4_idx = i
            elif txt == 'REFERENCES':
                references_idx = i

    print(f"Contents heading at P{contents_idx}")
    print(f"Chapter 4 heading at P{chapter4_idx}")
    print(f"References heading at P{references_idx}")

    # ═══════════════════════════════════════════
    # 1. REBUILD TABLE OF CONTENTS
    #    Remove old TOC content between "Contents" heading and Chapter 4,
    #    then insert new TOC entries.
    # ═══════════════════════════════════════════

    # Collect all headings for TOC
    headings = []
    figures = []
    tables_list = []

    for i, p in enumerate(paras):
        style = p.style.name if p.style else ''
        txt = p.text.strip()
        if not txt:
            continue

        if style == 'Heading 1' and txt != 'Contents':
            headings.append((1, txt))
        elif style == 'Heading 2':
            headings.append((2, txt))

        # Figures
        if txt.startswith('Figure ') and ' - ' in txt:
            figures.append(txt)

        # Tables (from our captions)
        if txt.startswith('Table ') and (' — ' in txt or ' - ' in txt):
            tables_list.append(txt)

    # Also scan inline for table captions we inserted (they may be in elements not in paras)
    # The 7 tables we know about:
    known_tables = [
        'Table 4.1 — Detection Factors and Weights (from detector.py:94-102)',
        'Table 4.2 — Complete API Route Table (from app.py)',
        'Table 4.3 — WiFi Scanning Method Hierarchy (wifi_scanner.py)',
        'Table 4.4 — Database Schema (from database.py:31-87)',
        'Table 4.5 — Attack Simulation Scenarios (from simulator.py)',
        'Table 5.1 — Detection Results Across All Simulation Scenarios',
        'Table 5.2 — All High-Risk Network Detections (Actual Results)',
    ]
    # Merge: use known_tables as canonical, add any from doc we found
    for kt in known_tables:
        if kt not in tables_list:
            tables_list.append(kt)
    # Sort tables by number
    def table_sort_key(t):
        try:
            parts = t.split(' ')[1]
            major, minor = parts.split('.')
            return (int(major), int(minor))
        except:
            return (99, 99)
    tables_list.sort(key=table_sort_key)

    print(f"\nFound {len(headings)} headings, {len(figures)} figures, {len(tables_list)} tables")

    # Delete old content between Contents heading and Chapter 4
    # We need to remove paragraphs between contents_idx+1 and chapter4_idx-1
    # In python-docx, removing paragraphs requires removing XML elements
    paras_to_remove = []
    for i in range(contents_idx + 1, chapter4_idx):
        p = paras[i]
        # Don't remove if it's a heading
        if p.style and 'Heading' in p.style.name:
            break
        paras_to_remove.append(p)

    for p in paras_to_remove:
        p._element.getparent().remove(p._element)

    print(f"Removed {len(paras_to_remove)} old TOC paragraphs")

    # Now insert new TOC content after the Contents heading
    # We need to re-fetch paragraphs since we modified the XML
    # Instead, we'll insert before Chapter 4 heading
    paras = doc.paragraphs  # refresh
    # Find chapter 4 again
    ch4_para = None
    for p in paras:
        if p.style and p.style.name == 'Heading 1' and 'CHAPTER 4' in p.text:
            ch4_para = p
            break

    if not ch4_para:
        print("ERROR: Could not find Chapter 4 heading!")
        return

    # Insert TOC entries before Chapter 4 (in reverse order so they end up in correct order)
    # First add a blank line before Chapter 4
    insert_paragraph_before(ch4_para, '', font_size=11)

    # Insert TOC entries in correct order by building from bottom up
    # We insert before ch4_para, and each insert goes right before it,
    # so we need to insert in REVERSE order so they appear correctly.
    for level, txt in headings:
        indent = 0 if level == 1 else 1.27
        fs = 12 if level == 1 else 11
        bld = level == 1
        insert_paragraph_before(ch4_para, txt, bold=bld, font_size=fs,
                                indent_left=indent, space_after=3)

    # ═══════════════════════════════════════════
    # 2. ADD LIST OF TABLES (between TOC and Chapter 4)
    # ═══════════════════════════════════════════

    # Re-find chapter 4
    paras = doc.paragraphs
    ch4_para = None
    for p in paras:
        if p.style and p.style.name == 'Heading 1' and 'CHAPTER 4' in p.text:
            ch4_para = p
            break

    # Insert heading first, then entries. Each goes just before ch4.
    # Order: heading, t1, t2, ..., t7, spacer, ch4
    insert_heading_before(ch4_para, 'List of Tables', level=1)
    for tbl_cap in tables_list:
        insert_paragraph_before(ch4_para, tbl_cap, font_size=11, space_after=3)
    insert_paragraph_before(ch4_para, '', font_size=6)  # spacer before ch4

    # ═══════════════════════════════════════════
    # 3. ADD LIST OF FIGURES (between List of Tables and Chapter 4)
    # ═══════════════════════════════════════════

    # Re-find chapter 4
    paras = doc.paragraphs
    ch4_para = None
    for p in paras:
        if p.style and p.style.name == 'Heading 1' and 'CHAPTER 4' in p.text:
            ch4_para = p
            break

    insert_heading_before(ch4_para, 'List of Figures', level=1)
    for fig in figures:
        insert_paragraph_before(ch4_para, fig, font_size=11, space_after=3)
    insert_paragraph_before(ch4_para, '', font_size=6)  # spacer before ch4

    # ═══════════════════════════════════════════
    # 4. ADD APPENDICES (after References)
    # ═══════════════════════════════════════════

    # Add page break then Appendices
    add_page_break(doc)

    # --- APPENDICES MAIN HEADING ---
    add_heading_to_body(doc, 'APPENDICES', level=1)

    # ─── Appendix A: Source Code Structure ───
    add_heading_to_body(doc, 'Appendix A: Project File Structure', level=2)

    add_paragraph_to_body(
        doc,
        'The EvilTwinGuard project is organized into the following directory structure:',
        font_size=11, space_after=6
    )

    file_tree = [
        ('evil_twin_detector/', 'Project root directory'),
        ('    app.py', 'Flask application — 12 routes, threading, error handlers (241 lines)'),
        ('    config.py', 'Configuration classes — Dev/Prod settings (25 lines)'),
        ('    scanner/', 'Core detection package'),
        ('        __init__.py', 'Package initializer'),
        ('        detector.py', 'Evil Twin detection engine — 9 factors, 41 vendors (413 lines)'),
        ('        simulator.py', 'Threat simulation — 6 scenarios, 68 networks (882 lines)'),
        ('        wifi_scanner.py', 'WiFi scanning — 6 methods + demo fallback (705 lines)'),
        ('    models/', 'Data persistence package'),
        ('        __init__.py', 'Package initializer'),
        ('        database.py', 'SQLite — 4 tables, 5 indexes, WAL mode (304 lines)'),
        ('    templates/', 'Jinja2 HTML templates'),
        ('        base.html', 'Base template with nav, dark theme CSS'),
        ('        dashboard.html', 'Main dashboard with stats and alerts'),
        ('        history.html', 'Scan history timeline'),
        ('        network_detail.html', 'Per-network detail view'),
        ('        404.html', 'Custom 404 error page'),
        ('    static/', 'Static assets (CSS, JS, images)'),
    ]

    add_bordered_table(doc,
        headers=['File / Directory', 'Description'],
        rows=file_tree,
    )
    add_paragraph_to_body(doc, '', font_size=6)

    # ─── Appendix B: Detection Factor Weights ───
    add_heading_to_body(doc, 'Appendix B: Detection Factor Weights and Scoring Logic', level=2)

    add_paragraph_to_body(
        doc,
        'The following code excerpt from detector.py (lines 91-102) defines the core risk '
        'scoring weights used by the EvilTwinDetector class:',
        font_size=11, space_after=6
    )

    code_weights = """class EvilTwinDetector:
    def __init__(self):
        self.whitelist = []
        self.network_history = defaultdict(list)
        self.weights = {
            'ssid_duplication': 25,
            'encryption_mismatch': 20,
            'signal_anomaly': 15,
            'channel_anomaly': 10,
            'mac_anomaly': 15,
            'open_network': 10,
            'common_spoof_target': 5,
        }
        # Total core weights: 100
        # Bonus: Historical changes (+10), Hidden+Open (+15)
        # Risk thresholds: HIGH >= 61, MEDIUM >= 31, LOW < 31"""

    for line in code_weights.strip().split('\n'):
        add_paragraph_to_body(doc, line, font_size=9, font_name='Consolas', space_after=0)

    add_paragraph_to_body(doc, '', font_size=6)

    add_paragraph_to_body(
        doc,
        'Risk Classification Thresholds (detector.py lines 261-266):',
        font_size=11, bold=True, space_after=4
    )

    add_bordered_table(doc,
        headers=['Risk Level', 'Score Range', 'Meaning', 'Action'],
        rows=[
            ['HIGH', '61 — 100', 'Strong Evil Twin indicators detected',
             'Avoid connection; possible attack in progress'],
            ['MEDIUM', '31 — 60', 'Some suspicious indicators present',
             'Investigate further before connecting'],
            ['LOW', '0 — 30', 'Normal network behavior',
             'Safe to connect (standard precautions apply)'],
        ],
    )
    add_paragraph_to_body(doc, '', font_size=6)

    # ─── Appendix C: Known Vendor OUI Database ───
    add_heading_to_body(doc, 'Appendix C: Known Vendor OUI Database', level=2)

    add_paragraph_to_body(
        doc,
        f'The detection engine maintains a database of {len(KNOWN_VENDORS)} known vendor OUI '
        f'(Organizationally Unique Identifier) prefixes used to verify MAC address legitimacy. '
        f'The following table lists all entries from detector.py (lines 29-71):',
        font_size=11, space_after=6
    )

    # Group vendors
    vendor_groups = {}
    for oui, vendor in sorted(KNOWN_VENDORS.items()):
        vendor_groups.setdefault(vendor, []).append(oui)

    vendor_rows = []
    for vendor in sorted(vendor_groups.keys()):
        ouis = vendor_groups[vendor]
        vendor_rows.append([vendor, str(len(ouis)), ', '.join(sorted(ouis))])

    add_bordered_table(doc,
        headers=['Vendor', 'Count', 'OUI Prefixes'],
        rows=vendor_rows,
    )
    add_paragraph_to_body(doc, '', font_size=6)

    # ─── Appendix D: Commonly Spoofed SSIDs ───
    add_heading_to_body(doc, 'Appendix D: Commonly Spoofed SSIDs', level=2)

    add_paragraph_to_body(
        doc,
        f'The following {len(COMMONLY_SPOOFED_SSIDS)} SSIDs are recognized as common targets for '
        f'Evil Twin attacks. Networks matching these names receive an additional +5 risk score. '
        f'Source: detector.py (lines 74-80):',
        font_size=11, space_after=6
    )

    ssid_rows = []
    for idx, ssid in enumerate(sorted(COMMONLY_SPOOFED_SSIDS), 1):
        category = 'Carrier/ISP' if ssid in ('attwifi', 'xfinity', 'xfinitywifi', 'tmobile', 't-mobile') \
            else 'Coffee/Food' if ssid in ('starbucks', 'google starbucks') \
            else 'Travel' if ssid in ('airport wifi', 'airport free wifi', 'hotel wifi', 'boingo', 'boingo hotspot') \
            else 'Generic' if ssid in ('free wifi', 'free internet', 'public wifi', 'open', 'guest') \
            else 'Router Default' if ssid in ('linksys', 'netgear', 'dlink', 'belkin', 'default') \
            else 'Generic'
        ssid_rows.append([str(idx), ssid, category])

    add_bordered_table(doc,
        headers=['#', 'SSID', 'Category'],
        rows=ssid_rows,
    )
    add_paragraph_to_body(doc, '', font_size=6)

    # ─── Appendix E: WiFi Scanning Methods ───
    add_heading_to_body(doc, 'Appendix E: WiFi Scanning Method Details', level=2)

    add_paragraph_to_body(
        doc,
        'The WiFiScanner class (wifi_scanner.py) implements automatic detection and fallback '
        'across six platform-specific scanning methods. The following table details each method '
        'with its requirements and capabilities:',
        font_size=11, space_after=6
    )

    add_bordered_table(doc,
        headers=['Priority', 'Method', 'Platform', 'Requires Root', 'Implementation', 'Output Parsing'],
        rows=[
            ['1', 'Scapy', 'All', 'Yes',
             'Sniffs Dot11Beacon and Dot11ProbeResp frames for 10 seconds',
             'Extracts SSID, BSSID, channel, encryption from 802.11 elements'],
            ['2', 'nmcli', 'Linux', 'No',
             'nmcli -t -f SSID,BSSID,CHAN,FREQ,SIGNAL,SECURITY device wifi list',
             'Parses colon-separated machine-readable output'],
            ['3', 'iwlist', 'Linux', 'Yes',
             'sudo iwlist <iface> scan',
             'Regex parsing of Cell/ESSID/Channel/Signal/Encryption blocks'],
            ['4', 'iw', 'Linux', 'Yes',
             'sudo iw <iface> scan trigger + dump',
             'Parses BSS blocks with SSID/signal/DS Parameter/RSN fields'],
            ['5', 'netsh', 'Windows', 'No',
             'netsh wlan show networks mode=bssid',
             'Parses SSID/BSSID/Signal/Channel/Authentication fields'],
            ['6', 'airport', 'macOS', 'No',
             'Apple80211.framework/Resources/airport -s',
             'Parses columnar output (SSID BSSID RSSI CHANNEL SECURITY)'],
            ['7', 'Demo', 'Fallback', 'No',
             'Generates 10 hardcoded networks including 2 Evil Twins',
             'Returns pre-built dictionaries with realistic values'],
        ],
    )

    add_paragraph_to_body(doc, '', font_size=4)

    add_paragraph_to_body(
        doc,
        'All methods return a standardized 7-field dictionary format:',
        font_size=11, bold=True, space_after=4
    )

    add_bordered_table(doc,
        headers=['Field', 'Type', 'Example', 'Description'],
        rows=[
            ['ssid', 'str', '"Brew & Bean WiFi"', 'Network name (or "<Hidden>")'],
            ['bssid', 'str', '"30:B5:C2:A1:44:21"', 'MAC address of access point'],
            ['signal_strength', 'int', '-52', 'Signal power in dBm'],
            ['channel', 'int', '6', 'WiFi channel number'],
            ['frequency', 'str', '"2.4GHz"', 'Frequency band'],
            ['encryption', 'str', '"WPA2"', 'Security protocol'],
            ['timestamp', 'str', '"2026-02-17T..."', 'ISO 8601 scan time'],
        ],
    )
    add_paragraph_to_body(doc, '', font_size=6)

    # ─── Appendix F: Database Schema ───
    add_heading_to_body(doc, 'Appendix F: Complete Database Schema', level=2)

    add_paragraph_to_body(
        doc,
        'The following SQL statements define the complete database schema as implemented in '
        'database.py (lines 31-87). The database uses SQLite with WAL (Write-Ahead Logging) '
        'journal mode for concurrent read performance:',
        font_size=11, space_after=6
    )

    sql_schema = """-- Scan sessions
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    total_networks INTEGER DEFAULT 0,
    high_risk_count INTEGER DEFAULT 0,
    medium_risk_count INTEGER DEFAULT 0,
    low_risk_count INTEGER DEFAULT 0,
    threat_level TEXT DEFAULT 'safe'
);

-- Individual network observations
CREATE TABLE IF NOT EXISTS networks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    ssid TEXT,
    bssid TEXT NOT NULL,
    signal_strength INTEGER,
    channel INTEGER,
    frequency TEXT,
    encryption TEXT,
    risk_score INTEGER DEFAULT 0,
    risk_level TEXT DEFAULT 'low',
    risk_factors TEXT,  -- JSON
    vendor TEXT,
    timestamp TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans (id)
);

-- Alerts log
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER,
    ssid TEXT,
    bssid TEXT,
    risk_level TEXT,
    risk_score INTEGER,
    message TEXT,
    timestamp TEXT,
    acknowledged INTEGER DEFAULT 0,
    FOREIGN KEY (scan_id) REFERENCES scans (id)
);

-- Trusted networks whitelist
CREATE TABLE IF NOT EXISTS whitelist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    bssid TEXT UNIQUE NOT NULL,
    ssid TEXT,
    added_date TEXT,
    notes TEXT
);

-- Performance indexes
CREATE INDEX IF NOT EXISTS idx_networks_scan_id ON networks(scan_id);
CREATE INDEX IF NOT EXISTS idx_networks_bssid ON networks(bssid);
CREATE INDEX IF NOT EXISTS idx_networks_ssid ON networks(ssid);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp);"""

    for line in sql_schema.strip().split('\n'):
        add_paragraph_to_body(doc, line, font_size=9, font_name='Consolas', space_after=0)

    add_paragraph_to_body(doc, '', font_size=6)

    # ─── Appendix G: Complete API Route Specifications ───
    add_heading_to_body(doc, 'Appendix G: Complete API Route Specifications', level=2)

    add_paragraph_to_body(
        doc,
        'The following table documents all 12 routes defined in app.py with their full '
        'specifications including request/response formats:',
        font_size=11, space_after=6
    )

    add_bordered_table(doc,
        headers=['Route', 'Method', 'Purpose', 'Request Body', 'Response Format'],
        rows=[
            ['/', 'GET', 'Dashboard page', 'N/A', 'HTML (dashboard.html with stats, alerts)'],
            ['/history', 'GET', 'Scan history', 'N/A', 'HTML (history.html with scan list)'],
            ['/network/<bssid>', 'GET', 'Network detail', 'N/A', 'HTML (network_detail.html)'],
            ['/api/scan', 'POST', 'Start scan', 'None', 'JSON {status, message}'],
            ['/api/scan/status', 'GET', 'Scan status', 'N/A', 'JSON {is_scanning, last_scan, network_count, alert_count}'],
            ['/api/networks', 'GET', 'All networks', 'N/A', 'JSON {networks[], last_scan}'],
            ['/api/alerts', 'GET', 'Active alerts', 'N/A', 'JSON {alerts[], count}'],
            ['/api/statistics', 'GET', 'System stats', 'N/A', 'JSON {total_scans, unique_networks, ...}'],
            ['/api/network/<bssid>/history', 'GET', 'Network history', 'N/A', 'JSON {bssid, history[]}'],
            ['/api/whitelist', 'GET', 'Get whitelist', 'N/A', 'JSON {whitelist[]}'],
            ['/api/whitelist', 'POST', 'Add to whitelist', 'JSON {bssid, ssid}', 'JSON {status, message}'],
            ['/api/whitelist', 'DELETE', 'Remove from whitelist', 'JSON {bssid}', 'JSON {status, message}'],
            ['/api/simulate/scenarios', 'GET', 'List scenarios', 'N/A', 'JSON {scenarios[]}'],
            ['/api/simulate/<id>', 'POST', 'Run simulation', 'None', 'JSON {status, message}'],
        ],
    )
    add_paragraph_to_body(doc, '', font_size=6)

    # ─── Appendix H: Simulation Scenario Network Details ───
    add_heading_to_body(doc, 'Appendix H: Simulation Scenario Network Details', level=2)

    add_paragraph_to_body(
        doc,
        'The following tables list every network generated by each simulation scenario, '
        'including whether it is a legitimate network or a threat:',
        font_size=11, space_after=6
    )

    simulator = ThreatSimulator()
    detector = EvilTwinDetector()

    for scenario in simulator.get_available_scenarios():
        sid = scenario['id']
        det = EvilTwinDetector()
        networks = simulator.simulate(sid)
        analyzed = det.analyze(networks)
        analyzed.sort(key=lambda x: x['risk_score'], reverse=True)

        add_paragraph_to_body(
            doc,
            f'{scenario["name"]} ({scenario["difficulty"]}) — '
            f'{scenario["networks"]} networks, {scenario["threats"]} threats:',
            font_size=11, bold=True, space_after=4
        )

        net_rows = []
        for n in analyzed:
            factors_short = ', '.join(
                (f.get('factor', '')[:20] if isinstance(f, dict) else str(f)[:20])
                for f in n.get('risk_factors', [])[:3]
            )
            net_rows.append([
                n['ssid'][:22],
                n['bssid'],
                str(n['signal_strength']),
                str(n['channel']),
                n['encryption'],
                str(n['risk_score']),
                n['risk_level'].upper(),
            ])

        add_bordered_table(doc,
            headers=['SSID', 'BSSID', 'Signal', 'Ch', 'Encryption', 'Score', 'Risk'],
            rows=net_rows,
        )
        add_paragraph_to_body(doc, '', font_size=6)

    # ═══════════════════════════════════════════
    # Now update the TOC headings to include appendices and lists
    # We need to add the new sections to the TOC area
    # ═══════════════════════════════════════════

    # Add TOC entries for List of Tables, List of Figures, and Appendices
    # These go at end of TOC, before the "List of Tables" heading
    paras = doc.paragraphs
    lot_para = None
    for p in paras:
        if p.style and 'Heading' in p.style.name and p.text.strip() == 'List of Tables':
            lot_para = p
            break

    if lot_para:
        toc_extra = [
            (1, 'List of Tables'),
            (1, 'List of Figures'),
            (1, 'APPENDICES'),
            (2, 'Appendix A: Project File Structure'),
            (2, 'Appendix B: Detection Factor Weights and Scoring Logic'),
            (2, 'Appendix C: Known Vendor OUI Database'),
            (2, 'Appendix D: Commonly Spoofed SSIDs'),
            (2, 'Appendix E: WiFi Scanning Method Details'),
            (2, 'Appendix F: Complete Database Schema'),
            (2, 'Appendix G: Complete API Route Specifications'),
            (2, 'Appendix H: Simulation Scenario Network Details'),
        ]

        for level, txt in toc_extra:
            indent = 0 if level == 1 else 1.27
            fs = 12 if level == 1 else 11
            bld = level == 1
            insert_paragraph_before(lot_para, txt, bold=bld, font_size=fs,
                                    indent_left=indent, space_after=3)
        # Add a spacer before the List of Tables heading
        insert_paragraph_before(lot_para, '', font_size=6)

    # ═══════════════════════════════════════════
    # Save
    # ═══════════════════════════════════════════

    output_path = 'EvilTwinGuard_Report_enriched.docx'
    doc.save(output_path)
    print(f"\nSaved to: {output_path}")
    return output_path


if __name__ == '__main__':
    print("=" * 60)
    print("  Adding TOC, List of Figures/Tables, Appendices")
    print("=" * 60)

    output = main()

    # Verify
    print("\nVerifying...")
    doc = Document(output)
    print(f"  Total paragraphs: {len(doc.paragraphs)}")
    print(f"  Total tables:     {len(doc.tables)}")

    headings = [(p.style.name, p.text[:80]) for p in doc.paragraphs
                if p.style and 'Heading' in p.style.name and p.text.strip()]
    print(f"  Headings: {len(headings)}")
    for style, txt in headings:
        indent = '  ' if '2' in style else ''
        print(f"    {indent}{txt}")

    print("\n" + "=" * 60)
    print("  DONE!")
    print("=" * 60)
