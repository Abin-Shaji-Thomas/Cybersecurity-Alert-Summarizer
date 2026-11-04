"""Build the A0 poster on top of the official KGS 2026 template and export it to PDF.

Run from anywhere:   python docs/poster/build_poster.py
Needs:               pip install python-pptx segno pillow
PDF export:          Microsoft PowerPoint (Windows, via COM from PowerShell). If it is missing, only the .pptx is written.

Every number on the poster comes from data/eval/results.json, docs/RESULTS.md, docs/DATASET.md or
test_samples/README.md (see NUMBERS below, which lists the source of each value).
"""
import json
import subprocess
import sys
from pathlib import Path

import segno
from PIL import Image, ImageFont
from pptx import Presentation
from pptx.chart.data import CategoryChartData
from pptx.dml.color import RGBColor
from pptx.enum.chart import XL_CHART_TYPE, XL_LEGEND_POSITION, XL_LABEL_POSITION
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import MSO_ANCHOR, PP_ALIGN
from pptx.oxml.ns import qn
from pptx.util import Inches, Pt

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
TEMPLATE = HERE / "KGS 2026 - Poster Design Template (1).pptx"
OUT_PPTX = HERE / "NLP_Poster_Cybersecurity_Alert_Summarizer.pptx"
OUT_PDF = HERE / "NLP_Poster_Cybersecurity_Alert_Summarizer.pdf"
IMG = HERE / "img"
REPO_URL = "https://github.com/Abin-Shaji-Thomas/Cybersecurity-Alert-Summarizer"

FONT = "Times New Roman"
NAVY = RGBColor(0x1F, 0x2A, 0x44)
RED = RGBColor(0xC0, 0x1F, 0x2E)        # Karunya red
GREY = RGBColor(0x59, 0x59, 0x59)
LIGHT = RGBColor(0xDA, 0xE3, 0xF3)      # light blue, like the template's bars
BLACK = RGBColor(0, 0, 0)
WHITE = RGBColor(0xFF, 0xFF, 0xFF)

BODY, CAPTION = 34, 30                  # pt (rules: body 34-40, captions ~30, nothing below 24)

# ---------------------------------------------------------------- numbers (all read from the repo)
R = json.loads((ROOT / "data" / "eval" / "results.json").read_text(encoding="utf-8"))
RM, SH = R["scenarios"]["russellmitchell"], R["scenarios"]["shaw"]
ROUGE = R["summarization"]["mean_f1"]
NUMBERS = {
    # docs/DATASET.md (raw alert counts of the two scenario files, bundled sample)
    "rm_raw": "41,488", "sh_raw": "68,539", "sample_raw": "1,515", "sample_alerts": "1,467", "sample_incidents": "18",
    # data/eval/results.json
    "rm_alerts": f"{RM['n_alerts']:,}", "sh_alerts": f"{SH['n_alerts']:,}",
    "rm_inc": str(RM["n_incidents"]), "sh_inc": str(SH["n_incidents"]),
    "rm_sec": str(RM["seconds"]), "sh_sec": str(SH["seconds"]),
    "rm_pur": RM["clustering"]["purity_incidents"], "sh_pur": SH["clustering"]["purity_incidents"],
    "rm_base": RM["clustering"]["purity_majority_baseline"], "sh_base": SH["clustering"]["purity_majority_baseline"],
    "rm_pp": RM["lm"]["perplexity_test_smoothed"], "sh_pp": SH["lm"]["perplexity_test_smoothed"],
    "ner_f1": R["ner"]["micro"]["f1"], "ner_n": R["ner"]["n_sentences"],
    "tri_p": R["triples"]["precision"], "tri_r": R["triples"]["recall"], "tri_n": R["triples"]["n_gold"],
    "hmm": R["hmm_vs_spacy"]["agreement"], "n_refs": R["summarization"]["n_matched"],
    # README.md (pytest)
    "tests": "19",
}
assert RM["lm"]["perplexity_test_unsmoothed"] == "infinity" and SH["lm"]["perplexity_test_unsmoothed"] == "infinity"
N = NUMBERS


# ---------------------------------------------------------------- helpers
def text_width_in(text, pt, bold=False):
    """Width of one line of Times New Roman text, in inches (real font metrics)."""
    f = ImageFont.truetype("C:/Windows/Fonts/" + ("timesbd.ttf" if bold else "times.ttf"), pt * 10)
    return f.getlength(text) / 10 / 72


def fit_one_line(text, max_pt, width_in, min_pt=24, bold=False):
    pt = max_pt
    while pt > min_pt and text_width_in(text, pt, bold) > width_in:
        pt -= 1
    return pt


def style_run(run, size, bold=False, color=BLACK, italic=False):
    f = run.font
    f.name, f.size, f.bold, f.italic = FONT, Pt(size), bold, italic
    f.color.rgb = color


def set_bullet(paragraph, char="•", indent_in=0.45):
    pPr = paragraph._p.get_or_add_pPr()
    pPr.set("marL", str(int(Inches(indent_in))))
    pPr.set("indent", str(-int(Inches(indent_in))))
    for tag in ("a:buNone", "a:buChar", "a:buAutoNum", "a:buFont"):
        for el in pPr.findall(qn(tag)):
            pPr.remove(el)
    bu_font = pPr.makeelement(qn("a:buFont"), {"typeface": "Arial"})
    bu = pPr.makeelement(qn("a:buChar"), {"char": char})
    pPr.append(bu_font)
    pPr.append(bu)


def textbox(slide, x, y, w, h, anchor=MSO_ANCHOR.TOP):
    tb = slide.shapes.add_textbox(Inches(x), Inches(y), Inches(w), Inches(h))
    tf = tb.text_frame
    tf.word_wrap = True
    tf.auto_size = None
    tf.margin_left = tf.margin_right = Inches(0.05)
    tf.margin_top = tf.margin_bottom = Inches(0.03)
    tf.vertical_anchor = anchor
    return tb, tf


def add_para(tf, parts, size=BODY, bullet=False, align=PP_ALIGN.LEFT, space_after=8, first=False, line_spacing=1.0):
    """parts = list of (text, bold, color) tuples or a plain string."""
    p = tf.paragraphs[0] if first else tf.add_paragraph()
    if isinstance(parts, str):
        parts = [(parts, False, BLACK)]
    for text, bold, color in parts:
        run = p.add_run()
        run.text = text
        style_run(run, size, bold, color)
    p.alignment = align
    p.space_after = Pt(space_after)
    p.line_spacing = line_spacing
    if bullet:
        set_bullet(p)
    return p


def bullets(slide, x, y, w, h, items, size=BODY, heading=None, space_after=10):
    """items: list of (bold label or None, text)."""
    _, tf = textbox(slide, x, y, w, h)
    first = True
    if heading:
        add_para(tf, [(heading, True, RED)], size=40, first=True, space_after=6)
        first = False
    for label, text in items:
        parts = ([(label + " ", True, BLACK)] if label else []) + [(text, False, BLACK)]
        add_para(tf, parts, size=size, bullet=True, first=first, space_after=space_after)
        first = False
    return tf


def caption(slide, x, y, w, text, size=CAPTION, color=BLACK, bold_prefix=True, align=PP_ALIGN.CENTER, h=0.55):
    _, tf = textbox(slide, x, y, w, h)
    if bold_prefix and text.startswith("Fig."):
        num, rest = text.split("  ", 1)
        add_para(tf, [(num + "  ", True, color), (rest, True, color)], size=size, first=True, align=align, space_after=0)
    else:
        add_para(tf, [(text, False, color)], size=size, first=True, align=align, space_after=0)
    return tf


def box(slide, x, y, w, h, fill, line=None, shape=MSO_SHAPE.ROUNDED_RECTANGLE):
    s = slide.shapes.add_shape(shape, Inches(x), Inches(y), Inches(w), Inches(h))
    s.fill.solid()
    s.fill.fore_color.rgb = fill
    if line is None:
        s.line.fill.background()
    else:
        s.line.color.rgb = line
        s.line.width = Pt(3)
    s.shadow.inherit = False
    tf = s.text_frame
    tf.word_wrap = True
    tf.margin_left = tf.margin_right = Inches(0.06)
    tf.margin_top = tf.margin_bottom = Inches(0.04)
    tf.vertical_anchor = MSO_ANCHOR.MIDDLE
    return s, tf


def arrow(slide, x, y, w, h, color=GREY):
    s = slide.shapes.add_shape(MSO_SHAPE.RIGHT_ARROW, Inches(x), Inches(y), Inches(w), Inches(h))
    s.fill.solid()
    s.fill.fore_color.rgb = color
    s.line.fill.background()
    s.shadow.inherit = False
    return s


def set_shape_text(shape, text, size=None, color=None, bold=None):
    """Replace a template shape's text but keep its paragraph/run formatting (font, size, colour)."""
    tf = shape.text_frame
    p0 = tf.paragraphs[0]
    for extra in tf.paragraphs[1:]:
        extra._p.getparent().remove(extra._p)
    runs = p0.runs
    for r in runs[1:]:
        r._r.getparent().remove(r._r)
    run = runs[0] if runs else p0.add_run()
    run.text = text
    run.font.name = FONT
    if size:
        run.font.size = Pt(size)
    if color is not None:
        run.font.color.rgb = color
    if bold is not None:
        run.font.bold = bold
    return run


# ---------------------------------------------------------------- figure crops (screenshots taken at 2x scale)
def crop_fig2():
    """Incident page: keep the title + badge row and the summary card, drop the breadcrumb and the button row."""
    im = Image.open(IMG / "fig2_incident_summary.png")
    top, card = im.crop((0, 55, im.width, 255)), im.crop((0, 382, im.width, im.height))
    out = Image.new("RGB", (im.width, top.height + card.height))
    out.paste(top, (0, 0))
    out.paste(card, (0, top.height))
    path = IMG / "fig2_crop.png"
    out.save(path)
    return path


def crop_fig3():
    """NLP Lab: keep only the CKY parse table."""
    im = Image.open(IMG / "fig3_nlp_lab_cky.png")
    path = IMG / "fig3_crop.png"
    im.crop((0, 150, im.width, 815)).save(path)
    return path


# ---------------------------------------------------------------- build
def build():
    prs = Presentation(str(TEMPLATE))
    slide = prs.slides[0]
    shapes = {s.shape_id: s for s in slide.shapes}

    # 1. delete every template instruction shape (body placeholders, SmartArt picture, Column 1-3, lorem ipsum)
    for sid in (59, 60, 61, 64, 65, 66, 68):
        el = shapes[sid]._element
        el.getparent().remove(el)

    # 2. header: title (96 pt, unchanged size) + three lines that do not overlap the bar or each other
    set_shape_text(shapes[2], "Cybersecurity Alert Summarizer", size=96)
    team = "Abin Shaji Thomas URK24CS6007; Jinto Joseph URK24CS1210; BÉAL Elouan ISK26CS1005"
    sup = "Supervisor: Dr. Brindha D, Assistant Professor, Division of Computer Science and Engineering"
    third = ("Division of Computer Science and Engineering, Karunya Institute of Technology and Sciences  |  "
             "Course: 26CS301 Natural Language Processing")
    line_w = 31.2      # usable width; PowerPoint sets text a little wider than the raw font metrics
    team_pt = fit_one_line(team, 60, line_w)
    sup_pt = fit_one_line(sup, team_pt, line_w)
    third_pt = fit_one_line(third, 40, line_w)
    for sid, text, pt, y in ((58, team, team_pt, 5.62), (69, sup, sup_pt, 6.52)):
        sh = shapes[sid]
        sh.left, sh.top, sh.width, sh.height = Inches(0.24), Inches(y), Inches(32.63), Inches(0.86)
        tf = sh.text_frame
        tf.word_wrap = False
        tf.margin_left = Inches(0.3)
        tf.margin_top = tf.margin_bottom = Inches(0)
        tf.vertical_anchor = MSO_ANCHOR.TOP
        set_shape_text(sh, text, size=pt, color=BLACK)
    _, tf = textbox(slide, 0.24, 7.55, 32.63, 0.7, anchor=MSO_ANCHOR.TOP)
    tf.margin_left = Inches(0.3)
    add_para(tf, [(third, False, GREY)], size=third_pt, first=True, space_after=0)

    # 3. section header bars: keep shape, position and 56 pt formatting, replace only the text
    for sid, name in ((54, "Introduction"), (62, "Methods"), (63, "Results"), (67, "Discussions")):
        set_shape_text(shapes[sid], name)

    # 4. INTRODUCTION
    bullets(slide, 0.79, 9.9, 15.1, 8.35, [
        ("Problem:", "SIEM and IDS tools raise thousands of near-identical alerts for a single attack, so analysts "
                     "suffer alert fatigue and the real incident is easy to miss."),
        ("Data:", f"AIT Alert Data Set (Landauer et al.): real Wazuh + Suricata alerts with labelled attack phases; "
                  f"scenarios russellmitchell ({N['rm_raw']} alerts) and shaw ({N['sh_raw']} alerts)."),
        ("Objectives:", "group alerts into incidents; summarise each one (what, who, target, when, severity, next "
                        "step); answer questions; run offline on a CPU."),
        ("Scope:", "all five NLP units in a React + FastAPI + SQLite web app, with an NLP Lab that shows every step."),
    ], size=40, space_after=22)

    # 5. METHODS: bullets + 5-step flow + caption
    bullets(slide, 16.62, 9.9, 15.55, 5.75, [
        ("Alert → sentence:", "each JSON alert becomes English, e.g. \u201cAt 09:40:06, host mail reported 'sshd: "
                              "authentication success' for user jhall from 172.19.131.174 (level 3).\u201d"),
        ("Incidents:", "TF-IDF + k-means (k chosen by silhouette), split at 30-minute gaps."),
        ("Summary:", "template filling, with extractive and DistilBART baselines; a QA chatbot over the facts."),
        ("Own code:", "edit distance, bigram LM, Viterbi, CKY, Chu-Liu/Edmonds, PMI."),
    ], space_after=6)
    steps = [("1", "Unit I", "Mask + bigram LM"), ("2", "Unit II", "POS + security NER"),
             ("3", "Unit III", "Parse + triples"), ("4", "Unit IV", "TF-IDF incidents"),
             ("5", "Unit V", "Summaries + QA")]
    bw, gap, by, bh = 2.55, 0.7, 15.75, 1.75
    for i, (num, unit, what) in enumerate(steps):
        x = 16.62 + i * (bw + gap)
        _, tf = box(slide, x, by, bw, bh, NAVY if i % 2 == 0 else RED)
        add_para(tf, [(f"{num}  {unit}", True, WHITE)], size=32, first=True, align=PP_ALIGN.CENTER, space_after=2)
        add_para(tf, [(what, False, WHITE)], size=26, align=PP_ALIGN.CENTER, space_after=0)
        if i < len(steps) - 1:
            arrow(slide, x + bw + 0.12, by + bh / 2 - 0.22, gap - 0.24, 0.44)
    caption(slide, 16.62, 17.58, 15.55, "JSON alerts → sentences → NLP pipeline → SQLite → React UI", color=GREY)

    # 6. RESULTS, column 1: key findings
    bullets(slide, 0.69, 19.75, 9.95, 15.6, [
        ("Alerts → incidents:", f"russellmitchell {N['rm_raw']} raw → {N['rm_alerts']} unique alerts → {N['rm_inc']} "
                                f"incidents; shaw {N['sh_raw']} → {N['sh_alerts']} → {N['sh_inc']}; bundled sample "
                                f"{N['sample_raw']} → {N['sample_alerts']} → {N['sample_incidents']}."),
        ("Purity:", f"incidents match the attack phases with purity {N['rm_pur']:.3f} and {N['sh_pur']:.3f}, above "
                    f"the one-group baseline of {N['rm_base']:.3f} and {N['sh_base']:.3f} (Fig. 4)."),
        ("Language model:", f"held-out perplexity is \u221e without smoothing and {N['rm_pp']:.2f} / "
                            f"{N['sh_pp']:.2f} with Laplace smoothing."),
        ("Faithful summaries:", "template summaries keep IPs, times and counts exact; DistilBART once shortened an "
                                "IP address."),
        ("Speed:", f"a full scenario runs in {N['rm_sec']} s and {N['sh_sec']} s on a laptop CPU."),
        ("Ask tab + PDF:", "questions are answered with supporting alerts; each incident exports as a PDF report."),
    ], size=39, heading="Key findings", space_after=16)

    # 7. RESULTS, column 2: three figures
    cx, cw = 11.6, 9.91
    # Fig. 1: architecture, drawn with native shapes
    ay, ah = 19.95, 2.2
    parts = [("React + Vite", "web UI"), ("FastAPI", "REST API"), ("NLP pipeline", "Units I–V"), ("SQLite", "6 tables")]
    abw, agap = 2.02, 0.6
    ax0 = cx + (cw - (4 * abw + 3 * agap)) / 2
    for i, (a, b) in enumerate(parts):
        _, tf = box(slide, ax0 + i * (abw + agap), ay, abw, ah, LIGHT, line=NAVY)
        add_para(tf, [(a, True, NAVY)], size=28, first=True, align=PP_ALIGN.CENTER, space_after=2)
        add_para(tf, [(b, False, NAVY)], size=26, align=PP_ALIGN.CENTER, space_after=0)
        if i < 3:
            arrow(slide, ax0 + i * (abw + agap) + abw + 0.08, ay + ah / 2 - 0.2, agap - 0.16, 0.4, color=NAVY)
    caption(slide, cx, ay + ah + 0.1, cw, "Fig. 1  System architecture (local, CPU only)")
    # Fig. 2: incident page (title + badges stitched to the template summary card), full column width
    f2 = crop_fig2()
    f2y = ay + ah + 0.75
    pic = slide.shapes.add_picture(str(f2), Inches(cx), Inches(f2y), width=Inches(cw))
    f2b = f2y + pic.height.inches
    caption(slide, cx, f2b + 0.06, cw, "Fig. 2  Incident page with its template summary")
    # Fig. 3: NLP Lab CKY table only, full column width
    f3 = crop_fig3()
    f3y = f2b + 0.72
    pic = slide.shapes.add_picture(str(f3), Inches(cx), Inches(f3y), width=Inches(cw))
    caption(slide, cx, f3y + pic.height.inches + 0.06, cw, "Fig. 3  NLP Lab, Unit II: our CKY parse table")

    # 8. RESULTS, column 3: ROUGE table, bullets, native chart
    rx, rw = 22.51, 9.91
    _, tf = textbox(slide, rx, 19.75, rw, 0.75)
    add_para(tf, [("Summary quality (ROUGE F1)", True, RED)], size=40, first=True, space_after=0)
    rows = [("Summary", "R-1", "R-2", "R-L"),
            ("Template", f"{ROUGE['template']['rouge1']:.4f}", f"{ROUGE['template']['rouge2']:.4f}", f"{ROUGE['template']['rougeL']:.4f}"),
            ("Extractive", f"{ROUGE['extractive']['rouge1']:.4f}", f"{ROUGE['extractive']['rouge2']:.4f}", f"{ROUGE['extractive']['rougeL']:.4f}"),
            ("DistilBART", f"{ROUGE['abstractive']['rouge1']:.4f}", f"{ROUGE['abstractive']['rouge2']:.4f}", f"{ROUGE['abstractive']['rougeL']:.4f}")]
    tbl = slide.shapes.add_table(4, 4, Inches(rx), Inches(20.6), Inches(rw), Inches(2.6)).table
    widths = [3.25, 2.22, 2.22, 2.22]
    for j, wv in enumerate(widths):
        tbl.columns[j].width = Inches(wv)
    for i, row in enumerate(rows):
        tbl.rows[i].height = Inches(0.65)
        for j, val in enumerate(row):
            cell = tbl.cell(i, j)
            cell.margin_left = cell.margin_right = Inches(0.1)
            cell.vertical_anchor = MSO_ANCHOR.MIDDLE
            tfc = cell.text_frame
            tfc.paragraphs[0].text = ""
            run = tfc.paragraphs[0].add_run()
            run.text = val
            head, best = i == 0, i == 1
            style_run(run, 30, bold=head or best, color=WHITE if head else BLACK)
            tfc.paragraphs[0].alignment = PP_ALIGN.LEFT if j == 0 else PP_ALIGN.CENTER
            cell.fill.solid()
            cell.fill.fore_color.rgb = NAVY if head else (LIGHT if best else WHITE)
    tbl.first_row = True
    caption(slide, rx, 23.28, rw, f"Mean F1 over {N['n_refs']} hand-written reference summaries; template row highlighted.",
            size=26, color=GREY, bold_prefix=False, align=PP_ALIGN.LEFT, h=0.9)
    bullets(slide, rx, 24.2, rw, 4.6, [
        ("NER:", f"micro F1 {N['ner_f1']:.3f} on {N['ner_n']} sentences."),
        ("Triples:", f"precision = recall = {N['tri_p']:.2f} on {N['tri_n']} gold sentences."),
        ("HMM vs spaCy:", f"POS agreement {N['hmm']:.3f} (our Viterbi)."),
        ("Tests:", f"{N['tests']} pytest tests pass."),
    ], size=36, space_after=8)
    cd = CategoryChartData()
    cd.categories = ["russellmitchell", "shaw"]
    cd.add_series("Incident purity", (N["rm_pur"], N["sh_pur"]))
    cd.add_series("One-group baseline", (N["rm_base"], N["sh_base"]))
    gf = slide.shapes.add_chart(XL_CHART_TYPE.COLUMN_CLUSTERED, Inches(rx), Inches(28.6), Inches(rw), Inches(6.05), cd)
    ch = gf.chart
    ch.has_legend = True
    ch.legend.position = XL_LEGEND_POSITION.BOTTOM
    ch.legend.include_in_layout = False
    ch.legend.font.size, ch.legend.font.name = Pt(26), FONT
    ch.font.name, ch.font.size = FONT, Pt(26)
    va = ch.value_axis
    va.minimum_scale, va.maximum_scale, va.major_unit = 0, 1.1, 0.25
    va.has_major_gridlines = True
    va.major_gridlines.format.line.color.rgb = RGBColor(0xD9, 0xD9, 0xD9)
    va.tick_labels.font.size, va.tick_labels.font.name = Pt(24), FONT
    va.tick_labels.number_format, va.tick_labels.number_format_is_linked = "0.00", False
    ca = ch.category_axis
    ca.tick_labels.font.size, ca.tick_labels.font.name = Pt(28), FONT
    plot = ch.plots[0]
    plot.gap_width, plot.overlap = 60, -10
    plot.has_data_labels = True
    dl = plot.data_labels
    dl.number_format, dl.number_format_is_linked = "0.000", False
    dl.position = XL_LABEL_POSITION.OUTSIDE_END
    dl.font.size, dl.font.name, dl.font.bold = Pt(26), FONT, True
    for series, color in zip(plot.series, (NAVY, RGBColor(0xA6, 0xA6, 0xA6))):
        series.format.fill.solid()
        series.format.fill.fore_color.rgb = color
    caption(slide, rx, 34.7, rw, "Fig. 4  Incident purity vs one-group baseline")

    # 9. DISCUSSIONS: Conclusion | Limitations | Future work + QR
    dy, dh, dw = 36.85, 6.65, 8.35
    bullets(slide, 0.86, dy, dw, dh, [
        (None, "A local, explainable pipeline turns tens of thousands of raw alerts into a few hundred incidents with "
               "summaries that keep the facts exact."),
        (None, "Template filling beat the extractive and DistilBART summaries on every ROUGE score."),
    ], size=38, heading="Conclusion", space_after=14)
    bullets(slide, 9.45, dy, dw, dh, [
        (None, "Gold data was labelled by one annotator."),
        (None, "The NER score is optimistic: most test sentences follow our own template."),
        (None, "Two attackers doing the same thing at the same time merge into one incident."),
    ], size=38, heading="Limitations", space_after=14)
    bullets(slide, 18.04, dy, dw, dh, [
        (None, "Live alert streams instead of uploaded files."),
        (None, "Attacker-aware clustering."),
        (None, "Domain-trained models, plus translation and speech for Unit V."),
    ], size=38, heading="Future work", space_after=14)
    qr_png = IMG / "qr_repo.png"
    segno.make(REPO_URL, error="m").save(str(qr_png), scale=24, border=1, dark="#1F2A44")
    qs = 5.3
    slide.shapes.add_picture(str(qr_png), Inches(26.85), Inches(36.95), Inches(qs), Inches(qs))
    caption(slide, 26.15, 36.95 + qs + 0.08, 6.7, "Scan for the code and results", size=30, bold_prefix=False)

    # 10. credit line above the ornament
    caption(slide, 0.5, 43.55, 32.1,
            "Dataset: Landauer et al., AIT Alert Data Set (AIT-ADS), Zenodo 8263181, CC BY 4.0.   "
            "Code: github.com/Abin-Shaji-Thomas/Cybersecurity-Alert-Summarizer",
            size=24, color=GREY, bold_prefix=False)

    prs.save(str(OUT_PPTX))
    print(f"saved {OUT_PPTX}  (team line {team_pt} pt, supervisor {sup_pt} pt, third line {third_pt} pt)")


def export_pdf():
    """Export with PowerPoint (COM, through PowerShell). 32 = ppSaveAsPDF."""
    ps = (f"$p = New-Object -ComObject PowerPoint.Application; "
          f"$d = $p.Presentations.Open('{OUT_PPTX}', $true, $false, $false); "
          f"$d.SaveAs('{OUT_PDF}', 32); $d.Close(); $p.Quit()")
    r = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True)
    if r.returncode != 0 or not OUT_PDF.exists():
        print("PDF export failed (is PowerPoint installed?):", r.stderr.strip()[:300])
        return False
    print(f"saved {OUT_PDF}")
    return True


if __name__ == "__main__":
    build()
    if "--no-pdf" not in sys.argv:
        export_pdf()
