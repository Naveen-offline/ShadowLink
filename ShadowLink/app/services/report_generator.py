"""PDF report generation with ReportLab. All text is escaped before rendering."""
from datetime import datetime, timezone
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def _p(text, style):
    return Paragraph(escape(str(text)), style)


def generate_pdf(scan, path) -> str:
    d = scan.details
    risk = d.get("risk", {})
    ss = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=ss["Heading1"], textColor=colors.HexColor("#0B3C5D"))
    h2 = ParagraphStyle("h2", parent=ss["Heading2"], textColor=colors.HexColor("#0B3C5D"), spaceBefore=10)
    body = ParagraphStyle("b", parent=ss["BodyText"], fontSize=9, leading=12)
    small = ParagraphStyle("s", parent=body, fontSize=8, textColor=colors.HexColor("#555555"))

    def table(rows, widths=(55 * mm, 115 * mm)):
        t = Table([[_p(a, body), _p(b, body)] for a, b in rows], colWidths=list(widths))
        t.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#BBBBBB")),
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#EEF3F7")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        return t

    doc = SimpleDocTemplate(str(path), pagesize=A4, title=f"ShadowLink Report #{scan.id}",
                            leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm, bottomMargin=16 * mm)
    s = []
    s.append(_p("ShadowLink Security Analysis Report", h1))
    s.append(table([
        ("Scan ID", scan.id),
        ("Submitted URL", scan.submitted_url),
        ("Normalized URL", scan.normalized_url),
        ("Registered domain", scan.registered_domain),
        ("Scanned at (UTC)", scan.created_at.strftime("%Y-%m-%d %H:%M:%S")),
        ("Report generated", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")),
    ]))
    s.append(_p("Risk assessment", h2))
    s.append(table([
        ("Risk score", f"{risk.get('score', 'n/a')} / 100"),
        ("Category", risk.get("category", "n/a")),
        ("Checks that could not run", ", ".join(risk.get("unavailable_checks", [])) or "None"),
    ]))
    s.append(Spacer(1, 3 * mm))
    s.append(_p(risk.get("disclaimer", ""), small))

    if risk.get("top_contributors"):
        s.append(_p("Main contributing indicators", h2))
        s.append(table([(f"{c['group']} (+{c['points']})", c["reason"]) for c in risk["top_contributors"]]))

    s.append(_p("URL structure indicators", h2))
    inds = d.get("indicators", [])
    s.append(table([(i["indicator_name"] + f" [{i['severity']}]", i["explanation"]) for i in inds])
              if inds else _p("No notable structural indicators observed.", body))

    dom = d.get("domain", {})
    s.append(_p("Domain intelligence", h2))
    s.append(table([
        ("Hostname", dom.get("hostname")),
        ("Resolved IPs", ", ".join(dom.get("resolved_ips", [])) or "Unavailable"),
        ("Nameservers", ", ".join(dom.get("nameservers", [])) or "Unavailable"),
        ("Creation date", dom.get("creation_date") or "Unavailable"),
        ("Domain age (days)", dom.get("domain_age_days") if dom.get("domain_age_days") is not None else "Unavailable"),
        ("Notes", "; ".join(dom.get("notes", [])) or "None"),
    ]))

    tls = d.get("tls", {})
    s.append(_p("Certificate analysis", h2))
    s.append(table([("Status", tls.get("status")), ("Issuer", tls.get("issuer") or "n/a"),
                    ("Valid until", tls.get("not_after") or "n/a"), ("Message", tls.get("message"))]))

    red = d.get("redirects", {})
    s.append(_p("Redirect analysis", h2))
    s.append(table([("Performed", "Yes" if red.get("performed") else "No"), ("Message", red.get("message")),
                    ("Hops", red.get("hops", 0)), ("Flags", "; ".join(red.get("flags", [])) or "None")]))

    ml = d.get("ml", {})
    s.append(_p("Machine-learning assessment", h2))
    if ml.get("available"):
        s.append(table([("Predicted class", ml.get("predicted_class")), ("Model score", ml.get("phishing_score")),
                        ("Model", f"{ml.get('model_name')} v{ml.get('model_version')}"),
                        ("Note", ml.get("score_note"))]))
    else:
        s.append(_p("Model unavailable: " + str(ml.get("message", "")), body))

    s.append(_p("Recommendations", h2))
    for r in d.get("recommendations", []):
        s.append(_p("• " + r, body))
    s.append(Spacer(1, 4 * mm))
    s.append(_p("ShadowLink provides an automated, limited estimate. It cannot guarantee that any URL is safe.", small))
    doc.build(s)
    return str(path)
