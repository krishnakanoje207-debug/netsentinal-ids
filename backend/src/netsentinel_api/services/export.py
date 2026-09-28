"""Turning alerts into a file somebody can take away.

CSV first. An export exists to leave this system - into a spreadsheet, an
appendix, a mail to whoever owns the host - and CSV is the one format that opens in
all of those without a library that can break. The dashboard already renders the
alert; this is for the readers who do not have it. A PDF of the same rows is
offered for the reader who will print it or file it, and it says which filters
produced it, because a printed table cannot be re-filtered.

**The rule that shapes this module: a spreadsheet executes what it opens.** A cell
beginning ``=``, ``+``, ``-``, ``@`` or a control character is a formula to Excel and
LibreOffice, and almost everything interesting in an alert was written by whoever
sent the traffic. ``=HYPERLINK`` in a hostname, or a ``+`` expression referencing a
remote file, is an injection that runs on the analyst's laptop rather than on the
sensor - and unlike the Copilot's prompt injection, the worst case here is not a
misleading paragraph. So every field is neutralised on the way out, whatever this
system believes about where it came from.

An empty field means no value, and that is not the same as zero. The dashboard shows
a missing risk score as a dash for the same reason; in a CSV the conventional
spelling is an empty cell, because ``--`` is a string to every tool that reads one.
"""

from __future__ import annotations

import csv
import io
from datetime import datetime

from fpdf import FPDF

#: The header row, and the order the fields are written in.
COLUMNS = (
    "alert_id",
    "created_at",
    "severity",
    "status",
    "source",
    "src_ip",
    "dst_ip",
    "mitre_technique",
    "risk_score",
    "model",
    "incident_id",
)

#: Characters a spreadsheet treats as the start of a formula rather than as text.
FORMULA_LEAD = ("=", "+", "-", "@", "\t", "\r")


def neutralise(value: str) -> str:
    """Make a field text, whatever it starts with.

    A leading apostrophe is how a spreadsheet is told the cell is a string; it is
    not displayed, and a tool that is not a spreadsheet reads the field with one
    extra character rather than executing it. Prefixing is deliberately preferred
    to stripping: an indicator value that had its leading character removed is
    evidence that has been quietly altered.
    """
    return f"'{value}" if value.startswith(FORMULA_LEAD) else value


def _cell(value: object, guard: bool = True) -> str:
    """One value, as it is written into the file.

    ``guard=False`` for the PDF, which nothing executes: an apostrophe there would
    only be the value, altered.
    """
    if value is None:
        # An empty cell, not "None" and not a dash. See the module docstring.
        return ""
    if isinstance(value, datetime):
        # ISO 8601, and kept in UTC. A local-time export is one nobody can line up
        # against the sensor's logs afterwards.
        return value.isoformat()
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float):
        return f"{value:.4f}"
    return neutralise(str(value)) if guard else str(value)


def alerts_csv(rows: list[dict]) -> str:
    """The export, as one string.

    Built in memory rather than streamed. The row count is capped by the caller, so
    the size of this string is bounded and knowable, and a streamed response whose
    generator outlives the database session it reads from is a harder bug than the
    memory it would save on a file of a few hundred kilobytes.
    """
    buffer = io.StringIO()
    # RFC 4180 line endings, which is what a spreadsheet expects regardless of the
    # platform the file was written on.
    writer = csv.writer(buffer, lineterminator="\r\n")
    writer.writerow(COLUMNS)
    for row in rows:
        writer.writerow([_cell(row.get(column)) for column in COLUMNS])
    return buffer.getvalue()


#: Column widths in the PDF, in millimetres, in COLUMNS order. They add up to the
#: width of a landscape A4 page inside its margins.
PDF_WIDTHS = (15, 42, 17, 38, 18, 30, 30, 23, 15, 30, 19)


def _latin1(text: str) -> str:
    """What the PDF's built-in font can draw. Anything else becomes a ``?``, rather
    than failing the whole export over one hostname."""
    return text.encode("latin-1", "replace").decode("latin-1")


def alerts_pdf(rows: list[dict], filters: dict[str, str | None], now: datetime) -> bytes:
    """The same rows as the CSV, as a printable table under the filters that chose them."""
    pdf = FPDF(orientation="landscape", format="A4")
    pdf.set_auto_page_break(auto=True, margin=10)
    pdf.set_margins(10, 10)
    pdf.add_page()

    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 8, "NetSentinel alert export", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", size=9)
    used = ", ".join(f"{k}={v}" for k, v in filters.items() if v) or "none"
    pdf.cell(0, 5, _latin1(f"Filters: {used}"), new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 5, f"Generated: {now.isoformat()}  |  Rows: {len(rows)}",
             new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)

    pdf.set_font("Helvetica", size=7)
    with pdf.table(col_widths=PDF_WIDTHS, text_align="LEFT", line_height=4) as table:
        table.row(COLUMNS)
        for row in rows:
            table.row([_latin1(_cell(row.get(column), guard=False)) for column in COLUMNS])
    return bytes(pdf.output())


def filename(now: datetime, truncated: bool, extension: str = "csv") -> str:
    """What the browser saves the file as.

    The truncation travels in the name rather than only in a response header,
    because the person who has to know is whoever opens the file next week. A
    header is gone by then, and a partial export that does not say it is partial is
    evidence that misleads by omission.
    """
    stamp = now.strftime("%Y%m%d-%H%M%S")
    suffix = "-truncated" if truncated else ""
    return f"netsentinel-alerts-{stamp}{suffix}.{extension}"
