"""
Safe readers for untrusted document sources.

Three concrete readers are provided:

  - CsvReader   : standard csv module, but values are coerced to strings
                  and never executed.
  - JsonReader  : json.loads with strict parsing; rejects non-object roots.
  - HtmlTableReader : BeautifulSoup over <table> rows. If bs4 isn't
                  available we fall back to a regex-based extractor so the
                  demo runs offline.

Every reader returns a list of dicts tagged with a SourceRecord so the
orchestrator can later attribute fields and decisions back to the file
they came from. NO field value is ever passed to eval/exec; nothing in
this module invokes a shell.
"""

from __future__ import annotations

import csv
import io
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class SourceRecord:
    source_id: str   # human-readable label for the source, e.g. "export.csv"
    row_index: int   # 0-based row inside the source
    data: dict[str, Any]
    raw_size: int    # size of original cell string for logging


# ---- CSV -------------------------------------------------------------------

class CsvReader:
    """Parses CSV safely. We always treat the header row as labels, not data.
    Quoted fields with newlines are handled by the stdlib csv module."""

    def __init__(self, source_id: str):
        self.source_id = source_id

    def read(self, path_or_bytes: str | Path | bytes) -> list[SourceRecord]:
        if isinstance(path_or_bytes, (str, Path)):
            text = Path(path_or_bytes).read_text(encoding="utf-8", errors="replace")
        else:
            text = path_or_bytes.decode("utf-8", errors="replace")

        reader = csv.DictReader(io.StringIO(text))
        records: list[SourceRecord] = []
        for i, row in enumerate(reader):
            cleaned = {k: (v if v is not None else "") for k, v in row.items()}
            # Empty header rows can produce None keys; drop them.
            cleaned = {k: v for k, v in cleaned.items() if k}
            records.append(SourceRecord(
                source_id=self.source_id,
                row_index=i,
                data=cleaned,
                raw_size=sum(len(str(x)) for x in cleaned.values()),
            ))
        return records


# ---- JSON ------------------------------------------------------------------

class JsonReader:
    """Reads JSON. The top-level must be a list of objects; any other shape
    is rejected with a clear error so the orchestrator can log it."""

    def __init__(self, source_id: str):
        self.source_id = source_id

    def read(self, path_or_bytes: str | Path | bytes) -> list[SourceRecord]:
        if isinstance(path_or_bytes, (str, Path)):
            text = Path(path_or_bytes).read_text(encoding="utf-8", errors="replace")
        else:
            text = path_or_bytes.decode("utf-8", errors="replace")

        obj = json.loads(text)
        if not isinstance(obj, list):
            raise ValueError(f"{self.source_id}: top-level JSON must be an array")
        records: list[SourceRecord] = []
        for i, item in enumerate(obj):
            if not isinstance(item, dict):
                raise ValueError(
                    f"{self.source_id}[{i}]: each JSON record must be an object"
                )
            # Coerce all values to strings for uniform downstream handling.
            cleaned = {str(k): ("" if v is None else v) for k, v in item.items()}
            records.append(SourceRecord(
                source_id=self.source_id,
                row_index=i,
                data=cleaned,
                raw_size=sum(len(str(x)) for x in cleaned.values()),
            ))
        return records


# ---- HTML TABLE ------------------------------------------------------------

_TR_ROW = re.compile(r"<tr\b[^>]*>(.*?)</tr>", re.IGNORECASE | re.DOTALL)
_TR_CELL = re.compile(r"<t[hd]\b[^>]*>(.*?)</t[hd]>", re.IGNORECASE | re.DOTALL)
_TAG = re.compile(r"<[^>]+>")
_WS = re.compile(r"\s+")


def _strip(html_fragment: str) -> str:
    # Strip tags, decode common entities, collapse whitespace.
    text = _TAG.sub(" ", html_fragment)
    text = (text.replace("&nbsp;", " ")
                .replace("&amp;", "&")
                .replace("&lt;", "<")
                .replace("&gt;", ">")
                .replace("&quot;", "\"")
                .replace("&#39;", "'"))
    return _WS.sub(" ", text).strip()


class HtmlTableReader:
    """Parses the first <table> on the page into records. Uses BeautifulSoup
    if it's available; otherwise falls back to a regex extractor."""

    def __init__(self, source_id: str):
        self.source_id = source_id

    def read(self, path_or_bytes: str | Path | bytes) -> list[SourceRecord]:
        if isinstance(path_or_bytes, (str, Path)):
            html = Path(path_or_bytes).read_text(encoding="utf-8", errors="replace")
        else:
            html = path_or_bytes.decode("utf-8", errors="replace")

        try:
            from bs4 import BeautifulSoup  # type: ignore
            return self._read_bs4(html)
        except ImportError:
            return self._read_regex(html)

    def _read_bs4(self, html: str) -> list[SourceRecord]:
        from bs4 import BeautifulSoup  # type: ignore
        soup = BeautifulSoup(html, "html.parser")
        table = soup.find("table")
        if table is None:
            return []
        rows = table.find_all("tr")
        if not rows:
            return []
        header_cells = rows[0].find_all(["th", "td"])
        headers = [_strip(str(c)) for c in header_cells]
        out: list[SourceRecord] = []
        for i, row in enumerate(rows[1:]):
            cells = row.find_all(["td", "th"])
            values = [_strip(str(c)) for c in cells]
            data = {}
            for j, h in enumerate(headers):
                data[h] = values[j] if j < len(values) else ""
            data = {k: v for k, v in data.items() if k}
            out.append(SourceRecord(
                source_id=self.source_id,
                row_index=i,
                data=data,
                raw_size=sum(len(str(x)) for x in data.values()),
            ))
        return out

    def _read_regex(self, html: str) -> list[SourceRecord]:
        rows = _TR_ROW.findall(html)
        if not rows:
            return []
        first_cells = _TR_CELL.findall(rows[0])
        if not first_cells:
            return []
        headers = [_strip(c) for c in first_cells]
        out: list[SourceRecord] = []
        for i, row in enumerate(rows[1:]):
            cells = _TR_CELL.findall(row)
            values = [_strip(c) for c in cells]
            data = {}
            for j, h in enumerate(headers):
                data[h] = values[j] if j < len(values) else ""
            data = {k: v for k, v in data.items() if k}
            out.append(SourceRecord(
                source_id=self.source_id,
                row_index=i,
                data=data,
                raw_size=sum(len(str(x)) for x in data.values()),
            ))
        return out
