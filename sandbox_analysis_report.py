#!/usr/bin/env python3
"""Generate sandbox operational reports from WEB and SANDBOX_VERDICT CSV exports."""

from __future__ import annotations

import argparse
import csv
import html
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from statistics import mean, median
from urllib.parse import urlsplit


MISSING_VALUES = {"", "none", "n/a", "na", "null", "-"}
WEB_TIME_COLUMN = "Event Time"
SLA_BUCKETS = (
    ("<= 1m", 60),
    ("1-5m", 300),
    ("5-10m", 600),
    ("> 10m", None),
)
SIZE_BUCKET_ORDER = ("Unknown", "< 1 MB", "1-10 MB", "10-50 MB", "50-100 MB", ">= 100 MB")
BLOCK_ACTION_MARKERS = ("block", "deny", "denied", "drop", "reset")
TZ_OFFSETS = {
    "UTC": 0,
    "GMT": 0,
    "CET": 1,
    "CEST": 2,
    "EST": -5,
    "EDT": -4,
    "CST": -6,
    "CDT": -5,
    "MST": -7,
    "MDT": -6,
    "PST": -8,
    "PDT": -7,
}
DATE_FORMATS = (
    "%B %d, %Y %I:%M:%S %p",
    "%b %d, %Y %I:%M:%S %p",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%m/%d/%Y %I:%M:%S %p",
    "%m/%d/%Y %H:%M:%S",
)


def clean(value: object) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    return "" if text.lower() in MISSING_VALUES else text


def normalize_md5(value: object) -> str:
    text = clean(value).lower()
    if not text:
        return ""
    return text if re.fullmatch(r"[0-9a-f]{32}", text) else text


def parse_timezone(zone_text: str) -> timezone:
    zone_text = zone_text.strip().upper()
    if zone_text in TZ_OFFSETS:
        return timezone(timedelta(hours=TZ_OFFSETS[zone_text]), zone_text)

    match = re.fullmatch(r"([+-])(\d{2}):?(\d{2})", zone_text)
    if match:
        sign, hours, minutes = match.groups()
        offset = timedelta(hours=int(hours), minutes=int(minutes))
        if sign == "-":
            offset = -offset
        return timezone(offset, zone_text)

    raise ValueError(f"unsupported timezone {zone_text!r}")


def parse_timestamp(value: object) -> datetime:
    text = clean(value)
    if not text:
        raise ValueError("empty timestamp")

    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is not None:
            return parsed.astimezone(timezone.utc)
    except ValueError:
        pass

    zone_match = re.match(r"^(?P<date>.+?)\s+(?P<zone>[A-Za-z]{2,5}|[+-]\d{2}:?\d{2})$", text)
    if zone_match:
        date_text = zone_match.group("date")
        parsed_tz = parse_timezone(zone_match.group("zone"))
    else:
        date_text = text
        parsed_tz = timezone.utc

    for fmt in DATE_FORMATS:
        try:
            return datetime.strptime(date_text, fmt).replace(tzinfo=parsed_tz).astimezone(timezone.utc)
        except ValueError:
            continue

    raise ValueError(f"unsupported timestamp format {text!r}")


def read_export_csv(path: Path) -> tuple[list[str], list[dict[str, str]], int]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.reader(handle)
        header = None
        header_line = 0

        for line_number, row in enumerate(reader, start=1):
            if row and row[0].lstrip("\ufeff").strip() == "No.":
                header = [cell.lstrip("\ufeff").strip() for cell in row]
                header_line = line_number
                break

        if header is None:
            raise SystemExit(f"{path}: could not find CSV header row starting with 'No.'")

        rows: list[dict[str, str]] = []
        for line_number, row in enumerate(reader, start=header_line + 1):
            if not row or not any(clean(cell) for cell in row):
                continue
            padded = row + [""] * max(0, len(header) - len(row))
            record = dict(zip(header, padded[: len(header)]))
            record["_source_line"] = str(line_number)
            rows.append(record)

    return header, rows, header_line


def require_columns(path: Path, header: list[str], required: list[str]) -> None:
    missing = [column for column in required if column not in header]
    if missing:
        available = ", ".join(header)
        raise SystemExit(f"{path}: missing required columns: {', '.join(missing)}\nAvailable columns: {available}")


def web_sandbox_result(row: dict[str, str] | None) -> str:
    return clean((row or {}).get("Threat Category"))


def is_sent_for_analysis(result: str) -> bool:
    return result.strip().lower() == "sent for analysis"


def parse_int(value: object) -> int | None:
    text = clean(value)
    if not text:
        return None
    try:
        return int(float(text.replace(",", "")))
    except ValueError:
        return None


def choose_earliest(rows: list[dict[str, str]], time_column: str) -> tuple[dict[str, str] | None, datetime | None, list[str]]:
    errors: list[str] = []
    choices: list[tuple[datetime, dict[str, str]]] = []

    for row in rows:
        try:
            choices.append((parse_timestamp(row.get(time_column)), row))
        except ValueError as exc:
            row_number = row.get("No.") or row.get("_source_line") or "?"
            errors.append(f"row {row_number}: {time_column}: {exc}")

    if not choices:
        return (rows[0] if rows else None), None, errors

    selected_time, selected_row = min(choices, key=lambda item: item[0])
    return selected_row, selected_time, errors


def choose_web_download_event(
    rows: list[dict[str, str]],
    completed_time: datetime | None,
) -> tuple[dict[str, str] | None, datetime | None, list[str], str]:
    errors: list[str] = []
    choices: list[tuple[datetime, dict[str, str]]] = []

    for row in rows:
        try:
            choices.append((parse_timestamp(row.get(WEB_TIME_COLUMN)), row))
        except ValueError as exc:
            row_number = row.get("No.") or row.get("_source_line") or "?"
            errors.append(f"row {row_number}: {WEB_TIME_COLUMN}: {exc}")

    if not choices:
        return (rows[0] if rows else None), None, errors, "no_valid_web_event_time"

    if completed_time is not None:
        before_completion = [(event_time, row) for event_time, row in choices if event_time <= completed_time]
        if before_completion:
            selected_time, selected_row = max(before_completion, key=lambda item: item[0])
            return selected_row, selected_time, errors, "latest_event_before_analysis_completed"
        selected_time, selected_row = min(choices, key=lambda item: item[0])
        return selected_row, selected_time, errors, "earliest_event_no_event_before_analysis_completed"

    known_decisions = [
        (event_time, row)
        for event_time, row in choices
        if web_sandbox_result(row) and not is_sent_for_analysis(web_sandbox_result(row))
    ]
    if known_decisions:
        selected_time, selected_row = max(known_decisions, key=lambda item: item[0])
        return selected_row, selected_time, errors, "latest_known_web_decision_no_analysis_completed_time"

    selected_time, selected_row = min(choices, key=lambda item: item[0])
    return selected_row, selected_time, errors, "earliest_event_no_analysis_completed_time"


def unique_join(rows: list[dict[str, str]], column: str, limit: int = 5) -> str:
    values: list[str] = []
    seen: set[str] = set()
    for row in rows:
        value = clean(row.get(column))
        if value and value not in seen:
            values.append(value)
            seen.add(value)
        if len(values) >= limit:
            break
    return "; ".join(values)


def extract_destination_domain(url: object) -> str:
    text = clean(url)
    if not text:
        return ""

    candidate = text if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", text) else f"//{text}"
    parsed = urlsplit(candidate)
    host = parsed.hostname or ""
    if not host and parsed.netloc:
        host = parsed.netloc.rsplit("@", 1)[-1].split(":", 1)[0]
    return host.rstrip(".").lower()


def destination_domain(web_group: list[dict[str, str]], selected_web_row: dict[str, str] | None) -> str:
    selected_domain = extract_destination_domain((selected_web_row or {}).get("URL"))
    if selected_domain:
        return selected_domain
    for row in web_group:
        domain = extract_destination_domain(row.get("URL"))
        if domain:
            return domain
    return "Unknown"


def is_blocked_web_row(row: dict[str, str] | None) -> bool:
    if not row:
        return False

    if clean(row.get("Blocked Policy Name")) or clean(row.get("Blocked Policy Type")):
        return True

    policy_action = clean(row.get("Policy Action")).lower()
    return any(marker in policy_action for marker in BLOCK_ACTION_MARKERS)


def sent_for_analysis_event_summary(rows: list[dict[str, str]], completed_time: datetime | None) -> dict[str, str]:
    sent_rows = [row for row in rows if is_sent_for_analysis(web_sandbox_result(row))]
    relevant_rows: list[dict[str, str]] = []

    for row in sent_rows:
        if completed_time is None:
            relevant_rows.append(row)
            continue
        try:
            event_time = parse_timestamp(row.get(WEB_TIME_COLUMN))
        except ValueError:
            continue
        if event_time <= completed_time:
            relevant_rows.append(row)

    relevant_count = len(relevant_rows)
    return {
        "sent_for_analysis_event_count": str(len(sent_rows)),
        "sent_for_analysis_before_completion_count": str(relevant_count),
        "repeated_sent_for_analysis": "yes" if relevant_count > 1 else "no",
        "sent_for_analysis_extra_events": str(max(0, relevant_count - 1)),
        "sent_for_analysis_row_numbers": unique_join(relevant_rows, "No.", limit=20),
        "sent_for_analysis_event_times": unique_join(relevant_rows, WEB_TIME_COLUMN, limit=20),
    }


def format_seconds(seconds_value: float | int | None) -> str:
    if seconds_value is None:
        return ""
    sign = "-" if seconds_value < 0 else ""
    total_seconds = int(round(abs(seconds_value)))
    days, remainder = divmod(total_seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)
    parts: list[str] = []
    if days:
        parts.append(f"{days}d")
    if hours or days:
        parts.append(f"{hours}h")
    if minutes or hours or days:
        parts.append(f"{minutes}m")
    parts.append(f"{seconds}s")
    return sign + " ".join(parts)


def format_bytes(value: int | None) -> str:
    if value is None:
        return ""
    size = float(value)
    units = ["B", "KB", "MB", "GB", "TB"]
    unit = units[0]
    for unit in units:
        if size < 1024 or unit == units[-1]:
            break
        size /= 1024
    if unit == "B":
        return f"{int(size)} {unit}"
    return f"{size:.1f} {unit}"


def size_bucket(value: int | None) -> str:
    if value is None:
        return "Unknown"
    mib = value / (1024 * 1024)
    if mib < 1:
        return "< 1 MB"
    if mib < 10:
        return "1-10 MB"
    if mib < 50:
        return "10-50 MB"
    if mib < 100:
        return "50-100 MB"
    return ">= 100 MB"


def percentile(values: list[float], percentile_value: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * percentile_value
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def truncate_ascii(value: object, width: int) -> str:
    text = "" if value is None else str(value)
    text = text.replace("\r", " ").replace("\n", " ")
    if len(text) <= width:
        return text
    if width <= 3:
        return text[:width]
    return text[: width - 3] + "..."


def ascii_table(
    title: str,
    columns: list[tuple[str, str]],
    rows: list[dict[str, object]],
    max_widths: dict[str, int] | None = None,
) -> list[str]:
    max_widths = max_widths or {}
    if not rows:
        rows = [{"message": "No data"}]
        columns = [("message", "Message")]

    widths: dict[str, int] = {}
    for key, label in columns:
        natural_width = len(label)
        for row in rows:
            natural_width = max(natural_width, len(str(row.get(key, ""))))
        widths[key] = min(natural_width, max_widths.get(key, 72))

    border = "+" + "+".join("-" * (widths[key] + 2) for key, _ in columns) + "+"
    title_width = max(len(border) - 4, len(title))
    title_border = "+" + "-" * (title_width + 2) + "+"
    lines = [title_border, f"| {truncate_ascii(title.upper(), title_width).ljust(title_width)} |", title_border]
    lines.append(border)
    lines.append("|" + "|".join(f" {truncate_ascii(label, widths[key]).ljust(widths[key])} " for key, label in columns) + "|")
    lines.append(border)
    for row in rows:
        lines.append(
            "|"
            + "|".join(
                f" {truncate_ascii(row.get(key, ''), widths[key]).ljust(widths[key])} "
                for key, _ in columns
            )
            + "|"
        )
    lines.append(border)
    return lines


def duration_stats(values: list[float]) -> dict[str, float | int | None]:
    if not values:
        return {"count": 0, "avg": None, "median": None, "p90": None, "min": None, "max": None}
    return {
        "count": len(values),
        "avg": mean(values),
        "median": median(values),
        "p90": percentile(values, 0.90),
        "min": min(values),
        "max": max(values),
    }


def stats_lines(label: str, values: list[float]) -> list[str]:
    if not values:
        return ascii_table(label, [("message", "Message")], [{"message": "No matched files with valid non-negative durations"}])
    stats = duration_stats(values)
    rows = [
        {"metric": "Count", "value": stats["count"], "seconds": ""},
        {"metric": "Average", "value": format_seconds(stats["avg"]), "seconds": f"{stats['avg']:.1f}s"},
        {"metric": "Median", "value": format_seconds(stats["median"]), "seconds": f"{stats['median']:.1f}s"},
        {"metric": "Min", "value": format_seconds(stats["min"]), "seconds": f"{stats['min']:.1f}s"},
        {"metric": "Max", "value": format_seconds(stats["max"]), "seconds": f"{stats['max']:.1f}s"},
        {"metric": "P90", "value": format_seconds(stats["p90"]), "seconds": f"{stats['p90']:.1f}s"},
    ]
    return ascii_table(label, [("metric", "Metric"), ("value", "Value"), ("seconds", "Seconds")], rows)


def grouped_stats_lines(label: str, grouped_values: dict[str, list[float]]) -> list[str]:
    if not grouped_values:
        return ascii_table(label, [("message", "Message")], [{"message": "No matched files with valid non-negative durations"}])
    rows: list[dict[str, object]] = []
    for group, values in sorted(grouped_values.items(), key=lambda item: (-len(item[1]), item[0])):
        stats = duration_stats(values)
        rows.append(
            {
                "group": group,
                "count": stats["count"],
                "avg": f"{format_seconds(stats['avg'])} ({stats['avg']:.1f}s)",
                "median": f"{format_seconds(stats['median'])} ({stats['median']:.1f}s)",
                "p90": f"{format_seconds(stats['p90'])} ({stats['p90']:.1f}s)",
                "min": f"{format_seconds(stats['min'])} ({stats['min']:.1f}s)",
                "max": f"{format_seconds(stats['max'])} ({stats['max']:.1f}s)",
            }
        )
    return ascii_table(
        label,
        [("group", "Group"), ("count", "Count"), ("avg", "Avg"), ("median", "Median"), ("p90", "P90"), ("min", "Min"), ("max", "Max")],
        rows,
        {"group": 42},
    )


def grouped_counter_lines(label: str, grouped_counts: dict[str, Counter[str]]) -> list[str]:
    if not grouped_counts:
        return ascii_table(label, [("message", "Message")], [{"message": "No file types"}])
    rows = []
    for group, counts in sorted(grouped_counts.items(), key=lambda item: (-sum(item[1].values()), item[0])):
        rows.append(
            {
                "group": group,
                "total": sum(counts.values()),
                "counts": ", ".join(f"{status}={count}" for status, count in sorted(counts.items())),
            }
        )
    return ascii_table(label, [("group", "Group"), ("total", "Total"), ("counts", "Counts")], rows, {"group": 42, "counts": 64})


def detail_duration(row: dict[str, str]) -> float | None:
    value = parse_int(row.get("duration_seconds"))
    if value is None or value < 0:
        return None
    return float(value)


def duration_rows(rows: list[dict[str, str]], include_known_by_cloud: bool = True) -> list[tuple[dict[str, str], float]]:
    output: list[tuple[dict[str, str], float]] = []
    for row in rows:
        if not include_known_by_cloud and row.get("status") == "known_by_cloud":
            continue
        duration = detail_duration(row)
        if duration is not None:
            output.append((row, duration))
    return output


def group_duration_values(rows: list[dict[str, str]], key: str, include_known_by_cloud: bool = True) -> dict[str, list[float]]:
    grouped: dict[str, list[float]] = defaultdict(list)
    for row, duration in duration_rows(rows, include_known_by_cloud):
        grouped[clean(row.get(key)) or "Unknown"].append(duration)
    return grouped


def group_status_counts(rows: list[dict[str, str]], key: str) -> dict[str, Counter[str]]:
    grouped: dict[str, Counter[str]] = defaultdict(Counter)
    for row in rows:
        grouped[clean(row.get(key)) or "Unknown"][clean(row.get("status")) or "unknown"] += 1
    return grouped


def sla_counts(rows: list[dict[str, str]], include_known_by_cloud: bool = True) -> Counter[str]:
    counts: Counter[str] = Counter()
    for _, duration in duration_rows(rows, include_known_by_cloud):
        for label, max_seconds in SLA_BUCKETS:
            if max_seconds is None or duration <= max_seconds:
                counts[label] += 1
                break
    return counts


def verdict_by_file_type(rows: list[dict[str, str]]) -> dict[str, Counter[str]]:
    grouped: dict[str, Counter[str]] = defaultdict(Counter)
    for row in rows:
        grouped[clean(row.get("download_file_type")) or "Unknown"][clean(row.get("verdict")) or "No verdict"] += 1
    return grouped


def grouped_operational_rows(rows: list[dict[str, str]], key: str) -> list[dict[str, str]]:
    status_by_group = group_status_counts(rows, key)
    durations_by_group = group_duration_values(rows, key, include_known_by_cloud=False)
    output: list[dict[str, str]] = []
    for group, counts in sorted(status_by_group.items(), key=lambda item: (-sum(item[1].values()), item[0])):
        stats = duration_stats(durations_by_group.get(group, []))
        output.append(
            {
                "group": group,
                "total": str(sum(counts.values())),
                "known_by_cloud": str(counts.get("known_by_cloud", 0)),
                "sandboxed": str(sum(count for status, count in counts.items() if status.startswith("matched"))),
                "canceled_or_incomplete": str(counts.get("canceled_or_incomplete", 0)),
                "avg_sandbox": format_seconds(stats["avg"]) if stats["avg"] is not None else "",
                "p90_sandbox": format_seconds(stats["p90"]) if stats["p90"] is not None else "",
                "max_sandbox": format_seconds(stats["max"]) if stats["max"] is not None else "",
            }
        )
    return output


def top_slowest_rows(rows: list[dict[str, str]], limit: int = 10) -> list[dict[str, str]]:
    sorted_rows = sorted(duration_rows(rows, include_known_by_cloud=False), key=lambda item: item[1], reverse=True)
    output: list[dict[str, str]] = []
    for row, duration in sorted_rows[:limit]:
        output.append(
            {
                "duration": format_seconds(duration),
                "file_name": clean(row.get("download_file_name")) or "(unknown filename)",
                "file_type": clean(row.get("download_file_type")) or "Unknown",
                "size": clean(row.get("received_bytes_human")),
                "verdict": clean(row.get("verdict")) or "No verdict",
                "status": clean(row.get("status")),
                "event_time": clean(row.get("download_time")),
                "md5": clean(row.get("md5")),
            }
        )
    return output


def repeated_sent_for_analysis_rows(rows: list[dict[str, str]], limit: int | None = None) -> list[dict[str, str]]:
    repeated_rows = [row for row in rows if clean(row.get("repeated_sent_for_analysis")).lower() == "yes"]
    repeated_rows.sort(
        key=lambda row: (
            parse_int(row.get("sent_for_analysis_before_completion_count")) or 0,
            detail_duration(row) or -1,
        ),
        reverse=True,
    )
    output: list[dict[str, str]] = []
    for row in repeated_rows[:limit]:
        output.append(
            {
                "sent_for_analysis_count": clean(row.get("sent_for_analysis_before_completion_count")),
                "extra_events": clean(row.get("sent_for_analysis_extra_events")),
                "duration": clean(row.get("duration_human")),
                "file_name": clean(row.get("download_file_name")) or "(unknown filename)",
                "file_type": clean(row.get("download_file_type")) or "Unknown",
                "verdict": clean(row.get("verdict")) or "No verdict",
                "status": clean(row.get("status")),
                "event_rows": clean(row.get("sent_for_analysis_row_numbers")),
                "event_times": clean(row.get("sent_for_analysis_event_times")),
                "md5": clean(row.get("md5")),
            }
        )
    return output


def canceled_or_incomplete_rows(rows: list[dict[str, str]], limit: int | None = None) -> list[dict[str, str]]:
    flagged_rows = [row for row in rows if clean(row.get("canceled_or_incomplete")).lower() == "yes"]
    flagged_rows.sort(
        key=lambda row: (
            clean(row.get("canceled_or_incomplete_reason")),
            parse_int(row.get("sent_for_analysis_event_count")) or 0,
            clean(row.get("download_time_utc")),
        ),
        reverse=True,
    )
    output: list[dict[str, str]] = []
    for row in flagged_rows[:limit]:
        output.append(
            {
                "reason": clean(row.get("canceled_or_incomplete_reason")),
                "sent_for_analysis_count": clean(row.get("sent_for_analysis_event_count")),
                "status": clean(row.get("status")),
                "verdict": clean(row.get("verdict")) or "No verdict",
                "file_name": clean(row.get("download_file_name")) or "(unknown filename)",
                "file_type": clean(row.get("download_file_type")) or "Unknown",
                "event_rows": clean(row.get("sent_for_analysis_row_numbers")),
                "md5": clean(row.get("md5")),
            }
        )
    return output


def destination_domain_stats(rows: list[dict[str, str]]) -> list[dict[str, object]]:
    grouped: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        grouped[clean(row.get("destination_domain")) or "Unknown"].append(row)

    output: list[dict[str, object]] = []
    for domain, domain_rows in grouped.items():
        sandbox_rows = duration_rows(domain_rows, include_known_by_cloud=False)
        durations = [duration for _, duration in sandbox_rows]
        stats = duration_stats(durations)
        status_counts = Counter(clean(row.get("status")) or "unknown" for row in domain_rows)
        blocked_count = sum(1 for row in domain_rows if clean(row.get("blocked")).lower() == "yes")
        total_count = len(domain_rows)
        worst_row = None
        worst_duration = None
        if sandbox_rows:
            worst_row, worst_duration = max(sandbox_rows, key=lambda item: item[1])

        output.append(
            {
                "domain": domain,
                "total": total_count,
                "sandboxed": sum(count for status, count in status_counts.items() if status.startswith("matched")),
                "known_by_cloud": status_counts.get("known_by_cloud", 0),
                "canceled_or_incomplete": status_counts.get("canceled_or_incomplete", 0),
                "blocked": blocked_count,
                "block_ratio": (blocked_count / total_count) if total_count else 0.0,
                "avg_release": stats["avg"],
                "p90_release": stats["p90"],
                "worst_release": stats["max"],
                "worst_file": clean((worst_row or {}).get("download_file_name")) or "",
                "worst_verdict": clean((worst_row or {}).get("verdict")) or "",
                "worst_status": clean((worst_row or {}).get("status")) or "",
                "worst_md5": clean((worst_row or {}).get("md5")) or "",
                "worst_duration": worst_duration,
            }
        )
    return output


def format_percent(value: float | int | None) -> str:
    if value is None:
        return ""
    return f"{float(value) * 100:.1f}%"


def domain_release_rows(rows: list[dict[str, str]], limit: int = 25) -> list[dict[str, str]]:
    domain_rows = [
        row for row in destination_domain_stats(rows)
        if isinstance(row.get("worst_release"), (float, int))
    ]
    domain_rows.sort(
        key=lambda row: (
            float(row.get("worst_release") or 0),
            float(row.get("p90_release") or 0),
            float(row.get("avg_release") or 0),
            int(row.get("sandboxed") or 0),
        ),
        reverse=True,
    )
    return [format_domain_row(row) for row in domain_rows[:limit]]


def domain_block_ratio_rows(rows: list[dict[str, str]], limit: int = 25) -> list[dict[str, str]]:
    domain_rows = [row for row in destination_domain_stats(rows) if int(row.get("blocked") or 0) > 0]
    domain_rows.sort(
        key=lambda row: (
            float(row.get("block_ratio") or 0),
            int(row.get("blocked") or 0),
            int(row.get("total") or 0),
            float(row.get("worst_release") or 0),
        ),
        reverse=True,
    )
    return [format_domain_row(row) for row in domain_rows[:limit]]


def format_domain_row(row: dict[str, object]) -> dict[str, str]:
    return {
        "domain": str(row.get("domain") or "Unknown"),
        "total": str(row.get("total") or 0),
        "sandboxed": str(row.get("sandboxed") or 0),
        "known_by_cloud": str(row.get("known_by_cloud") or 0),
        "canceled_or_incomplete": str(row.get("canceled_or_incomplete") or 0),
        "blocked": str(row.get("blocked") or 0),
        "block_ratio": format_percent(float(row.get("block_ratio") or 0)),
        "avg_release": format_seconds(row.get("avg_release") if isinstance(row.get("avg_release"), (float, int)) else None),
        "p90_release": format_seconds(row.get("p90_release") if isinstance(row.get("p90_release"), (float, int)) else None),
        "worst_release": format_seconds(row.get("worst_release") if isinstance(row.get("worst_release"), (float, int)) else None),
        "worst_file": str(row.get("worst_file") or ""),
        "worst_verdict": str(row.get("worst_verdict") or ""),
        "worst_status": str(row.get("worst_status") or ""),
        "worst_md5": str(row.get("worst_md5") or ""),
    }


def escape_html(value: object) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def render_table(columns: list[tuple[str, str]], rows: list[dict[str, str]], empty_message: str = "No data") -> str:
    if not rows:
        return f'<p class="empty">{escape_html(empty_message)}</p>'
    header = "".join(f"<th>{escape_html(label)}</th>" for _, label in columns)
    body_rows = []
    for row in rows:
        cells = "".join(f"<td>{escape_html(row.get(key, ''))}</td>" for key, _ in columns)
        body_rows.append(f"<tr>{cells}</tr>")
    return f'<div class="table-wrap"><table><thead><tr>{header}</tr></thead><tbody>{"".join(body_rows)}</tbody></table></div>'


def counter_chart_items(counts: Counter[str], order: tuple[str, ...] | None = None) -> list[tuple[str, float, str]]:
    if order:
        order_set = set(order)
        labels = [label for label in order if counts.get(label)]
        labels.extend(sorted(label for label in counts if label not in order_set))
    else:
        labels = [label for label, _ in counts.most_common()]
    return [(label, float(counts[label]), f"{counts[label]} files") for label in labels]


def grouped_average_chart_items(grouped_values: dict[str, list[float]], order: tuple[str, ...] | None = None) -> list[tuple[str, float, str]]:
    if order:
        order_set = set(order)
        labels = [label for label in order if grouped_values.get(label)]
        labels.extend(sorted(label for label in grouped_values if label not in order_set))
    else:
        labels = sorted(grouped_values, key=lambda label: (-mean(grouped_values[label]), label))
    return [(label, float(mean(grouped_values[label])), f"{len(grouped_values[label])} files") for label in labels if grouped_values.get(label)]


def render_ascii_bar_table(items: list[tuple[str, float, str]], value_formatter, max_items: int = 12) -> str:
    visible_items = [(label, value, note) for label, value, note in items if value >= 0][:max_items]
    if not visible_items:
        return '<p class="empty">No data</p>'
    max_value = max(value for _, value, _ in visible_items) or 1
    rows: list[dict[str, str]] = []
    for label, value, note in visible_items:
        bar_len = int(round((value / max_value) * 32)) if value else 0
        rows.append({"label": label, "bar": "#" * max(1, bar_len) if value else "", "value": value_formatter(value), "note": note})
    return render_table([("label", "Label"), ("bar", "Bar"), ("value", "Value"), ("note", "Note")], rows)


def render_metric_table(rows: list[dict[str, str]]) -> str:
    status_counts = Counter(clean(row.get("status")) or "unknown" for row in rows)
    sandbox_values = [duration for _, duration in duration_rows(rows, include_known_by_cloud=False)]
    stats = duration_stats(sandbox_values)
    file_types = {clean(row.get("download_file_type")) or "Unknown" for row in rows}
    repeated_sent_count = sum(1 for row in rows if clean(row.get("repeated_sent_for_analysis")).lower() == "yes")
    canceled_count = sum(1 for row in rows if clean(row.get("canceled_or_incomplete")).lower() == "yes")
    metric_rows = [
        {"metric": "Total files", "value": str(len(rows)), "note": "Unique MD5 rows in report"},
        {"metric": "Sandboxed", "value": str(sum(count for status, count in status_counts.items() if status.startswith("matched"))), "note": "Matched verdict rows"},
        {"metric": "Known by cloud", "value": str(status_counts.get("known_by_cloud", 0)), "note": "Instant decisions"},
        {"metric": "Canceled/incomplete", "value": str(canceled_count), "note": "SFA with no verdict or later cloud verdict"},
        {"metric": "Repeated SFA", "value": str(repeated_sent_count), "note": "Multiple Sent for Analysis events"},
        {"metric": "Avg sandbox", "value": format_seconds(stats["avg"]), "note": "Excludes known_by_cloud"},
        {"metric": "P90 sandbox", "value": format_seconds(stats["p90"]), "note": "Excludes known_by_cloud"},
        {"metric": "Max sandbox", "value": format_seconds(stats["max"]), "note": "Excludes known_by_cloud"},
        {"metric": "File types", "value": str(len(file_types)), "note": "Observed categories"},
    ]
    return render_table([("metric", "Metric"), ("value", "Value"), ("note", "Note")], metric_rows)


def render_verdict_file_type_table(rows: list[dict[str, str]]) -> str:
    grouped = verdict_by_file_type(rows)
    verdicts = sorted({verdict for counts in grouped.values() for verdict in counts})
    table_rows: list[dict[str, str]] = []
    for file_type, counts in sorted(grouped.items(), key=lambda item: (-sum(item[1].values()), item[0])):
        row = {"file_type": file_type, "total": str(sum(counts.values()))}
        for verdict in verdicts:
            row[verdict] = str(counts.get(verdict, 0))
        table_rows.append(row)
    columns = [("file_type", "File type"), ("total", "Total")] + [(verdict, verdict) for verdict in verdicts]
    return render_table(columns, table_rows, "No verdict data")


def render_html_report(detail_rows: list[dict[str, str]], summary_text: str, web_log_path: Path, verdict_log_path: Path) -> str:
    generated_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    status_counts = Counter(clean(row.get("status")) or "unknown" for row in detail_rows)
    sla_all = sla_counts(detail_rows, include_known_by_cloud=True)
    sla_sandbox = sla_counts(detail_rows, include_known_by_cloud=False)
    file_type_sandbox = group_duration_values(detail_rows, "download_file_type", include_known_by_cloud=False)
    size_sandbox = group_duration_values(detail_rows, "download_size_bucket", include_known_by_cloud=False)
    all_stats = duration_stats([duration for _, duration in duration_rows(detail_rows, include_known_by_cloud=True)])
    sandbox_stats = duration_stats([duration for _, duration in duration_rows(detail_rows, include_known_by_cloud=False)])
    decision_summary_rows = [
        {"metric": "Including known_by_cloud avg", "value": format_seconds(all_stats["avg"])},
        {"metric": "Including known_by_cloud P90", "value": format_seconds(all_stats["p90"])},
        {"metric": "Excluding known_by_cloud avg", "value": format_seconds(sandbox_stats["avg"])},
        {"metric": "Excluding known_by_cloud P90", "value": format_seconds(sandbox_stats["p90"])},
    ]
    top_rows = top_slowest_rows(detail_rows, limit=15)
    domain_release_top = domain_release_rows(detail_rows, limit=25)
    domain_block_ratio_top = domain_block_ratio_rows(detail_rows, limit=25)
    repeated_rows = repeated_sent_for_analysis_rows(detail_rows, limit=20)
    canceled_rows = canceled_or_incomplete_rows(detail_rows, limit=20)
    location_rows = grouped_operational_rows(detail_rows, "location")[:20]
    source_rows = grouped_operational_rows(detail_rows, "source_ip_country")[:20]
    department_rows = grouped_operational_rows(detail_rows, "department")[:20]
    detail_preview = sorted(detail_rows, key=lambda row: detail_duration(row) if detail_duration(row) is not None else -1, reverse=True)[:100]

    grouped_columns = [
        ("group", "Group"),
        ("total", "Total"),
        ("known_by_cloud", "Known by cloud"),
        ("sandboxed", "Sandboxed"),
        ("canceled_or_incomplete", "Canceled/incomplete"),
        ("avg_sandbox", "Avg sandbox"),
        ("p90_sandbox", "P90 sandbox"),
        ("max_sandbox", "Max sandbox"),
    ]
    detail_columns = [
        ("duration_human", "Duration"),
        ("status", "Status"),
        ("verdict", "Verdict"),
        ("sent_for_analysis_before_completion_count", "SFA events"),
        ("canceled_or_incomplete", "Canceled/incomplete"),
        ("download_file_type", "File type"),
        ("download_file_name", "File name"),
        ("received_bytes_human", "Size"),
        ("destination_domain", "Destination domain"),
        ("policy_action", "Policy action"),
        ("blocked", "Blocked"),
        ("download_time", "Event time"),
        ("analysis_completed_time", "Completed"),
        ("md5", "MD5"),
    ]
    top_columns = [
        ("duration", "Duration"),
        ("file_name", "File name"),
        ("file_type", "File type"),
        ("size", "Size"),
        ("verdict", "Verdict"),
        ("status", "Status"),
        ("event_time", "Event time"),
        ("md5", "MD5"),
    ]
    domain_columns = [
        ("domain", "Destination domain"),
        ("total", "Files"),
        ("sandboxed", "Sandboxed"),
        ("known_by_cloud", "Known by cloud"),
        ("canceled_or_incomplete", "Canceled/incomplete"),
        ("blocked", "Blocked"),
        ("block_ratio", "Block ratio"),
        ("avg_release", "Avg release"),
        ("p90_release", "P90 release"),
        ("worst_release", "Worst release"),
        ("worst_file", "Worst file"),
        ("worst_verdict", "Worst verdict"),
    ]
    repeated_columns = [
        ("sent_for_analysis_count", "SFA events"),
        ("extra_events", "Extra"),
        ("duration", "Duration"),
        ("file_name", "File name"),
        ("file_type", "File type"),
        ("verdict", "Verdict"),
        ("status", "Status"),
        ("event_rows", "WEB rows"),
        ("event_times", "Event times"),
        ("md5", "MD5"),
    ]
    canceled_columns = [
        ("reason", "Reason"),
        ("sent_for_analysis_count", "SFA events"),
        ("status", "Status"),
        ("verdict", "Verdict"),
        ("file_name", "File name"),
        ("file_type", "File type"),
        ("event_rows", "SFA WEB rows"),
        ("md5", "MD5"),
    ]

    css = """
    :root { color-scheme: light; }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: "Courier New", Courier, ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      background: #fff;
      color: #111;
    }
    .page { max-width: 1260px; margin: 0 auto; padding: 24px; }
    header { margin-bottom: 18px; border: 1px solid #111; padding: 14px 16px; background: #fff; }
    h1 { margin: 0 0 8px; font-size: 28px; letter-spacing: 0; color: #111; font-weight: 700; text-transform: uppercase; }
    h2 { margin: 0 0 12px; font-size: 18px; letter-spacing: 0; color: #111; font-weight: 700; text-transform: uppercase; }
    .meta { color: #333; font-size: 13px; line-height: 1.55; }
    .grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 16px; }
    .panel { background: #fff; border: 1px solid #111; border-radius: 0; box-shadow: none; padding: 16px; margin-bottom: 16px; overflow: hidden; }
    .table-wrap { overflow-x: auto; border: 1px solid #111; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; color: #111; }
    th, td { text-align: left; border: 1px solid #555; padding: 8px 9px; vertical-align: top; }
    th { background: #eee; color: #111; font-size: 12px; text-transform: uppercase; letter-spacing: 0; border: 1px solid #111; }
    td { color: #111; }
    tbody tr:nth-child(even) td { background: #f7f7f7; }
    .empty { color: #333; margin: 0; }
    details summary { cursor: pointer; color: #111; font-weight: 700; margin-bottom: 12px; text-transform: uppercase; }
    pre { background: #f7f7f7; color: #111; border: 1px solid #111; padding: 14px; border-radius: 0; overflow: auto; font-size: 12px; line-height: 1.45; }
    @media (max-width: 820px) { .page { padding: 16px; } .grid { grid-template-columns: 1fr; } h1 { font-size: 24px; } }
    @media print {
      @page { size: A4 landscape; margin: 10mm; }
      * { box-shadow: none !important; text-shadow: none !important; }
      html, body { background: #fff !important; color: #111827; }
      body { margin: 0; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
      .page { max-width: none; padding: 0; }
      header, .panel { background: #fff !important; color: #111827 !important; border-color: #cbd5e1 !important; box-shadow: none !important; }
      header { margin-bottom: 10px; break-after: avoid; page-break-after: avoid; }
      h1 { font-size: 21px; margin-bottom: 4px; color: #111827 !important; }
      h2 { font-size: 14px; margin-bottom: 8px; break-after: avoid; page-break-after: avoid; color: #111827 !important; }
      .meta { font-size: 10px; line-height: 1.35; color: #374151; }
      .grid { display: block; }
      .panel { border: 1px solid #cbd5e1; border-radius: 4px; padding: 8px; margin: 0 0 8px; break-inside: avoid; page-break-inside: avoid; overflow: visible; }
      .panel.table-panel { break-inside: auto; page-break-inside: auto; }
      .table-wrap { overflow: visible; border: none !important; }
      table { table-layout: fixed; width: 100%; font-size: 8.5px; line-height: 1.2; }
      thead { display: table-header-group; }
      tr { break-inside: avoid; page-break-inside: avoid; }
      th, td { padding: 4px 5px; overflow-wrap: anywhere; word-break: break-word; hyphens: auto; }
      th { background: #eef2f7 !important; color: #111827; font-size: 7.5px; }
      td { color: #111827; background: #fff !important; }
      .empty, details summary { color: #111827 !important; }
      pre { white-space: pre-wrap; background: #f3f4f6 !important; color: #111827; border: 1px solid #d1d5db; font-size: 8px; padding: 8px; }
      details[open] { break-before: page; page-break-before: always; }
    }
    """

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Sandbox Analysis Operational Report</title>
  <style>{css}</style>
</head>
<body>
  <main class="page">
    <header>
      <h1>Sandbox Analysis Operational Report</h1>
      <div class="meta">
        Generated: {escape_html(generated_utc)}<br>
        WEB log: {escape_html(web_log_path.name)}<br>
        SANDBOX_VERDICT log: {escape_html(verdict_log_path.name)}<br>
        Download timestamp source: {escape_html(WEB_TIME_COLUMN)}
      </div>
    </header>

    <section class="panel table-panel">
      <h2>Key Metrics</h2>
      {render_metric_table(detail_rows)}
    </section>

    <section class="panel table-panel">
      <h2>Decision Duration Summary</h2>
      {render_table([("metric", "Metric"), ("value", "Value")], decision_summary_rows)}
    </section>

    <section class="grid">
      <section class="panel">
        <h2>Status Distribution</h2>
        {render_ascii_bar_table(counter_chart_items(status_counts), lambda value: f"{int(value)}")}
      </section>
      <section class="panel">
        <h2>SLA Buckets Including known_by_cloud</h2>
        {render_ascii_bar_table(counter_chart_items(sla_all, tuple(label for label, _ in SLA_BUCKETS)), lambda value: f"{int(value)}")}
      </section>
      <section class="panel">
        <h2>SLA Buckets Excluding known_by_cloud</h2>
        {render_ascii_bar_table(counter_chart_items(sla_sandbox, tuple(label for label, _ in SLA_BUCKETS)), lambda value: f"{int(value)}")}
      </section>
      <section class="panel">
        <h2>Avg Sandbox Duration by File Type</h2>
        {render_ascii_bar_table(grouped_average_chart_items(file_type_sandbox), format_seconds)}
      </section>
      <section class="panel">
        <h2>Avg Sandbox Duration by File Size</h2>
        {render_ascii_bar_table(grouped_average_chart_items(size_sandbox, SIZE_BUCKET_ORDER), format_seconds)}
      </section>
    </section>

    <section class="panel table-panel">
      <h2>Top Slowest Sandboxed Files</h2>
      {render_table(top_columns, top_rows, "No sandboxed files with measured durations")}
    </section>

    <section class="panel table-panel">
      <h2>Destination Domains by Worst Release Time</h2>
      {render_table(domain_columns, domain_release_top, "No destination domains with measured sandbox release time")}
    </section>

    <section class="panel table-panel">
      <h2>Destination Domains by Highest Block Ratio</h2>
      {render_table(domain_columns, domain_block_ratio_top, "No blocked destination domains")}
    </section>

    <section class="panel table-panel">
      <h2>Repeated Sent for Analysis Events</h2>
      {render_table(repeated_columns, repeated_rows, "No files showed Sent for Analysis more than once before completion")}
    </section>

    <section class="panel table-panel">
      <h2>Canceled or Incomplete Downloads</h2>
      {render_table(canceled_columns, canceled_rows, "No files looked canceled or incomplete")}
    </section>

    <section class="panel table-panel">
      <h2>Verdict Breakdown by File Type</h2>
      {render_verdict_file_type_table(detail_rows)}
    </section>

    <section class="grid">
      <section class="panel table-panel">
        <h2>Location Metrics</h2>
        {render_table(grouped_columns, location_rows, "No location data")}
      </section>
      <section class="panel table-panel">
        <h2>Department Metrics</h2>
        {render_table(grouped_columns, department_rows, "No department data")}
      </section>
      <section class="panel table-panel">
        <h2>Source Country Metrics</h2>
        {render_table(grouped_columns, source_rows, "No source country data")}
      </section>
    </section>

    <section class="panel table-panel">
      <h2>Detail Preview</h2>
      {render_table(detail_columns, detail_preview, "No detail rows")}
    </section>

    <section class="panel">
      <details>
        <summary>Plain text summary</summary>
        <pre>{escape_html(summary_text)}</pre>
      </details>
    </section>
  </main>
</body>
</html>
"""


def build_report(web_rows: list[dict[str, str]], verdict_rows: list[dict[str, str]]) -> tuple[list[dict[str, str]], str]:
    web_by_md5: dict[str, list[dict[str, str]]] = defaultdict(list)
    verdict_by_md5: dict[str, list[dict[str, str]]] = defaultdict(list)

    for row in web_rows:
        md5 = normalize_md5(row.get("Sandbox MD5"))
        if md5:
            web_by_md5[md5].append(row)

    for row in verdict_rows:
        md5 = normalize_md5(row.get("File MD5"))
        if md5:
            verdict_by_md5[md5].append(row)

    detail_rows: list[dict[str, str]] = []
    status_counts: Counter[str] = Counter()
    verdict_counts: Counter[str] = Counter()
    decision_duration_values: list[float] = []
    decision_durations_by_verdict: dict[str, list[float]] = defaultdict(list)
    decision_durations_by_file_type: dict[str, list[float]] = defaultdict(list)
    sandbox_duration_values: list[float] = []
    sandbox_durations_by_verdict: dict[str, list[float]] = defaultdict(list)
    sandbox_durations_by_file_type: dict[str, list[float]] = defaultdict(list)
    status_counts_by_file_type: dict[str, Counter[str]] = defaultdict(Counter)
    timestamp_errors: list[str] = []

    all_md5s = sorted(set(web_by_md5) | set(verdict_by_md5))
    for md5 in all_md5s:
        web_group = web_by_md5.get(md5, [])
        verdict_group = verdict_by_md5.get(md5, [])

        verdict_row, completed_time, verdict_errors = choose_earliest(verdict_group, "Analysis Completed Time")
        web_row, download_time, web_errors, download_time_selection = choose_web_download_event(web_group, completed_time)
        sfa_summary = sent_for_analysis_event_summary(web_group, completed_time)
        timestamp_errors.extend(f"{md5}: {error}" for error in web_errors + verdict_errors)

        duration_seconds: float | None = None
        web_result = web_sandbox_result(web_row)
        canceled_or_incomplete = "no"
        canceled_or_incomplete_reason = ""
        if web_group and verdict_group and download_time and completed_time:
            duration_seconds = (completed_time - download_time).total_seconds()
            status = "matched" if duration_seconds >= 0 else "matched_negative_duration"
        elif web_group and verdict_group:
            status = "matched_missing_timestamp"
        elif web_group:
            if web_result and not is_sent_for_analysis(web_result):
                duration_seconds = 0
                status = "known_by_cloud"
                if parse_int(sfa_summary.get("sent_for_analysis_event_count")):
                    canceled_or_incomplete = "yes"
                    canceled_or_incomplete_reason = "SFA then cloud verdict without verdict row"
            else:
                status = "canceled_or_incomplete"
                canceled_or_incomplete = "yes"
                canceled_or_incomplete_reason = "SFA without verdict row"
        else:
            status = "missing_web_download"

        file_type = unique_join(web_group, "Download File Type Category") or clean((verdict_row or {}).get("Download File Type")) or "Unknown"
        status_counts[status] += 1
        status_counts_by_file_type[file_type][status] += 1

        verdict = clean((verdict_row or {}).get("Verdict"))
        if not verdict and web_group and web_result and not is_sent_for_analysis(web_result):
            verdict = web_result
        if not verdict:
            verdict = "No verdict"
        verdict_counts[verdict] += 1

        if duration_seconds is not None and duration_seconds >= 0:
            decision_duration_values.append(duration_seconds)
            decision_durations_by_verdict[verdict].append(duration_seconds)
            decision_durations_by_file_type[file_type].append(duration_seconds)
            if status != "known_by_cloud":
                sandbox_duration_values.append(duration_seconds)
                sandbox_durations_by_verdict[verdict].append(duration_seconds)
                sandbox_durations_by_file_type[file_type].append(duration_seconds)

        received_bytes = parse_int((web_row or {}).get("Received Bytes"))
        total_bytes = parse_int((web_row or {}).get("Total Bytes"))
        domain = destination_domain(web_group, web_row)
        blocked = any(is_blocked_web_row(row) for row in web_group) if web_group else False

        detail_rows.append(
            {
                "status": status,
                "md5": md5,
                "download_time": clean((web_row or {}).get(WEB_TIME_COLUMN)),
                "download_time_utc": download_time.strftime("%Y-%m-%d %H:%M:%S UTC") if download_time else "",
                "download_time_selection": download_time_selection,
                "analysis_completed_time": clean((verdict_row or {}).get("Analysis Completed Time")),
                "analysis_completed_time_utc": completed_time.strftime("%Y-%m-%d %H:%M:%S UTC") if completed_time else "",
                "duration_seconds": "" if duration_seconds is None else f"{duration_seconds:.0f}",
                "duration_human": format_seconds(duration_seconds),
                **sfa_summary,
                "canceled_or_incomplete": canceled_or_incomplete,
                "canceled_or_incomplete_reason": canceled_or_incomplete_reason,
                "verdict": verdict,
                "web_sandbox_result": web_result,
                "threat_name": clean((verdict_row or {}).get("Threat Name")),
                "download_file_type": file_type,
                "download_file_name": unique_join(web_group, "Download File Name"),
                "received_bytes": "" if received_bytes is None else str(received_bytes),
                "received_bytes_human": format_bytes(received_bytes),
                "total_bytes": "" if total_bytes is None else str(total_bytes),
                "download_size_bucket": size_bucket(received_bytes),
                "sha256": clean((verdict_row or {}).get("SHA-256")) or unique_join(web_group, "SHA-256"),
                "location": unique_join(web_group, "Location"),
                "department": unique_join(web_group, "Department"),
                "client_ip": unique_join(web_group, "Client IP"),
                "client_external_ip": unique_join(web_group, "Client External IP"),
                "source_ip_country": unique_join(web_group, "Source IP Country"),
                "destination_ip_country": unique_join(web_group, "Destination IP Country"),
                "destination_domain": domain,
                "policy_action": unique_join(web_group, "Policy Action"),
                "blocked": "yes" if blocked else "no",
                "blocked_policy_name": unique_join(web_group, "Blocked Policy Name"),
                "blocked_policy_type": unique_join(web_group, "Blocked Policy Type"),
                "user_location": unique_join(web_group, "User Location"),
                "url": unique_join(web_group, "URL", limit=3),
                "web_event_count": str(len(web_group)),
                "verdict_event_count": str(len(verdict_group)),
                "web_row_numbers": unique_join(web_group, "No."),
                "verdict_row_numbers": unique_join(verdict_group, "No."),
            }
        )

    lines: list[str] = []
    lines.extend(
        ascii_table(
            "Sandbox Analysis Duration Report",
            [("field", "Field"), ("value", "Value")],
            [
                {"field": "Generated UTC", "value": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S %Z")},
                {"field": "Web timestamp column", "value": WEB_TIME_COLUMN},
                {"field": "Matched download time rule", "value": "latest Event Time before Analysis Completed Time"},
            ],
            {"field": 28, "value": 72},
        )
    )
    lines.append("")
    lines.extend(
        ascii_table(
            "Inputs and Matching",
            [("metric", "Metric"), ("value", "Value")],
            [
                {"metric": "Web rows", "value": len(web_rows)},
                {"metric": "Web rows with Sandbox MD5", "value": sum(1 for row in web_rows if normalize_md5(row.get("Sandbox MD5")))},
                {"metric": "Verdict rows", "value": len(verdict_rows)},
                {"metric": "Verdict rows with File MD5", "value": sum(1 for row in verdict_rows if normalize_md5(row.get("File MD5")))},
                {"metric": "Unique web MD5s", "value": len(web_by_md5)},
                {"metric": "Unique verdict MD5s", "value": len(verdict_by_md5)},
                {"metric": "Unique MD5s in report", "value": len(all_md5s)},
            ],
            {"metric": 32},
        )
    )
    lines.append("")
    lines.extend(
        ascii_table(
            "Status Counts",
            [("status", "Status"), ("count", "Count")],
            [{"status": status, "count": count} for status, count in sorted(status_counts.items())],
            {"status": 36},
        )
    )

    repeated_rows = repeated_sent_for_analysis_rows(detail_rows)
    canceled_rows = canceled_or_incomplete_rows(detail_rows)
    lines.append("")
    lines.extend(
        ascii_table(
            "Repeated Sent for Analysis Events",
            [("metric", "Metric"), ("value", "Value")],
            [
                {"metric": "Files affected", "value": len(repeated_rows)},
                {"metric": "Extra Sent for Analysis events", "value": sum(parse_int(row.get("extra_events")) or 0 for row in repeated_rows)},
            ],
            {"metric": 36},
        )
    )
    if repeated_rows:
        lines.append("")
        lines.extend(
            ascii_table(
                "Repeated Sent for Analysis Files",
                [("sent_for_analysis_count", "SFA"), ("duration", "Duration"), ("file_type", "Type"), ("file_name", "File"), ("md5", "MD5")],
                repeated_rows[:10],
                {"file_type": 32, "file_name": 42, "md5": 32},
            )
        )

    lines.append("")
    lines.extend(
        ascii_table(
            "Canceled or Incomplete Downloads",
            [("metric", "Metric"), ("value", "Value")],
            [{"metric": "Files affected", "value": len(canceled_rows)}],
            {"metric": 36},
        )
    )
    if canceled_rows:
        lines.append("")
        lines.extend(
            ascii_table(
                "Canceled or Incomplete Files",
                [("reason", "Reason"), ("sent_for_analysis_count", "SFA"), ("status", "Status"), ("verdict", "Verdict"), ("file_type", "Type"), ("file_name", "File"), ("md5", "MD5")],
                canceled_rows[:10],
                {"reason": 42, "status": 26, "file_type": 32, "file_name": 42, "md5": 32},
            )
        )

    lines.append("")
    lines.extend(stats_lines("Decision durations, including known_by_cloud", decision_duration_values))
    lines.append("")
    lines.extend(stats_lines("Decision durations, excluding known_by_cloud", sandbox_duration_values))
    lines.append("")
    lines.extend(
        ascii_table(
            "Destination domains by worst release time",
            [
                ("domain", "Destination domain"),
                ("total", "Files"),
                ("sandboxed", "Sandboxed"),
                ("blocked", "Blocked"),
                ("block_ratio", "Block ratio"),
                ("avg_release", "Avg"),
                ("p90_release", "P90"),
                ("worst_release", "Worst"),
                ("worst_file", "Worst file"),
            ],
            domain_release_rows(detail_rows, limit=25),
            {"domain": 42, "worst_file": 42},
        )
    )
    lines.append("")
    lines.extend(
        ascii_table(
            "Destination domains by highest block ratio",
            [
                ("domain", "Destination domain"),
                ("total", "Files"),
                ("sandboxed", "Sandboxed"),
                ("blocked", "Blocked"),
                ("block_ratio", "Block ratio"),
                ("avg_release", "Avg"),
                ("p90_release", "P90"),
                ("worst_release", "Worst"),
                ("worst_file", "Worst file"),
            ],
            domain_block_ratio_rows(detail_rows, limit=25),
            {"domain": 42, "worst_file": 42},
        )
    )
    lines.append("")
    lines.extend(grouped_counter_lines("File type status counts", status_counts_by_file_type))
    lines.append("")
    lines.extend(grouped_stats_lines("Durations by file type, including known_by_cloud", decision_durations_by_file_type))
    lines.append("")
    lines.extend(grouped_stats_lines("Durations by file type, excluding known_by_cloud", sandbox_durations_by_file_type))
    lines.append("")
    lines.extend(
        ascii_table(
            "Verdict Counts",
            [("verdict", "Verdict"), ("count", "Count")],
            [{"verdict": verdict, "count": count} for verdict, count in sorted(verdict_counts.items())],
            {"verdict": 36},
        )
    )
    if decision_durations_by_verdict:
        lines.append("")
        lines.extend(grouped_stats_lines("Durations by verdict, including known_by_cloud", decision_durations_by_verdict))
    if sandbox_durations_by_verdict:
        lines.append("")
        lines.extend(grouped_stats_lines("Durations by verdict, excluding known_by_cloud", sandbox_durations_by_verdict))
    if timestamp_errors:
        warning_rows = [{"warning": error} for error in timestamp_errors[:25]]
        if len(timestamp_errors) > 25:
            warning_rows.append({"warning": f"... {len(timestamp_errors) - 25} more"})
        lines.append("")
        lines.extend(ascii_table("Timestamp Parse Warnings", [("warning", "Warning")], warning_rows, {"warning": 96}))

    return detail_rows, "\n".join(lines) + "\n"


def write_detail_csv(path: Path, rows: list[dict[str, str]]) -> None:
    fieldnames = [
        "status",
        "md5",
        "download_time",
        "download_time_utc",
        "download_time_selection",
        "analysis_completed_time",
        "analysis_completed_time_utc",
        "duration_seconds",
        "duration_human",
        "sent_for_analysis_event_count",
        "sent_for_analysis_before_completion_count",
        "repeated_sent_for_analysis",
        "sent_for_analysis_extra_events",
        "sent_for_analysis_row_numbers",
        "sent_for_analysis_event_times",
        "canceled_or_incomplete",
        "canceled_or_incomplete_reason",
        "verdict",
        "web_sandbox_result",
        "threat_name",
        "download_file_type",
        "download_file_name",
        "received_bytes",
        "received_bytes_human",
        "total_bytes",
        "download_size_bucket",
        "sha256",
        "location",
        "department",
        "client_ip",
        "client_external_ip",
        "source_ip_country",
        "destination_ip_country",
        "destination_domain",
        "policy_action",
        "blocked",
        "blocked_policy_name",
        "blocked_policy_type",
        "user_location",
        "url",
        "web_event_count",
        "verdict_event_count",
        "web_row_numbers",
        "verdict_row_numbers",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Join a WEB_log.csv export and a SANDBOX_VERDICT_log.csv export by MD5, then report sandbox operational metrics."
    )
    parser.add_argument("web_log_csv", type=Path, help="Path to WEB_log.csv")
    parser.add_argument("sandbox_verdict_csv", type=Path, help="Path to SANDBOX_VERDICT_log.csv")
    parser.add_argument("-o", "--output-dir", type=Path, default=Path("."), help="Directory for generated report files. Default: current directory")
    parser.add_argument("--prefix", default="sandbox_analysis_report", help="Output filename prefix. Default: sandbox_analysis_report")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    web_header, web_rows, _ = read_export_csv(args.web_log_csv)
    verdict_header, verdict_rows, _ = read_export_csv(args.sandbox_verdict_csv)
    require_columns(args.web_log_csv, web_header, ["No.", WEB_TIME_COLUMN, "Sandbox MD5"])
    require_columns(args.sandbox_verdict_csv, verdict_header, ["No.", "Analysis Completed Time", "File MD5"])

    detail_rows, summary = build_report(web_rows, verdict_rows)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    detail_path = args.output_dir / f"{args.prefix}_details.csv"
    summary_path = args.output_dir / f"{args.prefix}_summary.txt"
    html_path = args.output_dir / f"{args.prefix}.html"
    write_detail_csv(detail_path, detail_rows)
    summary_path.write_text(summary, encoding="utf-8")
    html_path.write_text(render_html_report(detail_rows, summary, args.web_log_csv, args.sandbox_verdict_csv), encoding="utf-8")

    print(summary.rstrip())
    print()
    print(f"Wrote detail CSV: {detail_path}")
    print(f"Wrote summary: {summary_path}")
    print(f"Wrote HTML report: {html_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
