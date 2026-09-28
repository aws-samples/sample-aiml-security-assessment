"""Command line: ``python3 -m assessment_history compare``.

S3 mode is what buildspec.yml runs after each assessment. For each account it
compares the current run with the most recent complete run saved before it,
writes ``security_assessment_changes_<YYYYMMDD_HHMMSS>.csv`` and ``.html`` into
``<bucket>/<account_id>/`` and prints what it did::

    python3 -m assessment_history compare --bucket BUCKET --accounts "ID ID"
        (--execution-id ID | --execution-arn-dir DIR)
        [--failures-file FILE] [--time-budget SECONDS]

It never fails the build: a problem with one account is printed as a WARNING
line, the other accounts carry on, and the exit code is 0. Setting
ENABLE_ASSESSMENT_HISTORY=false turns it off.

Local mode compares two folders, each holding one run's findings CSVs as
saved in the results bucket, and writes the CSV and HTML into a third folder::

    python3 -m assessment_history compare --account ID
        --previous-dir DIR --current-dir DIR --output-dir DIR
"""

from __future__ import annotations

import argparse
import csv
import io
import os
import re
import sys
import time
from collections.abc import Callable, Mapping
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path

from .compare import compare_runs
from .discover import (
    DirectorySource,
    DiscoveryError,
    S3Source,
    StoredFile,
    discover,
    format_utc,
    group_runs,
    read_complete_run,
)
from .models import (
    ACCOUNT_ID_PATTERN,
    CSV_COLUMNS,
    Change,
    Comparison,
    InvalidFindingError,
    Run,
)
from .render_changes import render_changes_page

SETTING = "ENABLE_ASSESSMENT_HISTORY"
CHANGES_FILE_PREFIX = "security_assessment_changes_"
# The main report the scanners' report Lambda writes for each run. Its name has
# no execution ID, so it's matched to a run by save time: the build uploads a
# run's CSVs and its main report together, seconds apart.
MAIN_REPORT_NAME = re.compile(r"security_assessment_single_account_\d{8}_\d{6}\.html")
MAIN_REPORT_WINDOW_SECONDS = 600
# The failure-ledger stage buildspec.yml records when the multi-account report
# fails. It's written under the management account's ID but says nothing
# about that account's own run, so it doesn't block its changes report.
REPORT_ONLY_STAGES = frozenset({"consolidation"})
# Stop starting new accounts when this little of --time-budget is left, so
# the step ends on its own before `timeout` stops it.
ACCOUNT_RESERVE_SECONDS = 60
# The retry settings the Lambda functions use (boto3_config in each app.py).
S3_RETRIES = {"max_attempts": 10, "mode": "adaptive"}
TILE_ORDER = (
    Change.REGRESSED,
    Change.NEW,
    Change.STILL_OPEN,
    Change.RESOLVED,
    Change.NO_LONGER_REPORTED,
    Change.NO_LONGER_ASSESSED,
)
MAX_LISTED = 10

Output = Callable[[str], None]


def history_enabled(environ: Mapping[str, str], out: Output) -> bool:
    """Read the setting. Missing means on (stacks created before it existed)."""
    raw = environ.get(SETTING)
    value = "true" if raw is None else raw.strip().lower()
    if value == "false":
        return False
    if value != "true":
        out(f"WARNING: {SETTING}={raw!r} is not true or false; using true")
    return True


def changes_file_name(comparison: Comparison, extension: str = "csv") -> str:
    """Name of a changes file: the current run's saved time, in UTC."""
    saved = comparison.current_saved_at.astimezone(UTC)
    return f"{CHANGES_FILE_PREFIX}{saved:%Y%m%d_%H%M%S}.{extension}"


def find_main_report(files: Iterable[StoredFile], saved_at: datetime) -> str | None:
    """The current run's main report, or None when it isn't certain.

    That's the one main report saved within 10 minutes of the run's CSVs;
    none or several means no link.
    """
    matches = [
        stored.name
        for stored in files
        if MAIN_REPORT_NAME.fullmatch(stored.name)
        and abs((stored.saved_at - saved_at).total_seconds())
        <= MAIN_REPORT_WINDOW_SECONDS
    ]
    return matches[0] if len(matches) == 1 else None


def changes_page(comparison: Comparison, files: Iterable[StoredFile]) -> bytes:
    """The changes HTML page, linking the CSV and, when known, the main report."""
    return render_changes_page(
        comparison,
        csv_name=changes_file_name(comparison),
        main_report_name=find_main_report(files, comparison.current_saved_at),
    ).encode("utf-8")


def changes_csv(comparison: Comparison) -> bytes:
    """The changes CSV: one row per finding, columns in CSV_COLUMNS order."""
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=CSV_COLUMNS)
    writer.writeheader()
    writer.writerows(comparison.to_csv_records())
    return buffer.getvalue().encode("utf-8")


def _listing(items: Mapping[str, str]) -> str:
    shown = [f"{name} ({side})" for name, side in list(items.items())[:MAX_LISTED]]
    if len(items) > MAX_LISTED:
        shown.append(f"and {len(items) - MAX_LISTED} more")
    return ", ".join(shown)


def describe(comparison: Comparison) -> list[str]:
    """Log lines: which two runs were compared and what changed."""
    lines = [
        f"  Compared run {comparison.current_execution_id} "
        f"(saved {format_utc(comparison.current_saved_at)}) with run "
        f"{comparison.previous_execution_id} "
        f"(saved {format_utc(comparison.previous_saved_at)}), "
        f"{comparison.days_apart} day(s) apart"
    ]
    if comparison.has_changes:
        tiles = comparison.tile_counts()
        counts = ", ".join(f"{change.value} {tiles[change]}" for change in TILE_ORDER)
        lines.append(f"  Bedrock, SageMaker, AgentCore, Agent Registry: {counts}")
    else:
        lines.append("  No changes since the last assessment")
    if comparison.not_compared_modules:
        lines.append(
            "  Not compared (enabled in only one run): "
            + _listing(comparison.not_compared_modules)
        )
    if comparison.not_compared_regions:
        lines.append(
            "  Not compared (scanned in only one run): "
            + _listing(comparison.not_compared_regions)
        )
    if comparison.single_run_check_ids:
        lines.append(
            "  Check IDs found in only one run: "
            + _listing(comparison.single_run_check_ids)
        )
    return lines


def read_failures(path: str) -> dict[str, list[str]]:
    """Reasons per account from buildspec.yml's failure ledger.

    Each line is "account<TAB>stage<TAB>reason". The file is only read.
    """
    ledger = Path(path)
    if not ledger.is_file():
        return {}
    failures: dict[str, list[str]] = {}
    for line in ledger.read_text(encoding="utf-8").splitlines():
        parts = line.split("\t")
        if len(parts) < 3 or parts[1] in REPORT_ONLY_STAGES:
            continue
        failures.setdefault(parts[0], []).append(parts[2])
    return failures


def _cannot_complete(out: Output, account: str, reasons: list[str]) -> None:
    unique = list(dict.fromkeys(reason.strip().rstrip(".") for reason in reasons))
    out(
        f"WARNING: Changes report cannot be completed for account {account}. "
        f"Reason(s): {'; '.join(unique)}."
    )


def _reason(error: Exception) -> str:
    if isinstance(error, (DiscoveryError, InvalidFindingError)):
        return str(error)
    return f"{type(error).__name__}: {error}"


def _current_execution_id(args: argparse.Namespace, account: str) -> str:
    if args.execution_id is not None:
        return args.execution_id.strip()
    arn_file = Path(args.execution_arn_dir) / f"{account}.txt"
    if not arn_file.is_file():
        raise DiscoveryError("no execution ARN was saved for the current run")
    return arn_file.read_text(encoding="utf-8").strip().rsplit(":", 1)[-1]


def _s3_client():
    import boto3
    from botocore.config import Config

    return boto3.client("s3", config=Config(retries=S3_RETRIES))


def _compare_in_s3(client, bucket: str, account: str, execution_id: str, out: Output):
    source = S3Source(client, bucket, account)
    found = discover(source, account, execution_id)
    out(f"Changes report for account {account}")
    for note in found.notes:
        out(f"  {note}")
    if found.previous is None:
        out(f"  No previous run for account {account}; changes report skipped.")
        return
    comparison = compare_runs(found.previous, found.current)
    page = changes_page(comparison, source.list_files())
    # The CSV first: if the page can't be written, its absence is the symptom.
    written = []
    for extension, body, content_type in (
        ("csv", changes_csv(comparison), "text/csv; charset=utf-8"),
        ("html", page, "text/html; charset=utf-8"),
    ):
        key = f"{account}/{changes_file_name(comparison, extension)}"
        client.put_object(Bucket=bucket, Key=key, Body=body, ContentType=content_type)
        written.append(key)
    for line in describe(comparison):
        out(line)
    for key in written:
        out(f"  Written: s3://{bucket}/{key}")


def run_s3(args, accounts, client, environ, clock, out: Output) -> int:
    """Write the changes CSV and page for each account. Always returns 0."""
    if not history_enabled(environ, out):
        out("Changes report disabled (EnableAssessmentHistory=false)")
        return 0
    client = client or _s3_client()
    failures = read_failures(args.failures_file) if args.failures_file else {}
    started = clock()
    for index, account in enumerate(accounts):
        if (
            args.time_budget is not None
            and clock() - started > args.time_budget - ACCOUNT_RESERVE_SECONDS
        ):
            for remaining in accounts[index:]:
                _cannot_complete(
                    out,
                    remaining,
                    ["the time limit for the changes report was reached"],
                )
            break
        if not ACCOUNT_ID_PATTERN.fullmatch(account):
            out(f"Skipped {account!r}: not an AWS account ID")
            continue
        if account in failures:
            _cannot_complete(out, account, failures[account])
            continue
        try:
            execution_id = _current_execution_id(args, account)
            _compare_in_s3(client, args.bucket, account, execution_id, out)
        except Exception as error:  # one account must not stop the others
            _cannot_complete(out, account, [_reason(error)])
    return 0


def _only_run(folder: str, account: str) -> Run:
    source = DirectorySource(folder)
    runs, _unknown = group_runs(source.list_files())
    if len(runs) != 1:
        raise DiscoveryError(
            f"{folder} should hold one run's findings CSVs; found {len(runs)} runs"
        )
    (run_files,) = runs.values()
    run, reason = read_complete_run(source, account, run_files)
    if run is None:
        raise DiscoveryError(f"the run in {folder} is incomplete ({reason})")
    return run


def run_local(account, previous_dir, current_dir, output_dir, out: Output) -> int:
    """Compare two local folders and write the CSV and page. 1 on an error."""
    try:
        previous = _only_run(previous_dir, account)
        current = _only_run(current_dir, account)
        comparison = compare_runs(previous, current)
        page = changes_page(comparison, DirectorySource(current_dir).list_files())
    except (DiscoveryError, ValueError, OSError) as error:
        out(f"ERROR: {error}")
        return 1
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    paths = [output / changes_file_name(comparison, ext) for ext in ("csv", "html")]
    paths[0].write_bytes(changes_csv(comparison))
    paths[1].write_bytes(page)
    out(f"Changes report for account {account}")
    for line in describe(comparison):
        out(line)
    for path in paths:
        out(f"  Written: {path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python3 -m assessment_history",
        description="Compare AI/ML security assessment runs.",
        allow_abbrev=False,
    )
    commands = parser.add_subparsers(dest="command", required=True)
    compare = commands.add_parser(
        "compare",
        help="compare each account's current run with its previous run",
        description="Write a changes-since-last-assessment CSV and page per account.",
        allow_abbrev=False,
    )
    s3 = compare.add_argument_group("S3 mode (what buildspec.yml runs)")
    s3.add_argument("--bucket", help="central results bucket")
    s3.add_argument("--accounts", help="account IDs, separated by spaces or commas")
    s3.add_argument(
        "--execution-id", help="the current run's execution ID (one account)"
    )
    s3.add_argument(
        "--execution-arn-dir",
        help="folder with <account_id>.txt holding each current execution ARN",
    )
    s3.add_argument("--failures-file", help="buildspec.yml failure ledger (read only)")
    s3.add_argument(
        "--time-budget",
        type=int,
        metavar="SECONDS",
        help="stop starting new accounts 60 seconds before this",
    )
    local = compare.add_argument_group("local mode")
    local.add_argument("--account", help="account the two folders belong to")
    local.add_argument("--previous-dir", help="folder with the previous run")
    local.add_argument("--current-dir", help="folder with the current run")
    local.add_argument("--output-dir", help="folder for the changes CSV and page")
    return parser


def main(
    argv: list[str] | None = None,
    *,
    s3_client=None,
    environ: Mapping[str, str] | None = None,
    clock: Callable[[], float] = time.monotonic,
    out: Output = print,
) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    local = (args.account, args.previous_dir, args.current_dir, args.output_dir)
    remote = (
        args.bucket,
        args.accounts,
        args.execution_id,
        args.execution_arn_dir,
        args.failures_file,
        args.time_budget,
    )
    if any(value is not None for value in local):
        if any(value is not None for value in remote):
            parser.error("use either the S3 options or the local-folder options")
        if any(value is None for value in local):
            parser.error(
                "local mode needs --account, --previous-dir, --current-dir "
                "and --output-dir"
            )
        return run_local(*local, out)
    if args.bucket is None or args.accounts is None:
        parser.error("S3 mode needs --bucket and --accounts")
    if (args.execution_id is None) == (args.execution_arn_dir is None):
        parser.error("S3 mode needs one of --execution-id or --execution-arn-dir")
    accounts = [account for account in re.split(r"[\s,]+", args.accounts) if account]
    if args.execution_id is not None and len(accounts) != 1:
        parser.error("--execution-id works with exactly one account")
    environ = os.environ if environ is None else environ
    return run_s3(args, accounts, s3_client, environ, clock, out)


if __name__ == "__main__":
    sys.exit(main())
