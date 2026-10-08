"""Command line: ``python3 -m assessment_history compare``.

S3 mode is what buildspec.yml runs after each assessment. For each account it
compares the current run with the most recent usable run saved before it,
writes ``security_assessment_changes_<YYYYMMDD_HHMMSS>.csv`` and ``.html`` into
``<bucket>/<account_id>/`` and prints what it did::

    python3 -m assessment_history compare --bucket BUCKET --accounts "ID ID"
        (--execution-id ID | --execution-arn-dir DIR)
        [--failures-file FILE] [--time-budget SECONDS]

It never fails the build: a problem with one account is printed as a WARNING
line, the other accounts carry on, and the exit code is 0. Setting
ENABLE_ASSESSMENT_HISTORY=false turns it off. ENABLE_BEDROCK,
ENABLE_SAGEMAKER, ENABLE_AGENTCORE and ENABLE_AGENT_REGISTRY say which core
services the current run selected (missing means selected, as in
buildspec.yml), so a deselected service's missing CSVs don't make the run
incomplete. The CSV is written before the
page, so a page that can't be written still leaves the CSV. Accounts are
started in an order that moves along one account with each CodeBuild build
number, so when the time budget runs out it isn't always the same accounts
that miss out.

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
# The CodeBuild switches for the core services (service selection), in
# CORE_MODULES order. buildspec.yml sets each to true when it's missing.
SELECTION_SETTINGS = {
    "bedrock": "ENABLE_BEDROCK",
    "sagemaker": "ENABLE_SAGEMAKER",
    "agentcore": "ENABLE_AGENTCORE",
    "agent-registry": "ENABLE_AGENT_REGISTRY",
}
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
# CodeBuild's build number, which moves the account order along (review F4).
BUILD_NUMBER = "CODEBUILD_BUILD_NUMBER"
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
# Core service names in the log's headline-counts line.
SERVICE_NAMES = {
    "bedrock": "Bedrock",
    "sagemaker": "SageMaker",
    "agentcore": "AgentCore",
    "agent-registry": "Agent Registry",
}

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


def selected_services(environ: Mapping[str, str], out: Output) -> frozenset[str] | None:
    """The core services the current run selected, from its switches.

    A missing switch means selected, as in buildspec.yml. If a switch is
    neither true nor false, the selection is unknown (None) and the services
    the run has CSVs for are taken as selected.
    """
    selected = set()
    for module, name in SELECTION_SETTINGS.items():
        raw = environ.get(name)
        value = "true" if raw is None else raw.strip().lower()
        if value not in ("true", "false"):
            out(
                f"WARNING: {name}={raw!r} is not true or false; the services "
                "with CSVs are taken as selected"
            )
            return None
        if value == "true":
            selected.add(module)
    return frozenset(selected)


def first_run_note(account: str) -> str:
    """The log line for an account with no usable earlier run."""
    return (
        f"No previous run for account {account}; changes report skipped. "
        "If this stack was redeployed, or earlier results were moved or deleted, "
        "they aren't compared. The next run will compare with this one."
    )


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


def _names(names: list[str]) -> str:
    shown = names[:MAX_LISTED]
    if len(names) > MAX_LISTED:
        shown.append(f"and {len(names) - MAX_LISTED} more")
    return ", ".join(shown)


def _listing(items: Mapping[str, str]) -> str:
    return _names([f"{name} ({side})" for name, side in items.items()])


def describe(comparison: Comparison) -> list[str]:
    """Log lines: which two runs were compared and what changed."""
    lines = [
        f"  Compared run {comparison.current_execution_id} "
        f"(saved {format_utc(comparison.current_saved_at)}) with run "
        f"{comparison.previous_execution_id} "
        f"(saved {format_utc(comparison.previous_saved_at)}), "
        f"{comparison.days_apart} day(s) apart"
    ]
    services = comparison.compared_services
    if not comparison.has_changes:
        lines.append("  No changes since the last assessment")
    elif services:
        tiles = comparison.tile_counts()
        counts = ", ".join(f"{change.value} {tiles[change]}" for change in TILE_ORDER)
        names = ", ".join(SERVICE_NAMES[service] for service in services)
        lines.append(f"  {names}: {counts}")
    else:
        lines.append(
            "  No core service was selected in both runs, so there are no headline "
            "counts; see the changes CSV"
        )
    if comparison.not_selected_services:
        lines.append(
            "  Not compared (not selected in both runs): "
            + _listing(comparison.not_selected_services)
        )
    if comparison.not_compared_options:
        lines.append(
            "  Not compared (enabled in only one run): "
            + _listing(comparison.not_compared_options)
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


def rotate_accounts(
    accounts: list[str], environ: Mapping[str, str]
) -> tuple[list[str], int]:
    """The accounts starting at (build number mod count), and that offset.

    Without a whole-number build number the order is unchanged.
    """
    raw = environ.get(BUILD_NUMBER, "").strip()
    if len(accounts) < 2 or not (raw.isascii() and raw.isdigit()):
        return list(accounts), 0
    offset = int(raw) % len(accounts)
    return accounts[offset:] + accounts[:offset], offset


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


def _compare_in_s3(
    client,
    bucket: str,
    account: str,
    execution_id: str,
    selected: frozenset[str] | None,
    out: Output,
):
    source = S3Source(client, bucket, account)
    found = discover(source, account, execution_id, selected)
    out(f"Changes report for account {account}")
    for note in found.notes:
        out(f"  {note}")
    if found.previous is None:
        out(f"  {first_run_note(account)}")
        return
    comparison = compare_runs(found.previous, found.current)
    # The CSV first, and on its own: a page that can't be made or written
    # must not cost the CSV (review item L1).
    csv_key = f"{account}/{changes_file_name(comparison)}"
    client.put_object(
        Bucket=bucket,
        Key=csv_key,
        Body=changes_csv(comparison),
        ContentType="text/csv; charset=utf-8",
    )
    written = [csv_key]
    page_problem = None
    try:
        page = changes_page(comparison, source.list_files())
        page_key = f"{account}/{changes_file_name(comparison, 'html')}"
        client.put_object(
            Bucket=bucket,
            Key=page_key,
            Body=page,
            ContentType="text/html; charset=utf-8",
        )
        written.append(page_key)
    except Exception as error:  # the CSV is already written
        page_problem = _reason(error)
    for line in describe(comparison):
        out(line)
    for key in written:
        out(f"  Written: s3://{bucket}/{key}")
    if page_problem is not None:
        out(
            f"WARNING: The changes page for account {account} could not be "
            f"written; the CSV was. Reason: {page_problem.rstrip('.')}."
        )


def run_s3(args, accounts, client, environ, clock, out: Output) -> int:
    """Write the changes CSV and page for each account. Always returns 0."""
    if not history_enabled(environ, out):
        out("Changes report disabled (EnableAssessmentHistory=false)")
        return 0
    selected = selected_services(environ, out)
    client = client or _s3_client()
    failures = read_failures(args.failures_file) if args.failures_file else {}
    accounts, offset = rotate_accounts(accounts, environ)
    if offset:
        out(
            f"Starting with account {accounts[0]}: the account order moves "
            "along one account with each build number"
        )
    started = clock()
    for index, account in enumerate(accounts):
        if (
            args.time_budget is not None
            and clock() - started > args.time_budget - ACCOUNT_RESERVE_SECONDS
        ):
            remaining = accounts[index:]
            for skipped in remaining:
                _cannot_complete(
                    out,
                    skipped,
                    ["the time limit for the changes report was reached"],
                )
            out(
                f"WARNING: The time limit was reached with {len(remaining)} of "
                f"{len(accounts)} account(s) not started: " + _names(remaining)
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
            _compare_in_s3(client, args.bucket, account, execution_id, selected, out)
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
