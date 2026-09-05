import argparse
import csv
import json
import math
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from statistics import mean, median, stdev

import matplotlib.pyplot as plt
from matplotlib.axes import Axes
from matplotlib.figure import Figure
from matplotlib.patches import FancyBboxPatch
from scipy.stats import t

from benchmark import MODE_LABELS, PAIRED_MODE_COMPARISONS
from tls_pqc_bridge.protocol import (
    ALPN_IDS,
    MAX_TRANSFER_BYTES,
    MODES,
    TLS_GROUP_BY_MODE,
)
from tls_pqc_bridge.tls import ALLOWED_TLS13_CIPHERS


@dataclass(frozen=True)
class MetricSpec:
    metric: str
    title: str
    unit: str
    legacy_metric: str
    logarithmic: bool = False


CLIENT_METRICS = (
    MetricSpec(
        "download_receive_ms",
        "Download receive and verify",
        "Elapsed time (ms)",
        "decrypt_time_ms",
        True,
    ),
    MetricSpec(
        "upload_send_ms",
        "Upload send",
        "Elapsed time (ms)",
        "encrypt_time_ms",
        True,
    ),
    MetricSpec(
        "transfer_total_ms",
        "Bidirectional transfer",
        "Elapsed time (ms)",
        "end_to_end_transfer_time_ms",
        True,
    ),
    MetricSpec(
        "channel_ready_ms",
        "Channel ready",
        "Elapsed time (ms)",
        "handshake_time_ms",
    ),
    MetricSpec(
        "ping_rtt_ms",
        "Application ping RTT",
        "Elapsed time (ms)",
        "ping_rtt_ms",
    ),
    MetricSpec(
        "throughput_mbps",
        "Throughput",
        "Throughput (Mbit/s)",
        "throughput_bytes_per_sec",
        True,
    ),
)
SERVER_METRICS = (
    MetricSpec(
        "upload_receive_ms",
        "Upload receive and verify",
        "Elapsed time (ms)",
        "decrypt_time_ms",
        True,
    ),
    MetricSpec(
        "download_send_ms",
        "Returned-copy send",
        "Elapsed time (ms)",
        "encrypt_time_ms",
        True,
    ),
    MetricSpec(
        "channel_ready_ms",
        "Channel ready",
        "Elapsed time (ms)",
        "handshake_time_ms",
    ),
    MetricSpec(
        "throughput_mbps",
        "Throughput",
        "Throughput (Mbit/s)",
        "throughput_bytes_per_sec",
        True,
    ),
    MetricSpec(
        "transfer_total_ms",
        "Bidirectional transfer",
        "Elapsed time (ms)",
        "transfer_duration_ms",
        True,
    ),
)
OVERVIEW_METRICS = tuple(
    spec
    for name in (
        "channel_ready_ms",
        "ping_rtt_ms",
        "transfer_total_ms",
        "throughput_mbps",
    )
    for spec in CLIENT_METRICS
    if spec.metric == name
)
MODE_STYLE = {
    "baseline": {
        "color": "#0072B2",
        "marker": "o",
        "linestyle": "-",
        "label": MODE_LABELS["baseline"],
    },
    "native": {
        "color": "#009E73",
        "marker": "^",
        "linestyle": "-.",
        "label": MODE_LABELS["native"],
    },
    "hybrid": {
        "color": "#D55E00",
        "marker": "s",
        "linestyle": "--",
        "label": MODE_LABELS["hybrid"],
    },
}
MODE_OFFSET = {"baseline": -0.18, "native": 0.0, "hybrid": 0.18}
COMPARISON_STYLE = {
    ("baseline", "native"): {"color": "#009E73", "marker": "^", "offset": -0.18},
    ("baseline", "hybrid"): {"color": "#D55E00", "marker": "s", "offset": 0.0},
    ("native", "hybrid"): {"color": "#7A5195", "marker": "D", "offset": 0.18},
}
PLOT_STYLE = {
    "axes.edgecolor": "#4A4F57",
    "axes.labelcolor": "#282C33",
    "axes.spines.right": False,
    "axes.spines.top": False,
    "figure.facecolor": "white",
    "font.size": 10,
    "legend.frameon": False,
    "svg.fonttype": "none",
    "text.color": "#20242A",
}
TLS_COLOR = "#0072B2"
PQ_COLOR = "#D55E00"
KEY_COLOR = "#007A5E"
NEUTRAL = "#40464F"


def plot_results(results: Path) -> tuple[Path, ...]:
    results = results.resolve()
    manifest = _read_manifest(results / "manifest.json")
    status = _read_status(results / "status.csv")
    runs = _read_runs(results / "runs.csv")
    summary = _read_numeric_table(
        results / "summary.csv",
        integer_fields={"payload_bytes", "attempted", "n"},
    )
    paired = _read_numeric_table(
        results / "paired-comparisons.csv",
        integer_fields={"payload_bytes", "paired_n", "relative_paired_n"},
    )
    sizes = _validate_evidence(manifest, status, runs, summary, paired)
    if len(sizes) < 2:
        raise ValueError("scaling plots require at least two payload sizes")

    plots = results / "plots"
    paper = plots / "paper"
    legacy = plots / "legacy-equivalent"
    outputs: list[Path] = []
    with plt.rc_context(PLOT_STYLE):
        outputs.extend(
            _save_figure(
                _scaling_summary(runs, summary, "client", OVERVIEW_METRICS, sizes),
                plots / "scaling-summary",
                "TLS-PQC Bridge scaling overview",
            )
        )
        outputs.extend(
            _save_figure(
                _handshake_components(runs),
                plots / "handshake-components",
                "TLS and PQC channel-establishment components",
            )
        )
        for endpoint, specs in (
            ("client", CLIENT_METRICS),
            ("server", SERVER_METRICS),
        ):
            size_slug = _size_slug(max(sizes))
            outputs.extend(
                _save_figure(
                    _scaling_summary(runs, summary, endpoint, specs, sizes),
                    paper / f"{endpoint}_scaling_summary",
                    f"{endpoint.capitalize()} legacy-equivalent scaling summary",
                )
            )
            for spec in specs:
                outputs.extend(
                    _save_figure(
                        _single_metric_figure(runs, summary, endpoint, spec, sizes),
                        legacy / endpoint / f"{spec.metric}_scaling",
                        f"{endpoint.capitalize()} {spec.title.lower()} scaling",
                    )
                )
            outputs.extend(
                _save_figure(
                    _paired_effects_figure(paired, endpoint, specs, max(sizes)),
                    legacy / f"{endpoint}_{size_slug}_paired_effects",
                    f"{endpoint.capitalize()} {_size_label(max(sizes))} paired protocol effects",
                )
            )
            table_path = legacy / f"{endpoint}_{size_slug}_paired_effects.csv"
            _write_effect_table(
                table_path, summary, paired, endpoint, specs, max(sizes)
            )
            outputs.append(table_path)
        outputs.extend(
            _save_figure(
                handshake_figure(),
                paper / "handshake",
                "TLS-PQC Bridge protocol sequence",
            )
        )
        outputs.extend(
            _save_figure(
                security_boundary_figure(),
                paper / "attack",
                "TLS-PQC Bridge security boundary",
            )
        )
    return tuple(outputs)


def _scaling_summary(
    runs: list[dict[str, object]],
    summary: list[dict[str, object]],
    endpoint: str,
    specs: tuple[MetricSpec, ...],
    sizes: list[int],
) -> Figure:
    columns = 2 if len(specs) <= 4 else 3
    rows = (len(specs) + columns - 1) // columns
    figure, axes = plt.subplots(
        rows,
        columns,
        figsize=(6.0 * columns, 3.6 * rows + 0.5),
        layout="constrained",
        squeeze=False,
    )
    for index, spec in enumerate(specs):
        _draw_metric(
            axes.flat[index],
            runs,
            summary,
            endpoint,
            spec,
            sizes,
            index == 0,
        )
    for index in range(len(specs), rows * columns):
        axes.flat[index].axis("off")
    figure.suptitle(
        f"{endpoint.capitalize()} performance by protocol",
        fontsize=15,
        weight="bold",
    )
    _add_footer(
        figure,
        "Classical TLS and the bridge both use X25519; native hybrid TLS uses "
        "X25519MLKEM768. Each panel reports the interval named on its axis.\nDots are runs; "
        "connected points are means with 95% Student-t intervals. One loopback host.",
        bottom_fraction=0.10,
    )
    return figure


def _single_metric_figure(
    runs: list[dict[str, object]],
    summary: list[dict[str, object]],
    endpoint: str,
    spec: MetricSpec,
    sizes: list[int],
) -> Figure:
    figure, axis = plt.subplots(figsize=(7.6, 4.8), layout="constrained")
    _draw_metric(axis, runs, summary, endpoint, spec, sizes, True)
    figure.suptitle(
        f"{endpoint.capitalize()} {spec.title.lower()} scaling",
        fontsize=14,
        weight="bold",
    )
    _add_footer(
        figure,
        "Classical TLS and the bridge both use X25519; native hybrid TLS uses "
        "X25519MLKEM768. The axis names the measured interval.\nDots are runs; bars are 95% "
        "Student-t intervals. One loopback host.",
        bottom_fraction=0.14,
    )
    return figure


def _draw_metric(
    axis: Axes,
    runs: list[dict[str, object]],
    summary: list[dict[str, object]],
    endpoint: str,
    spec: MetricSpec,
    sizes: list[int],
    show_legend: bool,
) -> None:
    positions = list(range(len(sizes)))
    for mode, style in MODE_STYLE.items():
        x_positions = [position + MODE_OFFSET[mode] for position in positions]
        means: list[float] = []
        lower: list[float] = []
        upper: list[float] = []
        for x_position, size in zip(x_positions, sizes):
            row = _select_summary(summary, mode, size, endpoint, spec.metric)
            average = float(row["mean"])
            means.append(average)
            lower.append(average - float(row["ci95_low"]))
            upper.append(float(row["ci95_high"]) - average)
            values = _raw_values(runs, mode, size, endpoint, spec.metric)
            if len(values) != int(row["n"]):
                raise ValueError(
                    f"raw and summary counts differ for {endpoint} {mode} {spec.metric}"
                )
            center = (len(values) - 1) / 2
            jittered = [
                x_position + 0.004 * (index - center) for index in range(len(values))
            ]
            axis.scatter(
                jittered,
                values,
                s=13,
                alpha=0.23,
                color=style["color"],
                marker=style["marker"],
                edgecolors="none",
            )
        axis.errorbar(
            x_positions,
            means,
            yerr=[lower, upper],
            color=style["color"],
            marker=style["marker"],
            linestyle=style["linestyle"],
            linewidth=1.8,
            markersize=6,
            capsize=3,
            label=style["label"],
        )
    axis.set_title(spec.title, fontsize=11, weight="bold")
    axis.set_xticks(positions, [_size_label(size) for size in sizes])
    axis.set_xlabel("Payload per direction")
    axis.set_ylabel(spec.unit)
    if spec.logarithmic:
        axis.set_yscale("log")
    axis.grid(axis="y", color="#D7DADF", linewidth=0.7)
    axis.set_axisbelow(True)
    if show_legend:
        axis.legend(loc="best")


def _handshake_components(runs: list[dict[str, object]]) -> Figure:
    series = (
        (
            "Client\nClassical TLS\nTLS handshake",
            "client",
            "baseline",
            "tls_handshake_ms",
            "TLS handshake",
        ),
        (
            "Client\nNative hybrid TLS\nTLS handshake",
            "client",
            "native",
            "tls_handshake_ms",
            "TLS handshake",
        ),
        (
            "Client\nTLS + PQC bridge\nTLS handshake",
            "client",
            "hybrid",
            "tls_handshake_ms",
            "TLS handshake",
        ),
        (
            "Client\nTLS + PQC bridge\nPQC exchange",
            "client",
            "hybrid",
            "pqc_handshake_ms",
            "PQC exchange",
        ),
        (
            "Server\nClassical TLS\nTLS handshake",
            "server",
            "baseline",
            "tls_handshake_ms",
            "TLS handshake",
        ),
        (
            "Server\nNative hybrid TLS\nTLS handshake",
            "server",
            "native",
            "tls_handshake_ms",
            "TLS handshake",
        ),
        (
            "Server\nTLS + PQC bridge\nTLS handshake",
            "server",
            "hybrid",
            "tls_handshake_ms",
            "TLS handshake",
        ),
        (
            "Server\nTLS + PQC bridge\nPQC exchange",
            "server",
            "hybrid",
            "pqc_handshake_ms",
            "PQC exchange",
        ),
    )
    component_style = {
        "TLS handshake": {"color": "#0072B2", "marker": "o"},
        "PQC exchange": {"color": "#D55E00", "marker": "s"},
    }
    figure, axis = plt.subplots(figsize=(12.0, 5.6), layout="constrained")
    labels: list[str] = []
    labelled: set[str] = set()
    for position, (label, endpoint, mode, metric, component) in enumerate(series):
        field = f"{endpoint}_{metric}"
        values = [
            float(run[field])
            for run in runs
            if run["mode"] == mode and run.get(field) not in (None, "")
        ]
        average, low, high = _mean_interval(values)
        center = (len(values) - 1) / 2
        jittered = [
            position + 0.0025 * (index - center) for index in range(len(values))
        ]
        style = component_style[component]
        axis.scatter(
            jittered,
            values,
            s=12,
            alpha=0.2,
            color=style["color"],
            marker=style["marker"],
            edgecolors="none",
        )
        axis.errorbar(
            position,
            average,
            yerr=[[average - low], [high - average]],
            color=style["color"],
            marker=style["marker"],
            markersize=7,
            capsize=4,
            label=component if component not in labelled else None,
        )
        labelled.add(component)
        labels.append(label)
    axis.set_xticks(range(len(labels)), labels)
    axis.set_yscale("log")
    axis.set_ylabel("Elapsed time (ms, logarithmic scale)")
    axis.set_title("TLS and PQC handshake timing components", weight="bold")
    axis.grid(axis="y", color="#D7DADF", linewidth=0.7)
    axis.legend(title="Measurement")
    _add_footer(
        figure,
        "Each point isolates the labeled component. PQC exchange is the application-layer "
        "ML-KEM, ML-DSA, KDF, and Finished exchange; total channel-establishment time is "
        "reported as Channel ready in the scaling figures.",
        bottom_fraction=0.14,
    )
    return figure


def _paired_effects_figure(
    paired: list[dict[str, object]],
    endpoint: str,
    specs: tuple[MetricSpec, ...],
    payload_bytes: int,
) -> Figure:
    selected = {
        (spec.metric, comparison): _select_paired(
            paired,
            payload_bytes,
            endpoint,
            spec.metric,
            *comparison,
        )
        for spec in specs
        for comparison in PAIRED_MODE_COMPARISONS
    }
    if any(int(row["relative_paired_n"]) < 2 for row in selected.values()):
        raise ValueError("paired-effect figures require at least two relative changes")
    lows = [float(row["relative_percent_ci95_low"]) for row in selected.values()]
    highs = [float(row["relative_percent_ci95_high"]) for row in selected.values()]
    span = max(highs) - min(lows)
    padding = max(2.0, span * 0.12)
    paired_counts = {int(row["relative_paired_n"]) for row in selected.values()}
    count_text = (
        f"{paired_counts.pop()} within-repetition changes"
        if len(paired_counts) == 1
        else "within-repetition changes"
    )

    figure, axis = plt.subplots(figsize=(10.8, 6.2), layout="constrained")
    positions = list(reversed(range(len(specs))))
    for comparison in PAIRED_MODE_COMPARISONS:
        style = COMPARISON_STYLE[comparison]
        reference_mode, candidate_mode = comparison
        for position, spec in zip(positions, specs):
            row = selected[spec.metric, comparison]
            average = float(row["relative_percent_mean"])
            low = float(row["relative_percent_ci95_low"])
            high = float(row["relative_percent_ci95_high"])
            axis.errorbar(
                average,
                position + float(style["offset"]),
                xerr=[[average - low], [high - average]],
                color=style["color"],
                marker=style["marker"],
                capsize=3,
                linewidth=1.5,
                label=(
                    f"{MODE_STYLE[candidate_mode]['label']} vs "
                    f"{MODE_STYLE[reference_mode]['label']}"
                    if position == positions[0]
                    else None
                ),
            )
    axis.axvline(0, color="#20242A", linewidth=1, linestyle=(0, (3, 3)))
    axis.set_xlim(min(lows) - padding, max(highs) + padding)
    axis.set_ylim(-0.55, len(specs) + 0.1)
    axis.set_yticks(positions, [spec.title for spec in specs])
    axis.set_xlabel("Paired change in candidate relative to reference (%)")
    axis.set_title(
        f"{endpoint.capitalize()} effects at "
        f"{_size_label(payload_bytes)} per direction",
        weight="bold",
    )
    axis.grid(axis="x", color="#D7DADF", linewidth=0.7)
    axis.legend(loc="upper left", fontsize=8.5)
    _add_footer(
        figure,
        "Each estimate compares the named metric between two runs in the same repetition; "
        f"it is not a PQC-only time estimate.\nMeans use {count_text}; bars are 95% Student-t "
        "intervals on this host.",
        bottom_fraction=0.14,
    )
    return figure


def _add_footer(figure: Figure, text: str, *, bottom_fraction: float) -> None:
    layout = figure.get_layout_engine()
    if layout is None:
        raise RuntimeError("figure footer requires a constrained layout engine")
    layout.set(rect=(0, bottom_fraction, 1, 1 - bottom_fraction))
    figure.text(0.5, 0.015, text, ha="center", fontsize=8.5, color="#4A4F57")


def _write_effect_table(
    path: Path,
    summary: list[dict[str, object]],
    paired: list[dict[str, object]],
    endpoint: str,
    specs: tuple[MetricSpec, ...],
    payload_bytes: int,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = (
        "legacy_metric",
        "current_metric",
        "current_estimand",
        "payload_bytes_per_direction",
        "reference_mode",
        "reference_mean",
        "reference_ci95_low",
        "reference_ci95_high",
        "candidate_mode",
        "candidate_mean",
        "candidate_ci95_low",
        "candidate_ci95_high",
        "paired_n",
        "paired_relative_n",
        "paired_relative_percent_mean",
        "paired_relative_percent_ci95_low",
        "paired_relative_percent_ci95_high",
    )
    with path.open("w", encoding="utf-8", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=fields)
        writer.writeheader()
        for spec in specs:
            for reference_mode, candidate_mode in PAIRED_MODE_COMPARISONS:
                reference = _select_summary(
                    summary, reference_mode, payload_bytes, endpoint, spec.metric
                )
                candidate = _select_summary(
                    summary, candidate_mode, payload_bytes, endpoint, spec.metric
                )
                comparison = _select_paired(
                    paired,
                    payload_bytes,
                    endpoint,
                    spec.metric,
                    reference_mode,
                    candidate_mode,
                )
                writer.writerow(
                    {
                        "legacy_metric": spec.legacy_metric,
                        "current_metric": spec.metric,
                        "current_estimand": spec.title,
                        "payload_bytes_per_direction": payload_bytes,
                        "reference_mode": reference_mode,
                        "reference_mean": reference["mean"],
                        "reference_ci95_low": reference["ci95_low"],
                        "reference_ci95_high": reference["ci95_high"],
                        "candidate_mode": candidate_mode,
                        "candidate_mean": candidate["mean"],
                        "candidate_ci95_low": candidate["ci95_low"],
                        "candidate_ci95_high": candidate["ci95_high"],
                        "paired_n": comparison["paired_n"],
                        "paired_relative_n": comparison["relative_paired_n"],
                        "paired_relative_percent_mean": comparison[
                            "relative_percent_mean"
                        ],
                        "paired_relative_percent_ci95_low": comparison[
                            "relative_percent_ci95_low"
                        ],
                        "paired_relative_percent_ci95_high": comparison[
                            "relative_percent_ci95_high"
                        ],
                    }
                )


def _select_summary(
    summary: list[dict[str, object]],
    mode: str,
    payload_bytes: int,
    endpoint: str,
    metric: str,
) -> dict[str, object]:
    selected = [
        row
        for row in summary
        if row["mode"] == mode
        and row["payload_bytes"] == payload_bytes
        and row["endpoint"] == endpoint
        and row["metric"] == metric
    ]
    if len(selected) != 1:
        raise ValueError(
            f"expected one summary row for {endpoint} {mode} {metric} {payload_bytes}"
        )
    return selected[0]


def _select_paired(
    paired: list[dict[str, object]],
    payload_bytes: int,
    endpoint: str,
    metric: str,
    reference_mode: str,
    candidate_mode: str,
) -> dict[str, object]:
    selected = [
        row
        for row in paired
        if row["payload_bytes"] == payload_bytes
        and row["endpoint"] == endpoint
        and row["metric"] == metric
        and row["reference_mode"] == reference_mode
        and row["candidate_mode"] == candidate_mode
    ]
    if len(selected) != 1:
        raise ValueError(
            f"expected one {reference_mode}-to-{candidate_mode} paired row for "
            f"{endpoint} {metric} {payload_bytes}"
        )
    return selected[0]


def _raw_values(
    runs: list[dict[str, object]],
    mode: str,
    payload_bytes: int,
    endpoint: str,
    metric: str,
) -> list[float]:
    field = f"{endpoint}_{metric}"
    selected = sorted(
        (
            (int(run["repetition"]), float(run[field]))
            for run in runs
            if run["mode"] == mode
            and run["payload_bytes"] == payload_bytes
            and run.get(field) not in (None, "")
        ),
        key=lambda item: item[0],
    )
    if not selected:
        raise ValueError(
            f"no raw values for {endpoint} {mode} {metric} {payload_bytes}"
        )
    return [value for _repetition, value in selected]


def _read_status(path: Path) -> dict[str, object]:
    rows = _read_csv(path)
    if len(rows) != 1:
        raise ValueError("status.csv must contain exactly one row")
    row = rows[0]
    status = {
        "attempted_runs": _parse_int(row, "attempted_runs"),
        "failed_runs": _parse_int(row, "failed_runs"),
        "successful_runs": _parse_int(row, "successful_runs"),
        "valid": _parse_bool(row, "valid"),
        "warmup_failed": _parse_bool(row, "warmup_failed"),
    }
    if (
        status["valid"] is not True
        or status["warmup_failed"] is not False
        or status["failed_runs"] != 0
    ):
        raise ValueError("refusing to plot an invalid benchmark")
    return status


def _read_runs(path: Path) -> list[dict[str, object]]:
    rows = _read_csv(path)
    for row in rows:
        row["success"] = _parse_bool(row, "success")
        row["payload_bytes"] = _parse_int(row, "payload_bytes")
        row["repetition"] = _parse_int(row, "repetition")
        row["execution_order"] = _parse_int(row, "execution_order")
    return rows


def _read_numeric_table(
    path: Path, *, integer_fields: set[str]
) -> list[dict[str, object]]:
    rows = _read_csv(path)
    for row in rows:
        for field, value in tuple(row.items()):
            if field in integer_fields:
                row[field] = _parse_int(row, field)
            elif (
                field
                not in {
                    "mode",
                    "endpoint",
                    "metric",
                    "reference_mode",
                    "candidate_mode",
                }
                and value != ""
            ):
                try:
                    row[field] = float(value)
                except ValueError as error:
                    raise ValueError(
                        f"{path.name} field {field} is not numeric"
                    ) from error
                if not math.isfinite(row[field]):
                    raise ValueError(f"{path.name} field {field} is not finite")
    return rows


def _read_manifest(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("cannot read manifest.json") from error
    if not isinstance(value, dict) or not isinstance(value.get("benchmark"), dict):
        raise ValueError("manifest.json has no benchmark plan")
    return value


def _validate_evidence(
    manifest: dict[str, object],
    status: dict[str, object],
    runs: list[dict[str, object]],
    summary: list[dict[str, object]],
    paired: list[dict[str, object]],
) -> list[int]:
    plan = manifest["benchmark"]
    try:
        raw_modes = plan["modes"]
        raw_sizes = plan["payload_sizes_bytes"]
        repetitions = plan["runs_per_condition"]
        warmups = plan["warmups_per_mode"]
        seed = plan["randomization_seed"]
        timeout_seconds = plan["timeout_seconds"]
        network = plan["network"]
        server_name = plan["server_name"]
        mode_labels = plan["mode_labels"]
        tls_groups = plan["tls_group_by_mode"]
        comparisons = plan["paired_mode_comparisons"]
    except KeyError as error:
        raise ValueError("manifest.json has an invalid benchmark plan") from error
    if (
        not isinstance(raw_modes, list)
        or not all(isinstance(mode, str) for mode in raw_modes)
        or not isinstance(raw_sizes, list)
        or any(
            isinstance(size, bool) or not isinstance(size, int) for size in raw_sizes
        )
        or isinstance(repetitions, bool)
        or not isinstance(repetitions, int)
        or isinstance(warmups, bool)
        or not isinstance(warmups, int)
        or isinstance(seed, bool)
        or not isinstance(seed, int)
        or isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not isinstance(network, str)
        or not isinstance(server_name, str)
        or not isinstance(mode_labels, dict)
        or not isinstance(tls_groups, dict)
        or not isinstance(comparisons, list)
    ):
        raise ValueError("manifest.json has an invalid benchmark plan")
    modes = tuple(raw_modes)
    sizes = raw_sizes
    if (
        modes != MODES
        or modes != tuple(MODE_STYLE)
        or mode_labels != {mode: str(MODE_STYLE[mode]["label"]) for mode in MODES}
        or tls_groups != TLS_GROUP_BY_MODE
        or comparisons != [list(pair) for pair in PAIRED_MODE_COMPARISONS]
        or repetitions < 2
        or warmups < 1
        or not math.isfinite(timeout_seconds)
        or timeout_seconds <= 0
        or network != "TCP over IPv4 loopback; no network emulation"
        or not server_name
        or not sizes
        or len(sizes) != len(set(sizes))
        or any(size <= 0 or size > MAX_TRANSFER_BYTES for size in sizes)
    ):
        raise ValueError("manifest.json has an unsupported benchmark plan")

    expected_runs = len(modes) * len(sizes) * repetitions
    if status != {
        "attempted_runs": expected_runs,
        "failed_runs": 0,
        "successful_runs": expected_runs,
        "valid": True,
        "warmup_failed": False,
    }:
        raise ValueError("benchmark status disagrees with its manifest")
    if len(runs) != expected_runs or any(not run["success"] for run in runs):
        raise ValueError("raw observations disagree with benchmark status")
    if [run["execution_order"] for run in runs] != list(range(1, expected_runs + 1)):
        raise ValueError("raw observations have an invalid execution order")
    run_ids = [str(run.get("run_id", "")) for run in runs]
    if any(not run_id for run_id in run_ids) or len(run_ids) != len(set(run_ids)):
        raise ValueError("raw observations have missing or duplicate run identifiers")

    expected_counts = Counter(
        {(mode, size): repetitions for mode in modes for size in sizes}
    )
    actual_counts = Counter((run.get("mode"), run["payload_bytes"]) for run in runs)
    if actual_counts != expected_counts:
        raise ValueError("raw observations do not contain the manifest condition grid")
    expected_repetitions = set(range(1, repetitions + 1))
    for mode, size in expected_counts:
        observed = {
            run["repetition"]
            for run in runs
            if run.get("mode") == mode and run["payload_bytes"] == size
        }
        if observed != expected_repetitions:
            raise ValueError(f"{mode} {size} has missing or duplicate repetitions")
    for run in runs:
        _validate_raw_run(run)

    _validate_summary(runs, summary, modes, sizes)
    _validate_paired(runs, paired, sizes, repetitions)
    return sorted(sizes)


def _validate_raw_run(run: dict[str, object]) -> None:
    try:
        completed = datetime.fromisoformat(str(run["completed_utc"]))
    except (KeyError, ValueError) as error:
        raise ValueError("raw observation has an invalid completion time") from error
    if completed.tzinfo is None or completed.utcoffset() is None:
        raise ValueError("raw observation completion time has no UTC offset")
    if completed.utcoffset().total_seconds() != 0:
        raise ValueError("raw observation completion time is not UTC")
    mode = str(run["mode"])
    payload = str(run["payload_bytes"])
    expected_alpn = ALPN_IDS[mode].decode("ascii")
    expected_group = TLS_GROUP_BY_MODE[mode]
    for endpoint in ("client", "server"):
        expected = {
            f"{endpoint}_success": "True",
            f"{endpoint}_endpoint": endpoint,
            f"{endpoint}_mode": mode,
            f"{endpoint}_payload_bytes": payload,
            f"{endpoint}_tls_version": "TLSv1.3",
            f"{endpoint}_tls_group": expected_group,
            f"{endpoint}_alpn": expected_alpn,
            f"{endpoint}_error_type": "",
            f"{endpoint}_error": "",
        }
        if any(str(run.get(field, "")) != value for field, value in expected.items()):
            raise ValueError(
                f"raw {endpoint} observation has inconsistent identity fields"
            )
    if run.get("error_type") or run.get("error"):
        raise ValueError("successful raw observation contains a run error")
    if run.get("client_tls_cipher") != run.get("server_tls_cipher"):
        raise ValueError("Alice and Bob report different TLS cipher suites")
    if run.get("client_tls_group") != run.get("server_tls_group"):
        raise ValueError("Alice and Bob report different TLS key-exchange groups")
    if run.get("client_tls_cipher") not in ALLOWED_TLS13_CIPHERS:
        raise ValueError("raw observation has an invalid TLS 1.3 cipher suite")

    for field, value in run.items():
        if value in (None, "") or not (
            field.endswith("_ms")
            or field.endswith("_mbps")
            or field.endswith("_bytes_sent")
            or field.endswith("_bytes_received")
        ):
            continue
        try:
            number = float(value)
        except (TypeError, ValueError) as error:
            raise ValueError(f"raw observation field {field} is not numeric") from error
        if not math.isfinite(number) or number < 0:
            raise ValueError(
                f"raw observation field {field} must be finite and nonnegative"
            )


def _validate_summary(
    runs: list[dict[str, object]],
    summary: list[dict[str, object]],
    modes: tuple[str, ...],
    sizes: list[int],
) -> None:
    keys = [
        (
            row.get("mode"),
            row.get("payload_bytes"),
            row.get("endpoint"),
            row.get("metric"),
        )
        for row in summary
    ]
    if len(keys) != len(set(keys)):
        raise ValueError("summary.csv contains duplicate estimates")
    expected_keys = _expected_summary_keys(runs, modes, sizes)
    if set(keys) != expected_keys:
        raise ValueError("summary.csv is incomplete or contains unknown estimates")
    for row in summary:
        values = _raw_values(
            runs,
            str(row["mode"]),
            int(row["payload_bytes"]),
            str(row["endpoint"]),
            str(row["metric"]),
        )
        expected = _descriptive_statistics(values)
        if int(row["attempted"]) != len(values) or int(row["n"]) != len(values):
            raise ValueError("summary.csv count disagrees with raw observations")
        _require_matching_statistics(row, expected, prefix="")


def _expected_summary_keys(
    runs: list[dict[str, object]], modes: tuple[str, ...], sizes: list[int]
) -> set[tuple[object, object, object, object]]:
    excluded = {
        "success",
        "endpoint",
        "mode",
        "payload_bytes",
        "tls_version",
        "tls_cipher",
        "tls_group",
        "alpn",
        "error_type",
        "error",
    }
    keys: set[tuple[object, object, object, object]] = set()
    for endpoint in ("client", "server"):
        prefix = f"{endpoint}_"
        metrics = {
            field.removeprefix(prefix)
            for field in runs[0]
            if field.startswith(prefix) and field.removeprefix(prefix) not in excluded
        }
        for mode in modes:
            for size in sizes:
                for metric in metrics:
                    if any(
                        run.get(f"{endpoint}_{metric}") not in (None, "")
                        for run in runs
                        if run["mode"] == mode and run["payload_bytes"] == size
                    ):
                        keys.add((mode, size, endpoint, metric))
    return keys


def _validate_paired(
    runs: list[dict[str, object]],
    paired: list[dict[str, object]],
    sizes: list[int],
    repetitions: int,
) -> None:
    keys = [
        (
            row.get("reference_mode"),
            row.get("candidate_mode"),
            row.get("payload_bytes"),
            row.get("endpoint"),
            row.get("metric"),
        )
        for row in paired
    ]
    if len(keys) != len(set(keys)):
        raise ValueError("paired-comparisons.csv contains duplicate estimates")
    summary_keys = _expected_summary_keys(runs, tuple(MODE_STYLE), sizes)
    expected_keys = {
        (reference_mode, candidate_mode, size, endpoint, metric)
        for reference_mode, candidate_mode in PAIRED_MODE_COMPARISONS
        for mode, size, endpoint, metric in summary_keys
        if mode == reference_mode
        and (candidate_mode, size, endpoint, metric) in summary_keys
    }
    if set(keys) != expected_keys:
        raise ValueError(
            "paired-comparisons.csv is incomplete or contains unknown estimates"
        )
    indexed = {
        (run["repetition"], run["mode"], run["payload_bytes"]): run for run in runs
    }
    for row in paired:
        differences: list[float] = []
        relative_changes: list[float] = []
        field = f"{row['endpoint']}_{row['metric']}"
        reference_mode = str(row["reference_mode"])
        candidate_mode = str(row["candidate_mode"])
        for repetition in range(1, repetitions + 1):
            reference = float(
                indexed[repetition, reference_mode, row["payload_bytes"]][field]
            )
            candidate = float(
                indexed[repetition, candidate_mode, row["payload_bytes"]][field]
            )
            differences.append(candidate - reference)
            if reference != 0:
                relative_changes.append(100 * (candidate - reference) / reference)
        if int(row["paired_n"]) != len(differences):
            raise ValueError("paired comparison count disagrees with raw observations")
        _require_matching_statistics(
            row, _descriptive_statistics(differences), prefix="difference_"
        )
        if int(row["relative_paired_n"]) != len(relative_changes):
            raise ValueError("relative paired count disagrees with raw observations")
        if len(relative_changes) >= 2:
            _require_matching_statistics(
                row,
                _descriptive_statistics(relative_changes),
                prefix="relative_percent_",
            )
        elif any(
            row.get(f"relative_percent_{field}") not in (None, "")
            for field in (
                "mean",
                "median",
                "standard_deviation",
                "ci95_low",
                "ci95_high",
                "minimum",
                "maximum",
            )
        ):
            raise ValueError("relative interval requires at least two observations")


def _descriptive_statistics(values: list[float]) -> dict[str, float]:
    average, low, high = _mean_interval(values)
    return {
        "mean": average,
        "median": median(values),
        "standard_deviation": stdev(values),
        "ci95_low": low,
        "ci95_high": high,
        "minimum": min(values),
        "maximum": max(values),
    }


def _require_matching_statistics(
    row: dict[str, object], expected: dict[str, float], *, prefix: str
) -> None:
    for field, value in expected.items():
        actual = row.get(f"{prefix}{field}")
        if not isinstance(actual, (int, float)) or not math.isclose(
            actual, value, rel_tol=1e-12, abs_tol=1e-12
        ):
            raise ValueError(
                f"derived statistic {prefix}{field} disagrees with raw data"
            )


def _read_csv(path: Path) -> list[dict[str, object]]:
    try:
        with path.open(encoding="utf-8", newline="") as source:
            rows = list(csv.DictReader(source))
    except OSError as error:
        raise ValueError(f"cannot read {path.name}") from error
    if not rows:
        raise ValueError(f"{path.name} contains no records")
    return [dict(row) for row in rows]


def _parse_int(row: dict[str, object], field: str) -> int:
    try:
        return int(str(row[field]))
    except (KeyError, ValueError) as error:
        raise ValueError(f"field {field} is not an integer") from error


def _parse_bool(row: dict[str, object], field: str) -> bool:
    try:
        value = str(row[field]).lower()
    except KeyError as error:
        raise ValueError(f"field {field} is missing") from error
    if value not in {"true", "false"}:
        raise ValueError(f"field {field} is not Boolean")
    return value == "true"


def _mean_interval(values: list[float]) -> tuple[float, float, float]:
    if len(values) < 2:
        raise ValueError(
            "at least two observations are required for a confidence interval"
        )
    average = mean(values)
    margin = t.ppf(0.975, len(values) - 1) * stdev(values) / math.sqrt(len(values))
    return average, average - margin, average + margin


def _size_label(size: int) -> str:
    for divisor, suffix in (
        (1024**3, "GiB"),
        (1024**2, "MiB"),
        (1024, "KiB"),
    ):
        if size >= divisor and size % divisor == 0:
            return f"{size // divisor} {suffix}"
    return f"{size:,} B"


def _size_slug(size: int) -> str:
    return _size_label(size).lower().replace(" ", "")


def _save_figure(figure: Figure, path: Path, title: str) -> tuple[Path, Path]:
    path.parent.mkdir(parents=True, exist_ok=True)
    png = path.with_suffix(".png")
    svg = path.with_suffix(".svg")
    figure.savefig(
        png,
        dpi=300,
        bbox_inches="tight",
        metadata={
            "Software": "TLS-PQC Bridge plot renderer",
            "Title": title,
        },
    )
    figure.savefig(
        svg,
        bbox_inches="tight",
        metadata={
            "Creator": "TLS-PQC Bridge plot renderer",
            "Title": title,
            "Date": None,
        },
    )
    plt.close(figure)
    return png, svg


def handshake_figure() -> Figure:
    figure = Figure(figsize=(12, 8.2), layout="constrained")
    axis = figure.subplots()
    axis.set(xlim=(0, 10), ylim=(0, 11))
    axis.axis("off")

    _stage(axis, 8.1, 10.1, "1  Stock TLS 1.3 plane with X25519", "#E8F3FA")
    _stage(axis, 3.7, 8.0, "2  Exporter-bound PQC plane", "#FFF1E6")
    _stage(axis, 0.6, 3.6, "3  Verified application exchange", "#E8F5F0")
    _actor(axis, 1.6, "Client")
    _actor(axis, 8.4, "Server")

    _double_arrow(
        axis,
        9.25,
        "Stock TLS 1.3 handshake: X25519, certificate chain, service identity, ALPN",
        TLS_COLOR,
    )
    axis.text(
        5,
        8.55,
        "Both derive k1 = TLS-Exporter(label, context, 32 bytes)",
        ha="center",
        va="center",
        color=TLS_COLOR,
        weight="bold",
    )

    _message(
        axis,
        7.45,
        8.4,
        1.6,
        "SERVER_INIT: nonce + ephemeral ML-KEM-768 key + ML-DSA-65 signature",
        PQ_COLOR,
    )
    axis.text(
        1.75,
        6.95,
        "Verify with pinned ML-DSA identity\nthen encapsulate → k2",
        ha="left",
        va="center",
        fontsize=9.5,
        color=NEUTRAL,
    )
    _message(
        axis,
        6.35,
        1.6,
        8.4,
        "CLIENT_KEM: ML-KEM ciphertext",
        PQ_COLOR,
    )
    axis.text(
        8.25,
        5.9,
        "Decapsulate → k2",
        ha="right",
        va="center",
        fontsize=9.5,
        color=NEUTRAL,
    )
    _center_box(
        axis,
        4.85,
        "Both: CatKDF(k1 || k2, protocol IDs, identity, exact frames)\n"
        "→ Finished keys + client/server AES-256-GCM keys and IVs",
        "#DFF2EA",
        KEY_COLOR,
    )
    _message(axis, 4.15, 8.4, 1.6, "SERVER_FINISHED: HMAC confirmation", KEY_COLOR)
    _message(axis, 3.75, 1.6, 8.4, "CLIENT_FINISHED: HMAC confirmation", KEY_COLOR)

    _double_arrow(axis, 2.95, "PING / PONG inside the negotiated channel", KEY_COLOR)
    _message(
        axis,
        2.25,
        1.6,
        8.4,
        "Authenticated streamed upload: start, data*, digest",
        KEY_COLOR,
    )
    _message(
        axis,
        1.55,
        8.4,
        1.6,
        "Verified returned copy: start, data*, digest",
        KEY_COLOR,
    )
    _message(axis, 0.9, 1.6, 8.4, "TRANSFER_ACK", KEY_COLOR)

    axis.text(
        5,
        0.15,
        "Bridge-protected application messages use sequence-bound, direction-specific records. "
        "The PQC exchange adds four one-way flights and 5,725 protocol-framed bytes.",
        ha="center",
        va="bottom",
        fontsize=8.8,
        color=NEUTRAL,
    )
    figure.suptitle("TLS-PQC Bridge version 1 over classical X25519 TLS", weight="bold")
    return figure


def security_boundary_figure() -> Figure:
    figure = Figure(figsize=(12, 7.4), layout="constrained")
    axis = figure.subplots()
    axis.set(xlim=(0, 12), ylim=(0, 9.2))
    axis.axis("off")

    _security_input(axis, 0.5, 7.25, 2.6, 0.9, "k1\nTLS exporter", "#E8F3FA", TLS_COLOR)
    _security_input(
        axis, 0.5, 5.95, 2.6, 0.9, "k2\nML-KEM-768 secret", "#FFF1E6", PQ_COLOR
    )
    _security_input(
        axis,
        4.15,
        6.6,
        3.2,
        0.95,
        "Transcript-bound CatKDF",
        "#E8F5F0",
        KEY_COLOR,
    )
    _security_input(
        axis,
        8.4,
        6.6,
        3.1,
        0.95,
        "Directional application keys",
        "#E8F5F0",
        KEY_COLOR,
    )
    _flow_arrow(axis, 3.1, 7.7, 4.15, 7.05, TLS_COLOR)
    _flow_arrow(axis, 3.1, 6.4, 4.15, 7.05, PQ_COLOR)
    _flow_arrow(axis, 7.35, 7.05, 8.4, 7.05, KEY_COLOR)
    axis.text(
        6,
        5.55,
        "The pinned ML-DSA signature binds the ephemeral KEM key and server identity to k1; "
        "Finished MACs confirm equal derivation before protected records are enabled.",
        ha="center",
        va="center",
        fontsize=9.3,
        color=NEUTRAL,
    )

    headers = ("Attack condition", "Surviving enforcement", "Bounded result")
    x_positions = (0.45, 4.0, 8.55)
    widths = (3.25, 4.25, 3.05)
    for x, width, header in zip(x_positions, widths, headers):
        _table_cell(axis, x, 4.65, width, 0.55, header, "#E6E8EB", NEUTRAL, bold=True)

    rows = (
        (
            "Network attacker;\nneither plane compromised",
            "TLS authentication + PQC identity\n+ both secret inputs",
            "Protected under\nthe stated assumptions",
            "#E8F5F0",
            KEY_COLOR,
        ),
        (
            "Classical establishment and\ncertificate authentication fail",
            "Pinned ML-DSA binding\n+ unknown ML-KEM secret",
            "Bridge-protected traffic\nintended to remain protected",
            "#FFF1E6",
            PQ_COLOR,
        ),
        (
            "PQC security assumption fails;\nnegotiated TLS remains secure",
            "TLS-plane authentication\nand record protection",
            "Traffic remains\nprotected by TLS",
            "#E8F3FA",
            TLS_COLOR,
        ),
        (
            "Both plane inputs or\nendpoint memory exposed",
            "No remaining\nunknown input",
            "Outside the\nsecurity claim",
            "#F1F1F1",
            NEUTRAL,
        ),
    )
    for row_index, row in enumerate(rows):
        y = 3.75 - row_index * 0.92
        for x, width, label in zip(x_positions, widths, row[:3]):
            _table_cell(axis, x, y, width, 0.82, label, row[3], row[4])

    axis.text(
        6,
        0.1,
        "This is an assumption-bounded failover argument, not a formal authenticated-key-exchange proof. "
        "It assumes correct implementations, sound randomness, protected keys, and sound trust configuration.",
        ha="center",
        va="bottom",
        fontsize=8.8,
        color=NEUTRAL,
    )
    figure.suptitle(
        "TLS-PQC Bridge security boundary and plane-failure cases", weight="bold"
    )
    return figure


def _stage(axis: Axes, bottom: float, top: float, label: str, color: str) -> None:
    axis.add_patch(
        FancyBboxPatch(
            (0.15, bottom),
            9.7,
            top - bottom,
            boxstyle="round,pad=0.02,rounding_size=0.08",
            facecolor=color,
            edgecolor="none",
            zorder=0,
        )
    )
    axis.text(0.35, top - 0.25, label, va="top", fontsize=10, weight="bold")


def _actor(axis: Axes, x: float, label: str) -> None:
    axis.text(
        x,
        10.55,
        label,
        ha="center",
        va="center",
        fontsize=12,
        weight="bold",
        bbox={"boxstyle": "round,pad=0.4", "facecolor": "white", "edgecolor": NEUTRAL},
    )
    axis.plot(
        [x, x], [0.75, 10.25], color="#7A7F87", linewidth=1.1, linestyle=(0, (3, 3))
    )


def _message(
    axis: Axes, y: float, start: float, end: float, label: str, color: str
) -> None:
    axis.annotate(
        "",
        xy=(end, y),
        xytext=(start, y),
        arrowprops={"arrowstyle": "-|>", "color": color, "linewidth": 1.8},
    )
    axis.text(5, y + 0.14, label, ha="center", va="bottom", fontsize=9.2, color=NEUTRAL)


def _double_arrow(axis: Axes, y: float, label: str, color: str) -> None:
    axis.annotate(
        "",
        xy=(8.4, y),
        xytext=(1.6, y),
        arrowprops={"arrowstyle": "<|-|>", "color": color, "linewidth": 2},
    )
    axis.text(5, y + 0.14, label, ha="center", va="bottom", fontsize=9.2, color=NEUTRAL)


def _center_box(axis: Axes, y: float, label: str, face: str, edge: str) -> None:
    axis.text(
        5,
        y,
        label,
        ha="center",
        va="center",
        fontsize=9.3,
        color=NEUTRAL,
        bbox={"boxstyle": "round,pad=0.42", "facecolor": face, "edgecolor": edge},
    )


def _security_input(
    axis: Axes,
    x: float,
    y: float,
    width: float,
    height: float,
    label: str,
    face: str,
    edge: str,
) -> None:
    axis.add_patch(
        FancyBboxPatch(
            (x, y),
            width,
            height,
            boxstyle="round,pad=0.03,rounding_size=0.08",
            facecolor=face,
            edgecolor=edge,
            linewidth=1.4,
        )
    )
    axis.text(
        x + width / 2, y + height / 2, label, ha="center", va="center", weight="bold"
    )


def _flow_arrow(
    axis: Axes, x1: float, y1: float, x2: float, y2: float, color: str
) -> None:
    axis.annotate(
        "",
        xy=(x2, y2),
        xytext=(x1, y1),
        arrowprops={"arrowstyle": "-|>", "color": color, "linewidth": 2},
    )


def _table_cell(
    axis: Axes,
    x: float,
    y: float,
    width: float,
    height: float,
    text: str,
    face: str,
    edge: str,
    *,
    bold: bool = False,
) -> None:
    axis.add_patch(
        FancyBboxPatch(
            (x, y),
            width,
            height,
            boxstyle="square,pad=0",
            facecolor=face,
            edgecolor="white",
            linewidth=2,
        )
    )
    axis.text(
        x + 0.12,
        y + height / 2,
        text,
        ha="left",
        va="center",
        wrap=True,
        fontsize=8.0,
        weight="bold" if bold else "normal",
        color=edge,
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Recreate the TLS-PQC Bridge research figures"
    )
    parser.add_argument("results", type=Path)
    arguments = parser.parse_args()
    for path in plot_results(arguments.results):
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
