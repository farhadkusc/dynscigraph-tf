#!/usr/bin/env python3
"""Write docs/figures/results.svg from benchmarks/results/evaluation.json."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    report = json.loads((ROOT / "benchmarks" / "results" / "evaluation.json").read_text())
    runs = report["attack"]["runs"]
    labels = [r["cutoff"][:4] for r in runs]
    series = [
        ("Graph", [r["ap"] for r in runs], "#1f4e79"),
        ("Logistic", [r["baselines"]["logistic_combination"]["ap"] for r in runs], "#7f8c8d"),
        ("Degree", [r["baselines"]["technique_degree"]["ap"] for r in runs], "#5b8c5a"),
        ("Random", [r["baselines"]["random"]["ap"] for r in runs], "#c47b3a"),
    ]
    width, height = 640, 320
    left, bottom, plot_w, plot_h = 64, 48, 520, 220
    ymax = 0.012
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        '<text x="64" y="28" font-family="Georgia, serif" font-size="16" fill="#1a1a1a">ATT&CK next-year average precision</text>',
    ]
    for tick in (0, 0.004, 0.008, 0.012):
        y = bottom + plot_h - (tick / ymax) * plot_h
        parts.append(f'<line x1="{left}" y1="{y:.1f}" x2="{left + plot_w}" y2="{y:.1f}" stroke="#e6e6e6"/>')
        parts.append(
            f'<text x="{left - 8}" y="{y + 4:.1f}" text-anchor="end" font-family="sans-serif" font-size="11" fill="#444">{tick:.3f}</text>'
        )
    group_w = plot_w / len(labels)
    bar_w = 18
    for i, label in enumerate(labels):
        gx = left + i * group_w + 28
        for j, (_, values, color) in enumerate(series):
            h = (values[i] / ymax) * plot_h
            x = gx + j * (bar_w + 4)
            y = bottom + plot_h - h
            parts.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_w}" height="{h:.1f}" fill="{color}"/>')
        parts.append(
            f'<text x="{gx + 40}" y="{bottom + plot_h + 20}" text-anchor="middle" font-family="sans-serif" font-size="12" fill="#222">{label}</text>'
        )
    lx = 430
    for j, (name, _, color) in enumerate(series):
        y = 52 + j * 18
        parts.append(f'<rect x="{lx}" y="{y}" width="12" height="12" fill="{color}"/>')
        parts.append(f'<text x="{lx + 18}" y="{y + 11}" font-family="sans-serif" font-size="12" fill="#222">{name}</text>')
    parts.append("</svg>")
    out = ROOT / "docs" / "figures" / "results.svg"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(parts) + "\n")
    print(out)


if __name__ == "__main__":
    main()
