"""SARIF 2.1.0 format generator for CI and GitHub Code Scanning integration."""

import json
from typing import Any

from errataguard import __version__
from errataguard.reporting.models import AnalysisReport


def format_sarif_report(report: AnalysisReport, indent: int = 2) -> str:
    """Generate SARIF 2.1.0 output for an AnalysisReport."""
    rules_dict: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for f in report.findings:
        if f.erratum_id not in rules_dict:
            rules_dict[f.erratum_id] = {
                "id": f.erratum_id,
                "name": f.title.replace(" ", "_"),
                "shortDescription": {
                    "text": f.title,
                },
                "fullDescription": {
                    "text": f"{f.title}. Workaround: {f.workaround}",
                },
                "help": {
                    "text": f"Erratum ID: {f.erratum_id}\nWorkaround: {f.workaround}\nReferences: {', '.join(f.references)}",
                },
                "properties": {
                    "problem.severity": "warning",
                },
            }

        # Location building
        loc_uri = f.source_file or str(report.binary_path)
        region: dict[str, Any] = {}
        if f.source_line is not None and f.source_line > 0:
            region["startLine"] = f.source_line
        else:
            region["startLine"] = 1

        results.append({
            "ruleId": f.erratum_id,
            "level": "warning",
            "message": {
                "text": f"Hardware erratum trigger detected at 0x{f.address:08X} in function {f.function or '<unknown>'}: {f.title}. Conditions: {', '.join(f.matched_conditions)}",
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": loc_uri.replace("\\", "/"),
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": region,
                    },
                }
            ],
            "properties": {
                "address": f"0x{f.address:08X}",
                "function": f.function or "<unknown>",
                "confidence": f.confidence,
                "conditions": list(f.matched_conditions),
            },
        })

    sarif_data = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ErrataGuard",
                        "version": __version__,
                        "informationUri": "https://github.com/errataguard/errataguard",
                        "rules": list(rules_dict.values()),
                    }
                },
                "artifacts": [
                    {
                        "location": {
                            "uri": str(report.binary_path).replace("\\", "/"),
                        },
                        "hashes": {
                            "sha-256": report.binary_sha256,
                        },
                    }
                ],
                "results": results,
            }
        ],
    }

    return json.dumps(sarif_data, indent=indent)
