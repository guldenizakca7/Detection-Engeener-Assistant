"""Convert Sigma YAML into SIEM query formats via pySigma backends."""
from __future__ import annotations

from .sigma import ir_to_sigma


def sigma_to_all(sigma_yaml: str) -> dict:
    """Convert Sigma YAML into all supported SIEM formats.

    Each backend's import and conversion is isolated in its own try/except
    so a single broken/missing backend never crashes the whole conversion;
    its value is set to None instead.

    Args:
        sigma_yaml: A Sigma rule as YAML text (e.g. from ir_to_sigma()).

    Returns:
        {"sigma": sigma_yaml, "kql": ..., "splunk": ..., "elastic": ...,
        "chronicle": ..., "crowdstrike": ..., "loki": ..., "sentinelone": ...,
        "carbonblack": ...} -- any backend that failed to import or convert
        is None instead of a string.

    Raises:
        Exception: If sigma_yaml itself is malformed and SigmaCollection.from_yaml()
            fails -- this is not caught, since it indicates a real bug upstream
            (an invalid Sigma rule), not a backend-specific problem.
    """
    from sigma.collection import SigmaCollection

    collection = SigmaCollection.from_yaml(sigma_yaml)
    results = {"sigma": sigma_yaml}

    try:
        # sigma.backends.microsoft365defender exports KustoBackend (produces KQL),
        # not "Microsoft365DefenderBackend" -- verified against the installed package.
        from sigma.backends.microsoft365defender import KustoBackend

        results["kql"] = "\n".join(KustoBackend().convert(collection))
    except Exception as exc:  # noqa: BLE001 -- isolate backend failures
        print(f"[rules] Warning: kql conversion failed: {exc}")
        results["kql"] = None

    try:
        from sigma.backends.splunk import SplunkBackend

        results["splunk"] = "\n".join(SplunkBackend().convert(collection))
    except Exception as exc:  # noqa: BLE001
        print(f"[rules] Warning: splunk conversion failed: {exc}")
        results["splunk"] = None

    try:
        from sigma.backends.elasticsearch import LuceneBackend

        results["elastic"] = "\n".join(LuceneBackend().convert(collection))
    except Exception as exc:  # noqa: BLE001
        print(f"[rules] Warning: elastic conversion failed: {exc}")
        results["elastic"] = None

    try:
        # Chronicle was rebranded to Google SecOps; the pySigma backend package
        # is pysigma-backend-secops, module sigma.backends.secops, class SecOpsBackend
        # -- "pysigma-backend-chronicle" / "ChronicleBackend" do not exist on PyPI.
        from sigma.backends.secops import SecOpsBackend

        results["chronicle"] = "\n".join(SecOpsBackend().convert(collection))
    except Exception as exc:  # noqa: BLE001
        print(f"[rules] Warning: chronicle conversion failed: {exc}")
        results["chronicle"] = None

    try:
        from sigma.backends.crowdstrike import LogScaleBackend

        results["crowdstrike"] = "\n".join(LogScaleBackend().convert(collection))
    except Exception as exc:  # noqa: BLE001
        print(f"[rules] Warning: crowdstrike conversion failed: {exc}")
        results["crowdstrike"] = None

    try:
        from sigma.backends.loki import LogQLBackend

        results["loki"] = "\n".join(LogQLBackend().convert(collection))
    except Exception as exc:  # noqa: BLE001
        print(f"[rules] Warning: loki conversion failed: {exc}")
        results["loki"] = None

    try:
        from sigma.backends.sentinelone import SentinelOneBackend

        results["sentinelone"] = "\n".join(SentinelOneBackend().convert(collection))
    except Exception as exc:  # noqa: BLE001
        print(f"[rules] Warning: sentinelone conversion failed: {exc}")
        results["sentinelone"] = None

    try:
        from sigma.backends.carbonblack import CarbonBlackBackend

        results["carbonblack"] = "\n".join(CarbonBlackBackend().convert(collection))
    except Exception as exc:  # noqa: BLE001
        print(f"[rules] Warning: carbonblack conversion failed: {exc}")
        results["carbonblack"] = None

    # qradar (pysigma-backend-QRadar-AQL) and insightidr (pysigma-backend-insightidr)
    # were requested but are intentionally NOT added: both are hard-pinned to
    # pysigma<0.12.0 even at their latest PyPI releases (0.3.2 and 0.2.4), which
    # is incompatible with the pysigma>=1.0 that the kql/splunk/elastic/chronicle
    # backends above require. Installing either one forces pip to downgrade the
    # shared pysigma core, which breaks those 4 already-working backends -- this
    # was verified by actually installing them and watching secops's import
    # break. There is no version combination that supports all of qradar,
    # insightidr, and the existing backends simultaneously; adding either would
    # require pinning pysigma back to <0.12 project-wide.

    return results


def convert_ir(ir_dict: dict) -> dict:
    """Generate a Sigma rule from an IR dict, then convert it to all SIEM formats.

    Args:
        ir_dict: A validated IR dict (see src.ir.schema.IR_SCHEMA).

    Returns:
        Same shape as sigma_to_all().
    """
    sigma_yaml = ir_to_sigma(ir_dict)
    return sigma_to_all(sigma_yaml)
