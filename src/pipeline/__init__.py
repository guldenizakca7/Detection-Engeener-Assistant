"""Pipeline layer: MITRE detection (stage 1), IR generation (stage 2), CTI processing."""
from .stage1 import detect_mitre_technique
from .stage2 import generate_ir
from .cti_processor import (
    is_cti_report,
    extract_techniques_from_report,
    extract_context_for_technique,
)
from .cache import get_cached_result, save_to_cache, clear_cache

__all__ = [
    "detect_mitre_technique",
    "generate_ir",
    "is_cti_report",
    "extract_techniques_from_report",
    "extract_context_for_technique",
    "get_cached_result",
    "save_to_cache",
    "clear_cache",
]
