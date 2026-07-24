"""Rules layer: deterministic IR -> Sigma -> SIEM format conversion."""
from .sigma import ir_to_sigma, build_condition
from .converter import sigma_to_all, convert_ir

__all__ = ["ir_to_sigma", "sigma_to_all", "convert_ir", "build_condition"]
