"""IR (Intermediate Representation) layer: schema definition, validation, auto-fix."""
from .schema import IR_SCHEMA
from .validator import IRValidationError, validate_ir, auto_fix_ir, validate_and_fix

__all__ = [
    "IR_SCHEMA",
    "validate_ir",
    "auto_fix_ir",
    "validate_and_fix",
    "IRValidationError",
]
