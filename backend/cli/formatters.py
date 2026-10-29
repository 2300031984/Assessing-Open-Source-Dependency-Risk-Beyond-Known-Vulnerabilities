"""
Output formatters for CYBER-100 CLI.
Provides clean JSON serialization and report file export.
"""

import json
from pathlib import Path
from datetime import datetime
from typing import Any, Dict

def _json_serial(obj: Any) -> Any:
    """JSON serializer for objects not serializable by default json code."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    if hasattr(obj, "model_dump"):
        return obj.model_dump()
    if hasattr(obj, "__dict__"):
        return obj.__dict__
    return str(obj)

def prepare_clean_analysis_dict(data: Dict[str, Any]) -> Dict[str, Any]:
    """Ensure all internal objects in analysis data are cleanly serializable."""
    clean = {}
    for key, value in data.items():
        if key == "risk_factors" and isinstance(value, dict):
            factors_dict = {}
            for f_name, f_val in value.items():
                if hasattr(f_val, "model_dump"):
                    factors_dict[f_name] = f_val.model_dump()
                elif hasattr(f_val, "__dict__"):
                    factors_dict[f_name] = f_val.__dict__
                elif isinstance(f_val, dict):
                    factors_dict[f_name] = f_val
                else:
                    factors_dict[f_name] = str(f_val)
            clean[key] = factors_dict
        elif hasattr(value, "model_dump"):
            clean[key] = value.model_dump()
        else:
            clean[key] = value
    return clean

def serialize_analysis_json(data: Dict[str, Any]) -> str:
    """Serialize analysis data to formatted, valid JSON string."""
    clean_data = prepare_clean_analysis_dict(data)
    return json.dumps(clean_data, indent=2, default=_json_serial)

def save_report_file(data: Dict[str, Any], output_path: Path) -> Path:
    """
    Export analysis data as JSON to user-specified path.
    Creates parent directories if necessary and handles IO errors.
    """
    resolved_path = output_path.resolve()
    resolved_path.parent.mkdir(parents=True, exist_ok=True)
    json_str = serialize_analysis_json(data)
    with open(resolved_path, "w", encoding="utf-8") as f:
        f.write(json_str)
        f.write("\n")
    return resolved_path
