"""
Memgar Configuration Management
===============================

Handles ~/.memgarrc configuration file.
"""

import os
import json
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import List, Optional


@dataclass
class MemgarConfig:
    """
    Memgar configuration settings.
    
    Attributes:
        output_format: Output format (text, json, table)
        verbose: Enable verbose output
        color: Enable colored output
        default_mode: Default operating mode
        risk_threshold_block: Risk score threshold for BLOCK
        risk_threshold_quarantine: Risk score threshold for QUARANTINE
        enable_semantic: Enable semantic analysis
        ignore_patterns: Regex patterns to ignore
        ignore_threat_ids: Threat IDs to ignore
        api_key: API key for cloud features
        api_url: API URL for cloud features
        cloud_enabled: Enable cloud features
        custom_rules_path: Path to custom rules file
    """
    
    # Output settings
    output_format: str = "text"
    verbose: bool = False
    color: bool = True
    
    # Analysis settings
    default_mode: str = "protect"
    risk_threshold_block: int = 80
    risk_threshold_quarantine: int = 40
    enable_semantic: bool = False
    
    # Ignore patterns (for false positives)
    ignore_patterns: List[str] = field(default_factory=list)
    ignore_threat_ids: List[str] = field(default_factory=list)
    
    # Cloud settings
    api_key: Optional[str] = None
    api_url: str = "https://api.memgar.io"
    cloud_enabled: bool = False
    
    # Custom rules
    custom_rules_path: Optional[str] = None


def get_config_path() -> Path:
    """
    Get configuration file path.
    
    Checks MEMGAR_CONFIG environment variable first,
    then defaults to ~/.memgarrc
    
    Returns:
        Path to configuration file
    """
    if "MEMGAR_CONFIG" in os.environ:
        return Path(os.environ["MEMGAR_CONFIG"])
    
    return Path.home() / ".memgarrc"


def load_config() -> MemgarConfig:
    """
    Load configuration from file.
    
    Returns:
        MemgarConfig instance with loaded or default values
    """
    config_path = get_config_path()
    
    if not config_path.exists():
        return MemgarConfig()
    
    try:
        with open(config_path, "r") as f:
            data = json.load(f)
        
        return MemgarConfig(
            output_format=data.get("output_format", "text"),
            verbose=data.get("verbose", False),
            color=data.get("color", True),
            default_mode=data.get("default_mode", "protect"),
            risk_threshold_block=data.get("risk_threshold_block", 80),
            risk_threshold_quarantine=data.get("risk_threshold_quarantine", 40),
            enable_semantic=data.get("enable_semantic", False),
            ignore_patterns=data.get("ignore_patterns", []),
            ignore_threat_ids=data.get("ignore_threat_ids", []),
            api_key=data.get("api_key"),
            api_url=data.get("api_url", "https://api.memgar.io"),
            cloud_enabled=data.get("cloud_enabled", False),
            custom_rules_path=data.get("custom_rules_path"),
        )
    except (json.JSONDecodeError, KeyError) as e:
        print(f"Warning: Error loading config from {config_path}: {e}")
        return MemgarConfig()


def save_config(config: MemgarConfig) -> None:
    """
    Save configuration to file.
    
    Args:
        config: MemgarConfig instance to save
    """
    config_path = get_config_path()
    
    with open(config_path, "w") as f:
        json.dump(asdict(config), f, indent=2)


def init_config() -> Path:
    """
    Initialize configuration file with defaults.
    
    Returns:
        Path to created configuration file
    """
    config_path = get_config_path()
    
    if config_path.exists():
        return config_path
    
    default_config = MemgarConfig()
    save_config(default_config)
    
    return config_path


# Example configuration content
EXAMPLE_CONFIG = """{
  "output_format": "text",
  "verbose": false,
  "color": true,
  "default_mode": "protect",
  "risk_threshold_block": 80,
  "risk_threshold_quarantine": 40,
  "enable_semantic": false,
  "ignore_patterns": [
    "test payment",
    "example.com"
  ],
  "ignore_threat_ids": [
    "ANOM-002"
  ],
  "api_key": null,
  "api_url": "https://api.memgar.io",
  "cloud_enabled": false,
  "custom_rules_path": null
}"""
