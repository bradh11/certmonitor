# config.py

import os

# Default validators if not set in environment
DEFAULT_VALIDATORS = ["expiration", "hostname", "root_certificate"]

# Read from environment variable, fall back to default if not set
env_validators = os.environ.get("ENABLED_VALIDATORS")
if env_validators:
    ENABLED_VALIDATORS = [v.strip() for v in env_validators.split(",") if v.strip()]
else:
    ENABLED_VALIDATORS = DEFAULT_VALIDATORS
