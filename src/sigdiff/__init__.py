"""sigdiff — detection-as-code for Linux telemetry.

Sigma rules are compiled against a field mapping over three sources (auditd,
journald, ssh/sudo auth logs). Attack techniques are executed, the telemetry
they leave behind is captured, normalized and hashed into a baseline, and CI
fails when a rule, a mapping, or the host changes what that telemetry says.
"""

__version__ = "0.1.0"
