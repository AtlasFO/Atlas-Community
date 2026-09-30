"""Atlas live-monitoring subsystem.

Contains:
  - artifacts/    Velociraptor artifact YAML templates for Custom.Atlas.*
                  detectors (process exec, persistence, network, YARA) and
                  Custom.Atlas.Respond.* remediation actions.
  - render.py     string.Template-based artifact rendering — substitutes
                  baseline allowlists into the parameterized VQL.
"""
