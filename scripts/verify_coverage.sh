#!/usr/bin/env bash

set -euo pipefail

.venv/bin/pytest -q tests/coverage/test_credential_access_coverage.py
.venv/bin/pytest -q tests/coverage/test_persistence_coverage.py
.venv/bin/pytest -q tests/coverage/test_archive_exfil_coverage.py
.venv/bin/pytest -q tests/coverage/test_post_auth_abuse_coverage.py
.venv/bin/pytest -q tests/coverage/test_log_tamper_coverage.py
.venv/bin/pytest -q tests/coverage/test_tool_install_abuse_coverage.py
.venv/bin/pytest -q tests/coverage/test_web_post_exploitation_coverage.py
.venv/bin/pytest -q tests/coverage/test_container_abuse_coverage.py
.venv/bin/pytest -q tests/coverage/test_tunnel_c2_coverage.py
.venv/bin/pytest -q tests/coverage/test_downloader_stager_coverage.py
.venv/bin/pytest -q tests/coverage/test_lateral_movement_coverage.py
.venv/bin/pytest -q tests/coverage/test_impact_destructive_coverage.py
