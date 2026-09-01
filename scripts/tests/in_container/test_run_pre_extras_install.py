# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
from __future__ import annotations

import hashlib
import io
import re
from pathlib import Path
from unittest import mock

import pytest
import run_pre_extras_install as m

ARCHIVE_CONTENT = b"pretend this is an SDK tarball"
ARCHIVE_SHA256 = hashlib.sha256(ARCHIVE_CONTENT).hexdigest()
URL = "https://example.com/sdk/9.4.0.0-Some-SDK-LinuxX64.tar.gz"

ENTRYPOINT = Path(__file__).parents[2] / "docker" / "entrypoint_ci.sh"


class TestDownloadFailureExitCodes:
    @pytest.mark.parametrize("fallback_ips", [None, ["10.0.0.1", "10.0.0.2"]], ids=["dns-only", "fallbacks"])
    @mock.patch.object(m, "_attempt_download", side_effect=TimeoutError("timed out"))
    def test_an_unreachable_upstream_exits_with_the_skip_code(self, mock_attempt, fallback_ips, tmp_path):
        with pytest.raises(SystemExit) as exc_info:
            m.download_with_checksum(
                URL, ARCHIVE_SHA256, tmp_path / "archive.tar.gz", fallback_ips=fallback_ips
            )

        assert exc_info.value.code == m.EXIT_CODE_UPSTREAM_UNREACHABLE
        assert mock_attempt.call_count == 1 + len(fallback_ips or [])

    @mock.patch("urllib.request.urlopen", return_value=io.BytesIO(b"not what the manifest pinned"))
    def test_a_checksum_mismatch_exits_hard_and_is_not_retried(self, mock_urlopen, tmp_path):
        with pytest.raises(SystemExit) as exc_info:
            m.download_with_checksum(
                URL, ARCHIVE_SHA256, tmp_path / "archive.tar.gz", fallback_ips=["10.0.0.1"]
            )

        assert exc_info.value.code == 1
        assert mock_urlopen.call_count == 1


def test_the_entrypoint_agrees_on_the_skip_exit_code():
    declared = re.search(r"^PRE_EXTRAS_EXIT_CODE_UPSTREAM_UNREACHABLE=(\d+)$", ENTRYPOINT.read_text(), re.M)

    assert declared is not None, f"constant not found in {ENTRYPOINT}"
    assert int(declared.group(1)) == m.EXIT_CODE_UPSTREAM_UNREACHABLE
