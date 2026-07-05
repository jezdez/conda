# Copyright (C) 2012 Anaconda, Inc
# SPDX-License-Identifier: BSD-3-Clause
import os
import re
from hashlib import sha256

import pytest

from conda.auxlib.ish import dals
from conda.base.constants import PREFIX_PLACEHOLDER
from conda.common.compat import on_win
from conda.core import portability
from conda.core.portability import (
    MAX_SHEBANG_LENGTH,
    SHEBANG_REGEX,
    _iter_codesign_batches,
    replace_long_shebang,
    update_prefix,
)
from conda.models.enums import FileMode

CONTENT = b"content line " * 5


def test_shebang_regex_matches():
    shebang = b"#!/simple/shebang"
    match = re.match(SHEBANG_REGEX, shebang, re.MULTILINE)
    assert match.groups() == (b"#!/simple/shebang", b"/simple/shebang", b"")

    # two lines
    shebang = b"#!/simple/shebang\nsecond line\n"
    match = re.match(SHEBANG_REGEX, shebang, re.MULTILINE)
    assert match.groups() == (b"#!/simple/shebang", b"/simple/shebang", b"")

    # with spaces
    shebang = b"#!/simple/shebang\nsecond line\n"
    match = re.match(SHEBANG_REGEX, shebang, re.MULTILINE)
    assert match.groups() == (b"#!/simple/shebang", b"/simple/shebang", b"")

    # with spaces
    shebang = b"#!    /simple/shebang\nsecond line\n"
    match = re.match(SHEBANG_REGEX, shebang, re.MULTILINE)
    assert match.groups() == (b"#!    /simple/shebang", b"/simple/shebang", b"")

    # with escaped spaces and flags
    shebang = b"#!/simple/shebang/escaped\\ space --and --flags -x\nsecond line\n"
    match = re.match(SHEBANG_REGEX, shebang, re.MULTILINE)
    assert match.groups() == (
        b"#!/simple/shebang/escaped\\ space --and --flags -x",
        b"/simple/shebang/escaped\\ space",
        b" --and --flags -x",
    )


def test_replace_simple_shebang_no_replacement():
    # simple shebang no replacement
    # NOTE: we don't do anything if the binary contains spaces! not our problem :)
    shebang = b"#!/simple/shebang/escaped\\ space --and --flags -x"
    data = b"\n".join((shebang, CONTENT, CONTENT, CONTENT))
    new_data = replace_long_shebang(FileMode.text, data)
    assert data == new_data


def test_replace_long_shebang_with_truncation_python():
    # long shebang with truncation
    #   executable name is 'python'
    shebang = b"#!/" + b"shebang/" * 100 + b"python" + b" --and --flags -x"
    assert len(shebang) > MAX_SHEBANG_LENGTH
    data = b"\n".join((shebang, CONTENT, CONTENT, CONTENT))
    new_data = replace_long_shebang(FileMode.text, data)
    new_shebang = b"#!/usr/bin/env python --and --flags -x"
    assert len(new_shebang) < MAX_SHEBANG_LENGTH
    new_expected_data = b"\n".join((new_shebang, CONTENT, CONTENT, CONTENT))
    assert new_expected_data == new_data


def test_replace_long_shebang_with_truncation_escaped_space():
    # long shebang with truncation
    #   executable name is 'escaped space'
    shebang = b"#!/" + b"shebang/" * 100 + b"escaped\\ space" + b" --and --flags -x"
    assert len(shebang) > MAX_SHEBANG_LENGTH
    data = b"\n".join((shebang, CONTENT, CONTENT, CONTENT))
    new_data = replace_long_shebang(FileMode.text, data)
    new_shebang = b"#!/usr/bin/env escaped\\ space --and --flags -x"
    assert len(new_shebang) < MAX_SHEBANG_LENGTH
    new_expected_data = b"\n".join((new_shebang, CONTENT, CONTENT, CONTENT))
    assert new_expected_data == new_data


def test_replace_normal_shebang_spaces_in_prefix_python():
    # normal shebang with escaped spaces in prefix
    #   executable name is 'python'
    shebang = b"#!/she\\ bang/python --and --flags -x"
    assert len(shebang) < MAX_SHEBANG_LENGTH
    data = b"\n".join((shebang, CONTENT, CONTENT, CONTENT))
    new_data = replace_long_shebang(FileMode.text, data)
    new_shebang = b"#!/usr/bin/env python --and --flags -x"
    assert len(new_shebang) < MAX_SHEBANG_LENGTH
    new_expected_data = b"\n".join((new_shebang, CONTENT, CONTENT, CONTENT))
    assert new_expected_data == new_data


def test_replace_normal_shebang_spaces_in_prefix_escaped_space():
    # normal shebang with escaped spaces in prefix
    #   executable name is 'escaped space'
    shebang = b"#!/she\\ bang/escaped\\ space --and --flags -x"
    assert len(shebang) < MAX_SHEBANG_LENGTH
    data = b"\n".join((shebang, CONTENT, CONTENT, CONTENT))
    new_data = replace_long_shebang(FileMode.text, data)
    new_shebang = b"#!/usr/bin/env escaped\\ space --and --flags -x"
    assert len(new_shebang) < MAX_SHEBANG_LENGTH
    new_expected_data = b"\n".join((new_shebang, CONTENT, CONTENT, CONTENT))
    assert new_expected_data == new_data


def test_replace_long_shebang_spaces_in_prefix():
    # long shebang with escaped spaces in prefix
    shebang = b"#!/" + b"she\\ bang/" * 100 + b"python --and --flags -x"
    assert len(shebang) > MAX_SHEBANG_LENGTH
    data = b"\n".join((shebang, CONTENT, CONTENT, CONTENT))
    new_data = replace_long_shebang(FileMode.text, data)
    new_shebang = b"#!/usr/bin/env python --and --flags -x"
    assert len(new_shebang) < MAX_SHEBANG_LENGTH
    new_expected_data = b"\n".join((new_shebang, CONTENT, CONTENT, CONTENT))
    assert new_expected_data == new_data


@pytest.mark.skipif(on_win, reason="Shebang replacement only needed on Unix systems")
def test_escaped_prefix_replaced_only_shebang(tmp_path):
    """
    In order to deal with spaces and shebangs, we first escape the spaces
    in the shebang and then post-process it with the /usr/bin/env trick.

    However, we must NOT escape other occurrences of the prefix in the file.
    """
    new_prefix = "/a/path/with/s p a c e s"
    contents = dals(
        f"""
        #!{PREFIX_PLACEHOLDER}/python
        data = "{PREFIX_PLACEHOLDER}"
        """
    )
    script = os.path.join(tmp_path, "executable_script")
    with open(script, "wb") as f:
        f.write(contents.encode("utf-8"))
    update_prefix(path=script, new_prefix=new_prefix, placeholder=PREFIX_PLACEHOLDER)

    with open(script) as f:
        for i, line in enumerate(f):
            if i == 0:
                assert line.startswith("#!/usr/bin/env python")
            elif i == 1:
                assert new_prefix in line


def test_update_prefix_can_defer_osx_arm64_codesign(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(portability, "on_mac", True)
    monkeypatch.setattr(
        portability, "update_file_in_place_as_binary", lambda *args: True
    )
    monkeypatch.setattr(
        portability,
        "codesign_paths",
        lambda paths: pytest.fail("codesign should be deferred"),
    )

    updated = update_prefix(
        "/unused",
        "/prefix",
        mode=FileMode.binary,
        subdir="osx-arm64",
        sign_binary=False,
    )

    assert updated is True


def test_update_prefix_can_return_updated_sha256(tmp_path):
    script = tmp_path / "script"
    script.write_bytes(f"#!{PREFIX_PLACEHOLDER}/python\n".encode())

    updated, updated_sha256 = update_prefix(
        path=str(script),
        new_prefix="/opt/demo",
        placeholder=PREFIX_PLACEHOLDER,
        return_sha256=True,
    )

    assert updated is True
    assert updated_sha256 == sha256(script.read_bytes()).hexdigest()


def test_update_prefix_does_not_hash_unless_requested(
    monkeypatch: pytest.MonkeyPatch, tmp_path
):
    script = tmp_path / "script"
    script.write_bytes(f"#!{PREFIX_PLACEHOLDER}/python\n".encode())
    monkeypatch.setattr(
        portability,
        "sha256",
        lambda *args, **kwargs: pytest.fail("sha256 should not be computed"),
    )

    assert (
        update_prefix(
            path=str(script),
            new_prefix="/opt/demo",
            placeholder=PREFIX_PLACEHOLDER,
        )
        is True
    )


def test_iter_codesign_batches_limits_command_size():
    paths = ("a", "b" * 10, "c" * 10)

    def command_arg_size(argument):
        return len(os.fsencode(argument)) + 1

    max_command_bytes = (
        sum(command_arg_size(argument) for argument in portability._CODESIGN_COMMAND)
        + command_arg_size(paths[0])
        + command_arg_size(paths[1])
    )

    assert list(_iter_codesign_batches(paths, max_command_bytes)) == [
        paths[:2],
        paths[2:],
    ]


def test_codesign_paths_runs_each_batch(mocker):
    run = mocker.patch("conda.core.portability.subprocess.run")
    mocker.patch(
        "conda.core.portability._iter_codesign_batches",
        return_value=(("one", "two"), ("three",)),
    )

    portability.codesign_paths(("one", "two", "three"))

    assert run.call_args_list == [
        mocker.call(
            ["/usr/bin/codesign", "-s", "-", "-f", "one", "two"],
            capture_output=True,
        ),
        mocker.call(
            ["/usr/bin/codesign", "-s", "-", "-f", "three"],
            capture_output=True,
        ),
    ]
