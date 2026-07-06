# Copyright (C) 2012 Anaconda, Inc
# SPDX-License-Identifier: BSD-3-Clause
from __future__ import annotations

import errno
import json
import os
import stat
from contextlib import nullcontext
from pathlib import Path
from shutil import copyfile

import pytest

from conda.gateways import subprocess as gateway_subprocess
from conda.gateways.disk import create


def raise_os_error(*args):
    raise OSError("failed")


@pytest.mark.parametrize(
    "function,raises",
    [
        ("create_application_entry_point", TypeError),
        ("ProgressFileWrapper", TypeError),
        ("create_fake_executable_softlink", TypeError),
        ("extract_tarball", TypeError),
    ],
)
def test_deprecations(function: str, raises: type[Exception] | None) -> None:
    raises_context = pytest.raises(raises) if raises else nullcontext()
    with pytest.deprecated_call(), raises_context:
        getattr(create, function)()


def test_copy_uses_clonefile_on_macos(monkeypatch: pytest.MonkeyPatch, tmp_path):
    source = tmp_path / "source"
    target = tmp_path / "target"
    source.write_text("contents")
    clone_calls = []

    class CloneFile:
        argtypes = None
        restype = None

        def __call__(self, src, dst, flags):
            clone_calls.append((src, dst, flags))
            copyfile(src, dst)
            return 0

    class LibC:
        clonefile = CloneFile()

    monkeypatch.setattr(create.sys, "platform", "darwin")
    monkeypatch.setattr(create, "CDLL", lambda *args, **kwargs: LibC())
    monkeypatch.setattr(
        create,
        "_do_copy",
        lambda src, dst: pytest.fail("copy fallback should not be used"),
    )
    create._CLONEFILE_UNSUPPORTED_DEVICES.clear()
    create._CLONEFILE_SUPPORTED_DEVICES.clear()
    monkeypatch.setattr(create, "_CLONEFILE", None)

    create.copy(str(source), str(target))

    assert target.read_text() == "contents"
    assert clone_calls == [(bytes(source), bytes(target), 0)]


def test_copy_clone_preserves_source_metadata(
    monkeypatch: pytest.MonkeyPatch, tmp_path
):
    source = tmp_path / "source"
    target = tmp_path / "target"
    source.write_text("contents")
    source.chmod(0o744)
    os.utime(source, (1_700_000_000, 1_700_000_000))

    class CloneFile:
        argtypes = None
        restype = None

        def __call__(self, src, dst, flags):
            copyfile(src, dst)
            return 0

    class LibC:
        clonefile = CloneFile()

    monkeypatch.setattr(create.sys, "platform", "darwin")
    monkeypatch.setattr(create, "CDLL", lambda *args, **kwargs: LibC())
    create._CLONEFILE_UNSUPPORTED_DEVICES.clear()
    create._CLONEFILE_SUPPORTED_DEVICES.clear()
    monkeypatch.setattr(create, "_CLONEFILE", None)

    create.copy(str(source), str(target))

    assert stat.S_IMODE(target.stat().st_mode) == 0o744
    assert int(target.stat().st_mtime) == 1_700_000_000


def test_copy_caches_unsupported_clonefile_device_pair(
    monkeypatch: pytest.MonkeyPatch, tmp_path
):
    source = tmp_path / "source"
    target_one = tmp_path / "target-one"
    target_two = tmp_path / "target-two"
    source.write_text("contents")
    clone_calls = []
    copy_calls = []

    class CloneFile:
        argtypes = None
        restype = None

        def __call__(self, src, dst, flags):
            clone_calls.append((src, dst, flags))
            return -1

    class LibC:
        clonefile = CloneFile()

    def copy_fallback(src, dst):
        copy_calls.append((src, dst))
        copyfile(src, dst)

    monkeypatch.setattr(create.sys, "platform", "darwin")
    monkeypatch.setattr(create, "CDLL", lambda *args, **kwargs: LibC())
    monkeypatch.setattr(create, "get_errno", lambda: errno.ENOTSUP)
    monkeypatch.setattr(create, "_do_copy", copy_fallback)
    create._CLONEFILE_UNSUPPORTED_DEVICES.clear()
    create._CLONEFILE_SUPPORTED_DEVICES.clear()
    monkeypatch.setattr(create, "_CLONEFILE", None)

    create.copy(str(source), str(target_one))
    create.copy(str(source), str(target_two))

    assert target_one.read_text() == "contents"
    assert target_two.read_text() == "contents"
    assert len(clone_calls) == 1
    assert copy_calls == [
        (str(source), str(target_one)),
        (str(source), str(target_two)),
    ]


def test_copy_uses_linux_reflink(monkeypatch: pytest.MonkeyPatch, tmp_path):
    source = tmp_path / "source"
    target = tmp_path / "target"
    source.write_text("contents")
    reflink_calls = []

    def reflink(dst_fd, request, src_fd):
        reflink_calls.append((dst_fd, request, src_fd))
        os.lseek(src_fd, 0, os.SEEK_SET)
        os.write(dst_fd, os.read(src_fd, source.stat().st_size))

    monkeypatch.setattr(create.sys, "platform", "linux")
    monkeypatch.setattr(create, "_FICLONE_IOCTL", reflink)
    monkeypatch.setattr(
        create,
        "_do_copy",
        lambda src, dst: pytest.fail("copy fallback should not be used"),
    )
    create._FICLONE_UNSUPPORTED_DEVICES.clear()
    create._FICLONE_SUPPORTED_DEVICES.clear()

    create.copy(str(source), str(target))

    assert target.read_text() == "contents"
    assert len(reflink_calls) == 1
    assert reflink_calls[0][1] == create._FICLONE


def test_copy_caches_unsupported_linux_reflink_device_pair(
    monkeypatch: pytest.MonkeyPatch, tmp_path
):
    source = tmp_path / "source"
    target_one = tmp_path / "target-one"
    target_two = tmp_path / "target-two"
    source.write_text("contents")
    reflink_calls = []
    copy_calls = []

    def reflink(dst_fd, request, src_fd):
        reflink_calls.append((dst_fd, request, src_fd))
        os.write(dst_fd, b"partial")
        raise OSError(getattr(errno, "EOPNOTSUPP", errno.EINVAL), "unsupported")

    def copy_fallback(src, dst):
        copy_calls.append((src, dst, Path(dst).exists()))
        copyfile(src, dst)

    monkeypatch.setattr(create.sys, "platform", "linux")
    monkeypatch.setattr(create, "_FICLONE_IOCTL", reflink)
    monkeypatch.setattr(create, "_do_copy", copy_fallback)
    create._FICLONE_UNSUPPORTED_DEVICES.clear()
    create._FICLONE_SUPPORTED_DEVICES.clear()

    create.copy(str(source), str(target_one))
    create.copy(str(source), str(target_two))

    assert target_one.read_text() == "contents"
    assert target_two.read_text() == "contents"
    assert len(reflink_calls) == 1
    assert copy_calls == [
        (str(source), str(target_one), False),
        (str(source), str(target_two), False),
    ]


def test_clone_file_supported_reuses_supported_device_pair(
    monkeypatch: pytest.MonkeyPatch, tmp_path
):
    source = tmp_path / "source"
    dest_dir = tmp_path / "dest"
    source.write_text("contents")
    dest_dir.mkdir()
    device_pair = (source.stat().st_dev, dest_dir.stat().st_dev)

    monkeypatch.setattr(create.sys, "platform", "linux")
    monkeypatch.setattr(
        create,
        "_clone_file",
        lambda *args: pytest.fail("known-supported device pair should not probe"),
    )
    create.clone_file_supported.cache_clear()
    create._FICLONE_UNSUPPORTED_DEVICES.clear()
    create._FICLONE_SUPPORTED_DEVICES.clear()
    create._FICLONE_SUPPORTED_DEVICES.add(device_pair)

    assert create.clone_file_supported(str(source), str(dest_dir)) is True


def test_do_copy_uses_windows_copyfile(monkeypatch: pytest.MonkeyPatch, tmp_path):
    source = tmp_path / "source"
    target = tmp_path / "target"
    source.write_text("contents")
    copy_calls = []

    def copy_file(src, dst, fail_if_exists):
        copy_calls.append((src, dst, fail_if_exists))
        copyfile(src, dst)
        return True

    monkeypatch.setattr(create, "on_win", True)
    monkeypatch.setattr(create, "_WIN_COPYFILE", copy_file)
    monkeypatch.setattr(
        create,
        "copyfileobj",
        lambda *args, **kwargs: pytest.fail("CopyFileW should avoid Python copy"),
    )

    create._do_copy(str(source), str(target))

    assert target.read_text() == "contents"
    assert copy_calls == [(str(source), str(target), True)]


def test_do_copy_cleans_up_failed_windows_copyfile(
    monkeypatch: pytest.MonkeyPatch, tmp_path
):
    source = tmp_path / "source"
    target = tmp_path / "target"
    source.write_text("contents")
    target.write_text("partial")
    removed = []
    rm_rf = create.rm_rf

    def copy_file(src, dst, fail_if_exists):
        return False

    def remove(path):
        removed.append(path)
        rm_rf(path)

    monkeypatch.setattr(create, "on_win", True)
    monkeypatch.setattr(create, "_WIN_COPYFILE", copy_file)
    monkeypatch.setattr(create, "rm_rf", remove)

    create._do_copy(str(source), str(target))

    assert target.read_text() == "contents"
    assert removed == [str(target)]


def test_clone_link_or_copy_falls_back_to_hardlink(
    monkeypatch: pytest.MonkeyPatch, tmp_path
):
    source = tmp_path / "source"
    target = tmp_path / "target"
    source.write_text("contents")
    copied = []

    monkeypatch.setattr(create, "_clone_file", lambda *args: False)
    monkeypatch.setattr(create, "_do_copy", lambda *args: copied.append(args))

    create.create_link(str(source), str(target), create.LinkType.clone)

    assert target.read_text() == "contents"
    assert target.stat().st_nlink == 2
    assert copied == []


def test_clone_link_or_copy_falls_back_to_copy_after_hardlink_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path
):
    source = tmp_path / "source"
    target = tmp_path / "target"
    source.write_text("contents")
    copied = []

    def copy_fallback(src, dst):
        copied.append((src, dst))
        copyfile(src, dst)
        return create.LinkType.copy

    monkeypatch.setattr(create, "_clone_file", lambda *args: False)
    monkeypatch.setattr(create, "link", lambda *args: raise_os_error())
    monkeypatch.setattr(create, "_do_copy", copy_fallback)

    create.create_link(str(source), str(target), create.LinkType.clone)

    assert target.read_text() == "contents"
    assert copied == [(str(source), str(target))]


def test_copy_link_type_does_not_fall_back_to_hardlink(
    monkeypatch: pytest.MonkeyPatch, tmp_path
):
    source = tmp_path / "source"
    target = tmp_path / "target"
    source.write_text("contents")
    link_calls = []

    def copy_fallback(src, dst):
        copyfile(src, dst)
        return create.LinkType.copy

    monkeypatch.setattr(create, "_clone_file", lambda *args: False)
    monkeypatch.setattr(create, "link", lambda *args: link_calls.append(args))
    monkeypatch.setattr(create, "_do_copy", copy_fallback)

    create.create_link(str(source), str(target), create.LinkType.copy)

    assert target.read_text() == "contents"
    assert target.stat().st_nlink == 1
    assert link_calls == []


def test_clone_file_supported_probes_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch, tmp_path
):
    source = tmp_path / "source"
    dest_dir = tmp_path / "dest"
    dest_dir.mkdir()
    source.write_text("contents")
    clone_calls = []
    removed = []

    def fake_clone(src, dst):
        clone_calls.append((src, dst))
        Path(dst).write_text("clone")
        return True

    monkeypatch.setattr(create, "_clone_file", fake_clone)
    monkeypatch.setattr(create, "rm_rf", lambda path: removed.append(path))
    create.clone_file_supported.cache_clear()
    create._CLONEFILE_UNSUPPORTED_DEVICES.clear()
    create._CLONEFILE_SUPPORTED_DEVICES.clear()
    create._FICLONE_UNSUPPORTED_DEVICES.clear()
    create._FICLONE_SUPPORTED_DEVICES.clear()

    assert create.clone_file_supported(str(source), str(dest_dir)) is True
    assert len(clone_calls) == 1
    assert clone_calls[0][0] == str(source)
    assert clone_calls[0][1].startswith(str(dest_dir / ".tmp.clone.source."))
    assert removed == [clone_calls[0][1]]


def test_compile_multiple_pyc_uses_direct_pair_compiler(
    monkeypatch: pytest.MonkeyPatch, tmp_path
):
    prefix = tmp_path / "prefix"
    source = prefix / "lib/python3.12/site-packages/demo.py"
    target = prefix / "lib/python3.12/site-packages/__pycache__/demo.cpython-312.pyc"
    source.parent.mkdir(parents=True)
    source.write_text("value = 1")
    calls = []

    def fake_any_subprocess(command, command_prefix):
        script = Path(command[2]).read_text()
        pairs = json.loads(Path(command[3]).read_text())
        calls.append((command, command_prefix, script, pairs))
        assert command[1] == "-Wi"
        assert "-c" not in command
        assert all("\n" not in arg for arg in command)
        assert "compileall" not in command
        assert "compileall" not in script
        assert pairs == [
            [
                str(Path("lib/python3.12/site-packages/demo.py")),
                str(
                    Path(
                        "lib/python3.12/site-packages/__pycache__/demo.cpython-312.pyc"
                    )
                ),
            ]
        ]
        target.parent.mkdir(parents=True)
        target.write_bytes(b"pyc")
        return "", "", 0

    monkeypatch.setattr(gateway_subprocess, "any_subprocess", fake_any_subprocess)

    created = create.compile_multiple_pyc(
        "/prefix/bin/python",
        [str(source)],
        [str(target)],
        str(prefix),
        "3.12",
    )

    assert created == [str(target)]
    assert calls == [
        (
            [
                "/prefix/bin/python",
                "-Wi",
                calls[0][0][2],
                calls[0][0][3],
            ],
            str(prefix),
            create._COMPILE_PYC_SCRIPT,
            [
                [
                    str(Path("lib/python3.12/site-packages/demo.py")),
                    str(
                        Path(
                            "lib/python3.12/site-packages/__pycache__/"
                            "demo.cpython-312.pyc"
                        )
                    ),
                ]
            ],
        )
    ]


def test_hard_link_path_executor_uses_dir_fds(
    monkeypatch: pytest.MonkeyPatch, tmp_path
):
    source_dir = tmp_path / "source"
    target_dir = tmp_path / "target"
    source_dir.mkdir()
    target_dir.mkdir()
    source = source_dir / "file"
    target = target_dir / "file"
    source.write_text("contents")
    opened = {}
    closed = []
    link_calls = []

    def fake_open(path, flags):
        fd = len(opened) + 10
        opened[str(path)] = fd
        return fd

    def fake_link(src, dst, *, src_dir_fd, dst_dir_fd):
        link_calls.append((src, dst, src_dir_fd, dst_dir_fd))

    monkeypatch.setattr(create, "on_win", False)
    monkeypatch.setattr(create.os, "open", fake_open)
    monkeypatch.setattr(create.os, "close", lambda fd: closed.append(fd))
    monkeypatch.setattr(create.os, "link", fake_link)
    monkeypatch.setattr(create.os, "supports_dir_fd", {fake_link})
    monkeypatch.setattr(
        create,
        "create_link",
        lambda *args, **kwargs: pytest.fail("dir-fd link should not fall back"),
    )

    with create.HardLinkPathExecutor() as link_executor:
        link_executor.link_or_copy(str(source), str(target))

    assert link_calls == [
        ("file", "file", opened[str(source_dir)], opened[str(target_dir)])
    ]
    assert sorted(closed) == sorted(opened.values())


def test_hard_link_path_executor_uses_windows_direct_link(
    monkeypatch: pytest.MonkeyPatch, tmp_path
):
    source = tmp_path / "source"
    target = tmp_path / "target"
    source.write_text("contents")
    link_calls = []

    def direct_link(src, dst):
        link_calls.append((src, dst))

    monkeypatch.setattr(create, "on_win", True)
    monkeypatch.setattr(create, "link", direct_link)
    monkeypatch.setattr(
        create,
        "create_link",
        lambda *args, **kwargs: pytest.fail("direct Windows link should not fall back"),
    )

    with create.HardLinkPathExecutor() as link_executor:
        link_executor.link_or_copy(str(source), str(target))

    assert link_calls == [(str(source), str(target))]


def test_hard_link_path_executor_falls_back_after_windows_direct_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path
):
    source = tmp_path / "source"
    target = tmp_path / "target"
    source.write_text("contents")
    fallback_calls = []

    def create_link(src, dst, link_type, force=False):
        fallback_calls.append((src, dst, link_type, force))

    monkeypatch.setattr(create, "on_win", True)
    monkeypatch.setattr(create, "link", lambda *args: raise_os_error())
    monkeypatch.setattr(create, "create_link", create_link)

    with create.HardLinkPathExecutor() as link_executor:
        link_executor.link_or_copy(str(source), str(target))

    assert fallback_calls == [
        (str(source), str(target), create.LinkType.hardlink, False)
    ]
