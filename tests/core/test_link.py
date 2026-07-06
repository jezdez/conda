# Copyright (C) 2012 Anaconda, Inc
# SPDX-License-Identifier: BSD-3-Clause

from pathlib import Path
from types import SimpleNamespace

import pytest

from conda.core import link
from conda.models.enums import LinkType
from conda.models.records import PackageRecord


def test_verify_pre_link_message_skips_missing_message_dir(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    class PackageData:
        extracted_package_dir = str(tmp_path / "package")

    class LinkGroup:
        pkg_data = PackageData()

    def fail_glob(self, pattern):
        raise AssertionError(
            "missing prelink_messages directories should not be globbed"
        )

    monkeypatch.setattr(link.Path, "glob", fail_glob)

    transaction = object.__new__(link.UnlinkLinkTransaction)
    transaction._verify_pre_link_message([LinkGroup()])


def test_determine_link_type_prefers_clone_link_mode(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    package_dir = tmp_path / "package"
    target_prefix = tmp_path / "prefix"
    (package_dir / "info").mkdir(parents=True)
    target_prefix.mkdir()
    (package_dir / "info" / "index.json").write_text("{}")

    monkeypatch.setattr(link, "clone_file_supported", lambda *args: True)
    monkeypatch.setattr(
        link,
        "hardlink_supported",
        lambda *args: pytest.fail("clone-backed copy should be preferred"),
    )

    assert (
        link.determine_link_type(str(package_dir), str(target_prefix)) == LinkType.clone
    )


def test_determine_link_type_falls_back_to_hardlink_without_clone(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    package_dir = tmp_path / "package"
    target_prefix = tmp_path / "prefix"
    (package_dir / "info").mkdir(parents=True)
    target_prefix.mkdir()
    (package_dir / "info" / "index.json").write_text("{}")

    monkeypatch.setattr(link, "clone_file_supported", lambda *args: False)
    monkeypatch.setattr(link, "hardlink_supported", lambda *args: True)

    assert (
        link.determine_link_type(str(package_dir), str(target_prefix))
        == LinkType.hardlink
    )


def test_aggregate_link_actions_keeps_link_path_subclasses_individual():
    class SpecialLinkPathAction(link.LinkPathAction):
        pass

    plain_one = object.__new__(link.LinkPathAction)
    plain_one.link_type = LinkType.hardlink
    special = object.__new__(SpecialLinkPathAction)
    special.link_type = LinkType.hardlink
    special.target_short_path = "bin/special"
    plain_two = object.__new__(link.LinkPathAction)
    plain_two.link_type = LinkType.hardlink

    actions = link.UnlinkLinkTransaction._aggregate_link_actions(
        (plain_one, special, plain_two)
    )

    assert actions == (plain_one, special, plain_two)


def test_aggregate_link_actions_keeps_clone_and_hardlink_batches_separate():
    def plain_action(link_type, target_short_path):
        action = object.__new__(link.LinkPathAction)
        action.link_type = link_type
        action.target_short_path = target_short_path
        action.source_short_path = target_short_path
        action.transaction_context = {}
        action.package_info = SimpleNamespace()
        action.target_prefix = "/prefix"
        return action

    directory = plain_action(LinkType.directory, "lib/demo")
    clone_action = plain_action(LinkType.clone, "lib/demo/module.py")
    hardlink_one = plain_action(LinkType.hardlink, "bin/one")
    hardlink_two = plain_action(LinkType.hardlink, "bin/two")

    actions = link.UnlinkLinkTransaction._aggregate_link_actions(
        (directory, clone_action, hardlink_one, hardlink_two)
    )

    assert isinstance(actions[0], link.BulkClonePathAction)
    assert isinstance(actions[1], link.BulkHardLinkPathAction)


@pytest.mark.parametrize(
    "paths,files,expected",
    (
        (("script",), (), True),
        (None, ("script",), True),
        ((), (), False),
        (None, (), True),
        (None, None, True),
    ),
    ids=(
        "paths-data-hit",
        "files-hit",
        "paths-data-known-absent",
        "empty-files-fallback",
        "unknown-metadata",
    ),
)
def test_package_metadata_includes_script(paths, files, expected):
    script_path = (
        f"{link.BIN_DIRECTORY}/.demo-pre-link.{'bat' if link.on_win else 'sh'}"
    )
    paths = (
        tuple(script_path if path == "script" else path for path in paths)
        if paths is not None
        else None
    )
    files = (
        tuple(script_path if path == "script" else path for path in files)
        if files is not None
        else None
    )
    path_entries = (
        tuple(SimpleNamespace(path=path) for path in paths)
        if paths is not None
        else None
    )
    prec = SimpleNamespace(
        name="demo",
        paths_data=SimpleNamespace(paths=path_entries) if paths is not None else None,
        files=files,
    )

    assert link._package_metadata_includes_script(prec, "pre-link") is expected


def test_execute_post_link_actions_skips_absent_script(
    monkeypatch: pytest.MonkeyPatch,
):
    class Prec:
        name = "demo"
        paths_data = SimpleNamespace(paths=())
        files = ()

    class ActionGroup:
        type = "link"
        target_prefix = "/unused"
        pkg_data = Prec()

    monkeypatch.setattr(
        link,
        "run_script",
        lambda *args, **kwargs: pytest.fail("absent scripts should not be probed"),
    )

    assert link.UnlinkLinkTransaction._execute_post_link_actions(ActionGroup()) is None


def test_calculate_change_report_revised_variant():
    """
    Test to ensure that the change report will categorize a change in variant as
    a "REVISED" package.
    """
    unlink_precs = [
        PackageRecord(
            **{
                "channel": "pkgs/main/linux-64",
                "name": "mypackage_decrease_build",
                "version": "2.3.9",
                "build": "py35_0",
                # notice the build number decrease between the unlink and link precs
                "build_number": 200,
            }
        ),
        PackageRecord(
            **{
                "channel": "pkgs/main/linux-64",
                "name": "mypackage",
                "version": "2.3.9",
                "build": "py35_0",
                # notice the build number stay the same between the unlink and link precs
                "build_number": 0,
            }
        ),
    ]

    link_precs = [
        PackageRecord(
            **{
                "channel": "pkgs/main/linux-64",
                "name": "mypackage_decrease_build",
                "version": "2.3.9",
                "build": "py36_0",
                "build_number": 100,
            }
        ),
        PackageRecord(
            **{
                "channel": "pkgs/main/linux-64",
                "name": "mypackage",
                "version": "2.3.9",
                "build": "py36_0",
                "build_number": 0,
            }
        ),
    ]

    change_report = link.UnlinkLinkTransaction._calculate_change_report(
        "notarealprefix", unlink_precs, link_precs, (), (), ()
    )

    assert (
        change_report.revised_precs.get("global:mypackage_decrease_build") is not None
    )
    assert change_report.revised_precs.get("global:mypackage") is not None


def test_calculate_change_report_downgrade():
    """
    Test to ensure that the change report will categorize a downgrade of a package
    """
    unlink_precs = [
        PackageRecord(
            **{
                "channel": "pkgs/main/linux-64",
                "name": "mypackage_downgrade_version",
                "version": "2.3.9",
                "build": "py36_0",
                "build_number": 0,
            }
        ),
        PackageRecord(
            **{
                "channel": "pkgs/main/linux-64",
                "name": "mypackage_downgrade_build",
                "version": "2.3.9",
                "build": "py36_0",
                "build_number": 1,
            }
        ),
    ]

    link_precs = [
        PackageRecord(
            **{
                "channel": "pkgs/main/linux-64",
                "name": "mypackage_downgrade_version",
                "version": "2.3.8",
                "build": "py36_0",
                "build_number": 0,
            }
        ),
        PackageRecord(
            **{
                "channel": "pkgs/main/linux-64",
                "name": "mypackage_downgrade_build",
                "version": "2.3.9",
                "build": "py36_0",
                "build_number": 0,
            }
        ),
    ]

    change_report = link.UnlinkLinkTransaction._calculate_change_report(
        "notarealprefix", unlink_precs, link_precs, (), (), ()
    )

    # ensure downgrade version gets added to the downgrade section
    assert (
        change_report.downgraded_precs.get("global:mypackage_downgrade_version")
        is not None
    )

    # ensure downgrade build number gets added to the downgrade section
    assert (
        change_report.downgraded_precs.get("global:mypackage_downgrade_build")
        is not None
    )


def test_calculate_change_report_update():
    """
    Test to ensure that the change report will categorize an upgrade of a package
    """
    unlink_precs = [
        PackageRecord(
            **{
                "channel": "pkgs/main/linux-64",
                "name": "mypackage",
                "version": "2.3.9",
                "build": "py35_0",
                "build_number": 0,
            }
        ),
        PackageRecord(
            **{
                "channel": "pkgs/main/linux-64",
                "name": "mypackage_upgrade_build",
                "version": "2.3.9",
                "build": "py36_0",
                "build_number": 1,
            }
        ),
    ]

    link_precs = [
        PackageRecord(
            **{
                "channel": "pkgs/main/linux-64",
                "name": "mypackage",
                "version": "2.4.9",
                "build": "py36_0",
                "build_number": 0,
            }
        ),
        PackageRecord(
            **{
                "channel": "pkgs/main/linux-64",
                "name": "mypackage_upgrade_build",
                "version": "2.3.9",
                "build": "py36_0",
                "build_number": 2,
            }
        ),
    ]

    change_report = link.UnlinkLinkTransaction._calculate_change_report(
        "notarealprefix", unlink_precs, link_precs, (), (), ()
    )

    assert change_report.updated_precs.get("global:mypackage") is not None
    assert change_report.updated_precs.get("global:mypackage_upgrade_build") is not None


def test_calculate_change_report_superseded():
    """
    Test to ensure that the change report will categorize a superseded package
    """
    unlink_precs = [
        PackageRecord(
            **{
                "channel": "pkgs/main/linux-64",
                "name": "mypackage",
                "version": "2.3.9",
                "build": "py35_0",
                "build_number": 0,
            }
        ),
    ]

    link_precs = [
        PackageRecord(
            **{
                "channel": "conda-forge/linux-64",
                "name": "mypackage",
                "version": "2.3.9",
                "build": "py36_0",
                "build_number": 0,
            }
        ),
    ]

    change_report = link.UnlinkLinkTransaction._calculate_change_report(
        "notarealprefix", unlink_precs, link_precs, (), (), ()
    )

    assert change_report.superseded_precs.get("global:mypackage") is not None
