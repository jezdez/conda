# Copyright (C) 2012 Anaconda, Inc
# SPDX-License-Identifier: BSD-3-Clause
"""Atomic actions that make up a package installation or removal transaction."""

from __future__ import annotations

import os
import re
import sys
from abc import ABC, abstractmethod
from itertools import chain
from logging import getLogger
from os.path import basename, dirname, getsize, isdir, isfile, join, normpath
from typing import TYPE_CHECKING
from uuid import uuid4

from .. import CONDA_PACKAGE_ROOT, CondaError
from ..auxlib.ish import dals
from ..base.constants import CONDA_TEMP_EXTENSION, WINDOWS_LAUNCHER_STUB_PATH
from ..base.context import context
from ..common.compat import on_win
from ..common.constants import TRACE
from ..common.io import ThreadLimitedThreadPoolExecutor, dashlist
from ..common.path import (
    BIN_DIRECTORY,
    get_leaf_directories,
    get_python_noarch_target_path,
    get_python_short_path,
    parse_entry_point_def,
    pyc_path,
    url_to_path,
    win_path_ok,
)
from ..common.serialize import json
from ..common.url import has_platform, path_to_url
from ..exceptions import (
    CondaUpgradeError,
    CondaVerificationError,
    NotWritableError,
    PaddingError,
    SafetyError,
)
from ..gateways.connection.download import download
from ..gateways.disk.create import (
    HardLinkPathExecutor,
    clone_directory,
    compile_multiple_pyc,
    copy,
    create_hard_link_or_copy,
    create_link,
    create_python_entry_point,
    make_menu,
    mkdir_p,
    write_as_json_to_file,
)
from ..gateways.disk.delete import rm_rf
from ..gateways.disk.permissions import make_writable
from ..gateways.disk.read import compute_sum, islink, lexists, read_index_json
from ..gateways.disk.update import backoff_rename, touch
from ..history import History
from ..models.channel import Channel
from ..models.enums import LinkType, NoarchType, PathEnum
from ..models.match_spec import MatchSpec
from ..models.records import (
    Link,
    PackageCacheRecord,
    PackageRecord,
    PathDataV1,
    PathsData,
    PrefixRecord,
)
from .envs_manager import get_user_environments_txt_file, register_env, unregister_env
from .portability import (
    _PaddingError,
    codesign_paths,
    needs_osx_arm64_codesign,
    update_prefix,
)
from .prefix_data import PrefixData

if TYPE_CHECKING:
    from collections.abc import Iterable

try:
    FileNotFoundError
except NameError:
    FileNotFoundError = IOError

log = getLogger(__name__)

_MENU_RE = re.compile(r"^menu/.*\.json$", re.IGNORECASE)
PARALLEL_PATH_ACTION_THRESHOLD = 64
PARALLEL_PATH_ACTION_WORKERS = 8
REPR_IGNORE_KWARGS = (
    "transaction_context",
    "package_info",
    "hold_path",
)


class Action(ABC):
    """Base class for path manipulation actions, including linking, unlinking, and others.

    Pre and post-transaction plugins should inherit this class to implement their
    own verification, execution, reversing, and cleanup steps. These methods are
    guaranteed to be called in the following order:

        1. ``verify``
        2. ``execute``
        3. ``reverse`` (only if ``execute`` raises an exception)
        4. ``cleanup``


    Args:
        transaction_context: Mapping between target prefixes and PrefixActionGroup instances.
        target_prefix: Target prefix for the action.
        unlink_precs: Package records to be unlinked.
        link_precs: Package records to link.
        remove_specs: Specs to be removed.
        update_specs: Specs to be updated.
        neutered_specs: Specs to be neutered.
    """

    _verified = False

    def __init__(
        self,
        transaction_context: dict[str, str] | None = None,
        target_prefix: str | None = None,
        unlink_precs: Iterable[PackageRecord] | None = None,
        link_precs: Iterable[PackageRecord] | None = None,
        remove_specs: Iterable[MatchSpec] | None = None,
        update_specs: Iterable[MatchSpec] | None = None,
        neutered_specs: Iterable[MatchSpec] | None = None,
    ):
        self.transaction_context = transaction_context
        self.target_prefix = target_prefix
        self.unlink_precs = unlink_precs
        self.link_precs = link_precs
        self.remove_specs = remove_specs
        self.update_specs = update_specs
        self.neutered_specs = neutered_specs

    @abstractmethod
    def verify(self) -> Exception | None:
        """Carry out any pre-execution verification.

        Should set self._verified = True upon success.

        Returns:
            On failure, this function should return (not raise!) an exception
            object. At the end of the verification run, all errors will be raised as a
            CondaMultiError.
        """

    @abstractmethod
    def execute(self) -> None:
        """Execute the action.

        Called after ``self.verify()``. If this function raises an exception,
        ``self.reverse()`` will be called.
        """

    @abstractmethod
    def reverse(self) -> None:
        """Reverse what was done in execute.

        Called only if ``self.execute()`` raises an exception.
        """
        pass

    @abstractmethod
    def cleanup(self) -> None:
        """Carry out any post-execution tasks."""
        pass

    @property
    def verified(self):
        return self._verified

    def __repr__(self):
        args = (
            f"{key}={value!r}"
            for key, value in vars(self).items()
            if key not in REPR_IGNORE_KWARGS
        )
        return "{}({})".format(self.__class__.__name__, ", ".join(args))


class PathAction(Action):
    @property
    @abstractmethod
    def target_full_path(self):
        raise NotImplementedError()


class MultiPathAction(Action):
    @property
    @abstractmethod
    def target_full_paths(self):
        raise NotImplementedError()


class PrefixPathAction(PathAction):
    def __init__(self, transaction_context, target_prefix, target_short_path):
        self.transaction_context = transaction_context
        self.target_prefix = target_prefix
        self.target_short_path = target_short_path

    @property
    def target_short_paths(self):
        return (self.target_short_path,)

    @property
    def target_full_path(self):
        trgt, shrt_pth = self.target_prefix, self.target_short_path
        if trgt is not None and shrt_pth is not None:
            return join(trgt, win_path_ok(shrt_pth))
        else:
            return None


# ######################################################
#  Creation of Paths within a Prefix
# ######################################################


class CreateInPrefixPathAction(PrefixPathAction):
    # All CreatePathAction subclasses must create a SINGLE new path
    #   the short/in-prefix version of that path must be returned by execute()

    def __init__(
        self,
        transaction_context,
        package_info,
        source_prefix,
        source_short_path,
        target_prefix,
        target_short_path,
    ):
        super().__init__(transaction_context, target_prefix, target_short_path)
        self.package_info = package_info
        self.source_prefix = source_prefix
        self.source_short_path = source_short_path

    def verify(self):
        self._verified = True

    def cleanup(self):
        # create actions typically won't need cleanup
        pass

    @property
    def source_full_path(self):
        prfx, shrt_pth = self.source_prefix, self.source_short_path
        return join(prfx, win_path_ok(shrt_pth)) if prfx and shrt_pth else None


class LinkPathAction(CreateInPrefixPathAction):
    @classmethod
    def create_file_link_actions(
        cls, transaction_context, package_info, target_prefix, requested_link_type
    ):
        def get_prefix_replace(source_path_data):
            if source_path_data.path_type == PathEnum.softlink:
                link_type = LinkType.copy
                prefix_placehoder, file_mode = "", None
            elif source_path_data.prefix_placeholder:
                link_type = LinkType.copy
                prefix_placehoder = source_path_data.prefix_placeholder
                file_mode = source_path_data.file_mode
            elif source_path_data.no_link:
                link_type = LinkType.copy
                prefix_placehoder, file_mode = "", None
            else:
                link_type = requested_link_type
                prefix_placehoder, file_mode = "", None

            return link_type, prefix_placehoder, file_mode

        def make_file_link_action(source_path_data):
            # TODO: this inner function is still kind of a mess
            noarch = package_info.repodata_record.noarch
            if noarch is None and package_info.package_metadata is not None:
                # Look in package metadata in case it was omitted from repodata (see issue #8311)
                noarch = package_info.package_metadata.noarch
                if noarch is not None:
                    noarch = noarch.type
            if noarch == NoarchType.python:
                sp_dir = transaction_context["target_site_packages_short_path"]
                if sp_dir is None:
                    raise CondaError(
                        "Unable to determine python site-packages "
                        "dir in target_prefix!\nPlease make sure "
                        f"python is installed in {target_prefix}"
                    )
                target_short_path = get_python_noarch_target_path(
                    source_path_data.path, sp_dir
                )
            elif noarch is None or noarch == NoarchType.generic:
                target_short_path = source_path_data.path
            else:
                raise CondaUpgradeError(
                    dals(
                        """
                The current version of conda is too old to install this package.
                Please update conda."""
                    )
                )

            link_type, placeholder, fmode = get_prefix_replace(source_path_data)

            if placeholder:
                return PrefixReplaceLinkAction(
                    transaction_context,
                    package_info,
                    package_info.extracted_package_dir,
                    source_path_data.path,
                    target_prefix,
                    target_short_path,
                    requested_link_type,
                    placeholder,
                    fmode,
                    source_path_data,
                )
            else:
                return LinkPathAction(
                    transaction_context,
                    package_info,
                    package_info.extracted_package_dir,
                    source_path_data.path,
                    target_prefix,
                    target_short_path,
                    link_type,
                    source_path_data,
                )

        return tuple(
            make_file_link_action(spi) for spi in package_info.paths_data.paths
        )

    @classmethod
    def create_directory_actions(
        cls,
        transaction_context,
        package_info,
        target_prefix,
        requested_link_type,
        file_link_actions,
    ):
        leaf_directories = get_leaf_directories(
            axn.target_short_path for axn in file_link_actions
        )
        return tuple(
            cls(
                transaction_context,
                package_info,
                None,
                None,
                target_prefix,
                directory_short_path,
                LinkType.directory,
                None,
            )
            for directory_short_path in leaf_directories
        )

    @classmethod
    def create_python_entry_point_windows_exe_action(
        cls,
        transaction_context,
        package_info,
        target_prefix,
        requested_link_type,
        entry_point_def,
    ):
        if context.subdir not in WINDOWS_LAUNCHER_STUB_PATH:
            raise NotImplementedError(
                f"Windows entry point stub not available for subdir {context.subdir!r}. "
                f"Supported: {dashlist(WINDOWS_LAUNCHER_STUB_PATH)}."
            )
        source_directory = CONDA_PACKAGE_ROOT
        source_short_path = WINDOWS_LAUNCHER_STUB_PATH[context.subdir]
        command, _, _ = parse_entry_point_def(entry_point_def)
        target_short_path = f"Scripts/{command}.exe"
        if not normpath(target_short_path).startswith("Scripts" + os.sep):
            raise ValueError(
                "target_short_path must point to Scripts/: " + target_short_path
            )
        source_path_data = PathDataV1(
            _path=target_short_path,
            path_type=PathEnum.windows_python_entry_point_exe,
        )
        return cls(
            transaction_context,
            package_info,
            source_directory,
            source_short_path,
            target_prefix,
            target_short_path,
            requested_link_type,
            source_path_data,
        )

    def __init__(
        self,
        transaction_context,
        package_info,
        extracted_package_dir,
        source_short_path,
        target_prefix,
        target_short_path,
        link_type,
        source_path_data,
    ):
        super().__init__(
            transaction_context,
            package_info,
            extracted_package_dir,
            source_short_path,
            target_prefix,
            target_short_path,
        )
        self.link_type = link_type
        self._execute_successful = False
        self.source_path_data = source_path_data
        self.prefix_path_data = None

    def verify(self):
        if self.link_type != LinkType.directory and not lexists(
            self.source_full_path
        ):  # pragma: no cover
            return CondaVerificationError(
                dals(
                    f"""
            The package for {self.package_info.repodata_record.name} located at {self.package_info.extracted_package_dir}
            appears to be corrupted. The path '{self.source_short_path}'
            specified in the package manifest cannot be found.
            """
                )
            )

        source_path_data = self.source_path_data
        try:
            source_path_type = source_path_data.path_type
        except AttributeError:
            source_path_type = None
        if source_path_type in PathEnum.basic_types:
            # this let's us keep the non-generic path types like windows_python_entry_point_exe
            source_path_type = None

        if self.link_type == LinkType.directory:
            self.prefix_path_data = None
        elif self.link_type == LinkType.softlink:
            self.prefix_path_data = PathDataV1.from_objects(
                self.source_path_data,
                path_type=source_path_type or PathEnum.softlink,
            )
        elif (
            self.link_type == LinkType.copy
            and source_path_data.path_type == PathEnum.softlink
        ):
            self.prefix_path_data = PathDataV1.from_objects(
                self.source_path_data,
                path_type=source_path_type or PathEnum.softlink,
            )

        elif source_path_data.path_type == PathEnum.hardlink:
            try:
                reported_size_in_bytes = source_path_data.size_in_bytes
            except AttributeError:
                reported_size_in_bytes = None
            source_size_in_bytes = 0
            if reported_size_in_bytes:
                source_size_in_bytes = getsize(self.source_full_path)
                if reported_size_in_bytes != source_size_in_bytes:
                    return SafetyError(
                        dals(
                            f"""
                    The package for {self.package_info.repodata_record.name} located at {self.package_info.extracted_package_dir}
                    appears to be corrupted. The path '{self.source_short_path}'
                    has an incorrect size.
                      reported size: {reported_size_in_bytes} bytes
                      actual size: {source_size_in_bytes} bytes
                    """
                        )
                    )

            try:
                reported_sha256 = source_path_data.sha256
            except AttributeError:
                reported_sha256 = None
            # sha256 is expensive.  Only run if file sizes agree, and then only if enabled
            if (
                source_size_in_bytes
                and reported_size_in_bytes == source_size_in_bytes
                and context.extra_safety_checks
            ):
                source_sha256 = compute_sum(self.source_full_path, "sha256")

                if reported_sha256 and reported_sha256 != source_sha256:
                    return SafetyError(
                        dals(
                            f"""
                    The package for {self.package_info.repodata_record.name} located at {self.package_info.extracted_package_dir}
                    appears to be corrupted. The path '{self.source_short_path}'
                    has a sha256 mismatch.
                    reported sha256: {reported_sha256}
                    actual sha256: {source_sha256}
                    """
                        )
                    )
            self.prefix_path_data = PathDataV1.from_objects(
                source_path_data,
                sha256=reported_sha256,
                sha256_in_prefix=reported_sha256,
                path_type=source_path_type or PathEnum.hardlink,
            )
        elif source_path_data.path_type == PathEnum.windows_python_entry_point_exe:
            self.prefix_path_data = source_path_data
        else:
            raise NotImplementedError()

        self._verified = True

    def execute(self):
        log.log(TRACE, "linking %s => %s", self.source_full_path, self.target_full_path)
        create_link(
            self.source_full_path,
            self.target_full_path,
            self.link_type,
            force=context.force,
        )
        self._execute_successful = True

    def reverse(self):
        if self._execute_successful:
            log.log(TRACE, "reversing link creation %s", self.target_prefix)
            if not isdir(self.target_full_path):
                rm_rf(self.target_full_path, clean_empty_parents=True)


class BulkHardLinkPathAction(MultiPathAction):
    def __init__(self, *link_path_actions):
        self._link_path_actions = link_path_actions
        self.transaction_context = link_path_actions[0].transaction_context
        self.package_info = link_path_actions[0].package_info
        self.target_prefix = link_path_actions[0].target_prefix
        self.target_short_paths = tuple(
            action.target_short_path for action in link_path_actions
        )
        self._execute_successful = False

    @property
    def target_full_paths(self):
        return tuple(action.target_full_path for action in self._link_path_actions)

    def verify(self):
        for action in self._link_path_actions:
            if action.verified:
                continue
            error = action.verify()
            if error:
                return error
        self._verified = True

    def execute(self):
        log.log(TRACE, "bulk hard linking %d paths", len(self._link_path_actions))
        with HardLinkPathExecutor(force=context.force) as link_executor:
            for action in self._link_path_actions:
                # The wrapped LinkPathAction still owns verify, rollback, and
                # conda-meta data; the bulk action only reuses syscall setup.
                link_executor.link_or_copy(
                    action.source_full_path,
                    action.target_full_path,
                )
                action._execute_successful = True
        self._execute_successful = True

    def reverse(self):
        if any(action._execute_successful for action in self._link_path_actions):
            log.log(TRACE, "reversing bulk hard link creation %s", self.target_prefix)
            for action in reversed(self._link_path_actions):
                action.reverse()

    def cleanup(self):
        for action in self._link_path_actions:
            action.cleanup()


def _path_parts(path):
    return tuple(part for part in path.replace("\\", "/").split("/") if part)


def _parts_to_path(parts):
    return "/".join(parts)


def _parts_start_with(path_parts, prefix_parts):
    return path_parts[: len(prefix_parts)] == prefix_parts


class BulkClonePathAction(MultiPathAction):
    def __init__(self, directory_actions, link_path_actions, blocked_short_paths=()):
        self._directory_actions = tuple(directory_actions)
        self._link_path_actions = tuple(link_path_actions)
        self._blocked_short_paths = {
            _path_parts(path) for path in blocked_short_paths if path
        }
        self.transaction_context = link_path_actions[0].transaction_context
        self.package_info = link_path_actions[0].package_info
        self.target_prefix = link_path_actions[0].target_prefix
        self.target_short_paths = tuple(
            action.target_short_path for action in link_path_actions
        )
        self._clone_directory_parts = self._find_clone_directory_parts()
        self._execute_successful = False

    @property
    def target_full_paths(self):
        return tuple(action.target_full_path for action in self._link_path_actions)

    def verify(self):
        for action in chain(self._directory_actions, self._link_path_actions):
            if action.verified:
                continue
            error = action.verify()
            if error:
                return error
        self._verified = True

    def execute(self):
        log.log(
            TRACE,
            "bulk clone linking %d paths from %s",
            len(self._link_path_actions),
            self.package_info.extracted_package_dir,
        )
        covered_actions = set()
        for directory_parts in self._clone_directory_parts:
            clone_actions = tuple(
                action
                for action in self._link_path_actions
                if action not in covered_actions
                and _parts_start_with(
                    _path_parts(action.target_short_path), directory_parts
                )
            )
            if not clone_actions:
                continue

            source_dir = join(
                self.package_info.extracted_package_dir,
                win_path_ok(_parts_to_path(directory_parts)),
            )
            target_dir = join(
                self.target_prefix, win_path_ok(_parts_to_path(directory_parts))
            )
            if lexists(target_dir):
                continue
            # Directory clones are only safe when the manifest exactly covers
            # the source subtree; otherwise individual LinkPathActions run.
            if not self._source_tree_matches_actions(
                source_dir, directory_parts, clone_actions
            ):
                continue

            mkdir_p(dirname(target_dir))
            if clone_directory(source_dir, target_dir):
                self._touch_cloned_python_import_dirs(directory_parts, target_dir)
                for action in clone_actions:
                    action._execute_successful = True
                covered_actions.update(clone_actions)

        # Keep explicit directory actions in the normal transaction stream so
        # their verify/rollback behavior is unchanged after a successful clone.
        for action in self._directory_actions:
            action.execute()

        remaining_actions = tuple(
            action
            for action in self._link_path_actions
            if action not in covered_actions
        )
        # Leftover clone actions are the fallback tail after directory clones.
        # On non-APFS platforms determine_link_type never selects LinkType.clone.
        workers = (
            1
            if context.debug or len(remaining_actions) < PARALLEL_PATH_ACTION_THRESHOLD
            else min(
                PARALLEL_PATH_ACTION_WORKERS,
                os.cpu_count() or 1,
                len(remaining_actions),
            )
        )
        if workers == 1:
            for action in remaining_actions:
                action.execute()
        else:
            with ThreadLimitedThreadPoolExecutor(workers) as executor:
                futures = tuple(
                    executor.submit(action.execute) for action in remaining_actions
                )
                for future in futures:
                    future.result()
        self._execute_successful = True

    def reverse(self):
        if any(action._execute_successful for action in self._link_path_actions):
            log.log(TRACE, "reversing bulk clone creation %s", self.target_prefix)
            for action in reversed(self._link_path_actions):
                action.reverse()
        for action in reversed(self._directory_actions):
            action.reverse()

    def cleanup(self):
        for action in chain(self._directory_actions, self._link_path_actions):
            action.cleanup()

    def _find_clone_directory_parts(self):
        cloneable_paths = {
            _path_parts(action.target_short_path) for action in self._link_path_actions
        }
        candidate_parts = set()
        for path_parts in cloneable_paths:
            for index in range(1, len(path_parts)):
                candidate = path_parts[:index]
                # A non-plain action under a subtree can require prefix rewrite,
                # menu handling, or another side effect that a directory clone skips.
                if not any(
                    _parts_start_with(blocked_path, candidate)
                    for blocked_path in self._blocked_short_paths
                ):
                    candidate_parts.add(candidate)

        return tuple(sorted(candidate_parts, key=lambda parts: (len(parts), parts)))

    def _touch_cloned_python_import_dirs(self, directory_parts, target_dir):
        site_packages = self.transaction_context.get("target_site_packages_short_path")
        if not site_packages:
            return

        # clonefile preserves source directory mtimes; touch import roots so
        # Python's directory caches see newly installed modules immediately.
        site_packages_parts = _path_parts(site_packages)
        touch_paths = []
        if _parts_start_with(site_packages_parts, directory_parts):
            touch_paths.append(join(self.target_prefix, win_path_ok(site_packages)))
        elif _parts_start_with(directory_parts, site_packages_parts):
            touch_paths.append(target_dir)
            touch_paths.append(join(self.target_prefix, win_path_ok(site_packages)))

        for touch_path in touch_paths:
            if isdir(touch_path):
                touch(touch_path)

    def _source_tree_matches_actions(self, source_dir, directory_parts, clone_actions):
        if not isdir(source_dir):
            return False

        expected = {
            _parts_to_path(
                _path_parts(action.source_short_path)[len(directory_parts) :]
            )
            for action in clone_actions
        }
        actual = set()
        for root, dirs, files in os.walk(source_dir):
            # A symlinked directory could pull in files outside the manifest.
            if any(islink(join(root, directory)) for directory in dirs):
                return False
            relative_root = os.path.relpath(root, source_dir)
            for filename in files:
                relative_path = (
                    filename if relative_root == "." else f"{relative_root}/{filename}"
                )
                actual.add(relative_path.replace(os.sep, "/"))
                if relative_path.replace(os.sep, "/") not in expected:
                    return False
        return actual == expected


class PrefixReplaceLinkAction(LinkPathAction):
    def __init__(
        self,
        transaction_context,
        package_info,
        extracted_package_dir,
        source_short_path,
        target_prefix,
        target_short_path,
        link_type,
        prefix_placeholder,
        file_mode,
        source_path_data,
    ):
        # This link_type used in execute(). Make sure we always respect LinkType.copy request.
        link_type = LinkType.copy if link_type == LinkType.copy else LinkType.hardlink
        super().__init__(
            transaction_context,
            package_info,
            extracted_package_dir,
            source_short_path,
            target_prefix,
            target_short_path,
            link_type,
            source_path_data,
        )
        self.prefix_placeholder = prefix_placeholder
        self.file_mode = file_mode
        self.intermediate_path = None

    def verify(self, *, queue_codesign=True):
        validation_error = super().verify()
        if validation_error:
            return validation_error

        if islink(self.source_full_path):
            log.log(
                TRACE,
                "ignoring prefix update for symlink with source path %s",
                self.source_full_path,
            )
            # return
            raise RuntimeError(
                f"Ignoring prefix update for symlink with source path {self.source_full_path}"
            )

        mkdir_p(self.transaction_context["temp_dir"])
        self.intermediate_path = join(
            self.transaction_context["temp_dir"], str(uuid4())
        )

        log.log(
            TRACE, "copying %s => %s", self.source_full_path, self.intermediate_path
        )
        create_link(self.source_full_path, self.intermediate_path, LinkType.copy)
        make_writable(self.intermediate_path)

        try:
            log.log(TRACE, "rewriting prefixes in %s", self.target_full_path)
            should_hash = context.extra_safety_checks
            update_result = update_prefix(
                self.intermediate_path,
                context.target_prefix_override or self.target_prefix,
                self.prefix_placeholder,
                self.file_mode,
                subdir=self.package_info.repodata_record.subdir,
                sign_binary=False,
                return_sha256=should_hash,
            )
            if should_hash:
                updated, sha256_in_prefix = update_result
            else:
                updated = update_result
                sha256_in_prefix = None
            if updated and needs_osx_arm64_codesign(
                self.file_mode, self.package_info.repodata_record.subdir
            ):
                # Normal transaction verify batches all rewritten binaries; a
                # lazy verify during execute must sign before the file is linked.
                if queue_codesign:
                    self.transaction_context.setdefault(
                        "osx_arm64_codesign_paths", []
                    ).append(self.intermediate_path)
                else:
                    codesign_paths((self.intermediate_path,))
        except _PaddingError:
            raise PaddingError(
                self.target_full_path,
                self.prefix_placeholder,
                len(self.prefix_placeholder),
            )

        self.prefix_path_data = PathDataV1.from_objects(
            self.prefix_path_data,
            file_mode=self.file_mode,
            path_type=PathEnum.hardlink,
            prefix_placeholder=self.prefix_placeholder,
            sha256_in_prefix=sha256_in_prefix,
        )

        self._verified = True

    def execute(self):
        if not self._verified:
            self.verify(queue_codesign=False)
        source_path = self.intermediate_path or self.source_full_path
        log.log(TRACE, "linking %s => %s", source_path, self.target_full_path)
        create_link(source_path, self.target_full_path, self.link_type)
        self._execute_successful = True


class MakeMenuAction(CreateInPrefixPathAction):
    @classmethod
    def create_actions(
        cls, transaction_context, package_info, target_prefix, requested_link_type
    ):
        shorcuts_lower = [name.lower() for name in (context.shortcuts_only or ())]
        if context.shortcuts and (
            not context.shortcuts_only
            or (shorcuts_lower and package_info.name.lower() in shorcuts_lower)
        ):
            return tuple(
                cls(transaction_context, package_info, target_prefix, spi.path)
                for spi in package_info.paths_data.paths
                if bool(_MENU_RE.match(spi.path))
            )
        else:
            return ()

    def __init__(
        self, transaction_context, package_info, target_prefix, target_short_path
    ):
        super().__init__(
            transaction_context,
            package_info,
            None,
            None,
            target_prefix,
            target_short_path,
        )
        self._execute_successful = False

    def execute(self):
        log.log(TRACE, "making menu for %s", self.target_full_path)
        make_menu(self.target_prefix, self.target_short_path, remove=False)
        self._execute_successful = True

    def reverse(self):
        if self._execute_successful:
            log.log(TRACE, "removing menu for %s", self.target_full_path)
            make_menu(self.target_prefix, self.target_short_path, remove=True)


class CompileMultiPycAction(MultiPathAction):
    @classmethod
    def create_actions(
        cls,
        transaction_context,
        package_info,
        target_prefix,
        requested_link_type,
        file_link_actions,
    ):
        noarch = package_info.package_metadata and package_info.package_metadata.noarch
        if noarch is not None and noarch.type == NoarchType.python:
            noarch_py_file_re = re.compile(r"^site-packages[/\\][^\t\n\r\f\v]+\.py$")
            py_ver = transaction_context["target_python_version"]
            py_files = tuple(
                axn.target_short_path
                for axn in file_link_actions
                if getattr(axn, "source_short_path")
                and noarch_py_file_re.match(axn.source_short_path)
            )
            pyc_files = tuple(pyc_path(pf, py_ver) for pf in py_files)
            return (
                cls(
                    transaction_context,
                    package_info,
                    target_prefix,
                    py_files,
                    pyc_files,
                ),
            )
        else:
            return ()

    def __init__(
        self,
        transaction_context,
        package_info,
        target_prefix,
        source_short_paths,
        target_short_paths,
    ):
        self.transaction_context = transaction_context
        self.package_info = package_info
        self.target_prefix = target_prefix
        self.source_short_paths = source_short_paths
        self.target_short_paths = target_short_paths
        self.prefix_path_data = None
        self.prefix_paths_data = [
            PathDataV1(
                _path=p,
                path_type=PathEnum.pyc_file,
            )
            for p in self.target_short_paths
        ]
        self._execute_successful = False

    @property
    def target_full_paths(self):
        def join_or_none(prefix, short_path):
            if prefix is None or short_path is None:
                return None
            else:
                return join(prefix, win_path_ok(short_path))

        return (join_or_none(self.target_prefix, p) for p in self.target_short_paths)

    @property
    def source_full_paths(self):
        def join_or_none(prefix, short_path):
            if prefix is None or short_path is None:
                return None
            else:
                return join(prefix, win_path_ok(short_path))

        return (join_or_none(self.target_prefix, p) for p in self.source_short_paths)

    def verify(self):
        self._verified = True

    def cleanup(self):
        # create actions typically won't need cleanup
        pass

    def execute(self):
        # compile_pyc is sometimes expected to fail, for example a python 3.6 file
        #   installed into a python 2 environment, but no code paths actually importing it
        # technically then, this file should be removed from the manifest in conda-meta, but
        #   at the time of this writing that's not currently happening
        log.log(TRACE, "compiling %s", " ".join(self.target_full_paths))
        target_python_version = self.transaction_context["target_python_version"]
        python_short_path = get_python_short_path(target_python_version)
        python_full_path = join(self.target_prefix, win_path_ok(python_short_path))
        compile_multiple_pyc(
            python_full_path,
            self.source_full_paths,
            self.target_full_paths,
            self.target_prefix,
            self.transaction_context["target_python_version"],
        )
        self._execute_successful = True

        # Update prefix_paths_data with the file sizes now that the .pyc files exist.
        # Note: when used via AggregateCompileMultiPycAction, this updates the
        # aggregate's prefix_paths_data. The aggregate's execute() will separately
        # update each individual action's data.
        for path_data in self.prefix_paths_data:
            pyc_full_path = join(self.target_prefix, win_path_ok(path_data._path))
            try:
                path_data.size_in_bytes = getsize(pyc_full_path)
            except OSError:
                log.log(TRACE, "could not get size for %s", pyc_full_path)

    def reverse(self):
        # this removes all pyc files even if they were not created
        if self._execute_successful:
            log.log(
                TRACE, "reversing pyc creation %s", " ".join(self.target_full_paths)
            )
            for target_full_path in self.target_full_paths:
                rm_rf(target_full_path)


class AggregateCompileMultiPycAction(CompileMultiPycAction):
    """Bunch up all of our compile actions, so that they all get carried out at once.
    This avoids clobbering and is faster when we have several individual packages requiring
    compilation.
    """

    def __init__(self, *individuals, **kw):
        self._individuals = individuals
        transaction_context = individuals[0].transaction_context
        # not used; doesn't matter
        package_info = individuals[0].package_info
        target_prefix = individuals[0].target_prefix
        source_short_paths = set()
        target_short_paths = set()
        for individual in individuals:
            source_short_paths.update(individual.source_short_paths)
            target_short_paths.update(individual.target_short_paths)
        super().__init__(
            transaction_context,
            package_info,
            target_prefix,
            source_short_paths,
            target_short_paths,
        )

    def execute(self):
        super().execute()
        # Update each individual action's prefix_paths_data with file sizes.
        # The manifest is written using individual actions' data, not the aggregate's.
        for individual in self._individuals:
            for path_data in individual.prefix_paths_data:
                pyc_full_path = join(self.target_prefix, win_path_ok(path_data._path))
                try:
                    path_data.size_in_bytes = getsize(pyc_full_path)
                except OSError:
                    log.log(TRACE, "could not get size for %s", pyc_full_path)


class CreatePythonEntryPointAction(CreateInPrefixPathAction):
    @classmethod
    def create_actions(
        cls, transaction_context, package_info, target_prefix, requested_link_type
    ):
        noarch = package_info.package_metadata and package_info.package_metadata.noarch
        if noarch is not None and noarch.type == NoarchType.python:

            def this_triplet(entry_point_def):
                command, module, func = parse_entry_point_def(entry_point_def)
                target_short_path = f"{BIN_DIRECTORY}/{command}"
                if not normpath(target_short_path).startswith(BIN_DIRECTORY + os.sep):
                    raise ValueError(
                        f"target_short_path must point to {BIN_DIRECTORY}: {target_short_path!r}"
                    )
                if on_win:
                    target_short_path += "-script.py"
                return target_short_path, module, func

            actions = tuple(
                cls(
                    transaction_context,
                    package_info,
                    target_prefix,
                    *this_triplet(ep_def),
                )
                for ep_def in noarch.entry_points or ()
            )

            if on_win:  # pragma: unix no cover
                actions += tuple(
                    LinkPathAction.create_python_entry_point_windows_exe_action(
                        transaction_context,
                        package_info,
                        target_prefix,
                        requested_link_type,
                        ep_def,
                    )
                    for ep_def in noarch.entry_points or ()
                )

            return actions
        else:
            return ()

    def __init__(
        self,
        transaction_context,
        package_info,
        target_prefix,
        target_short_path,
        module,
        func,
    ):
        super().__init__(
            transaction_context,
            package_info,
            None,
            None,
            target_prefix,
            target_short_path,
        )
        self.module = module
        self.func = func

        if on_win:
            path_type = PathEnum.windows_python_entry_point_script
        else:
            path_type = PathEnum.unix_python_entry_point
        self.prefix_path_data = PathDataV1(
            _path=self.target_short_path,
            path_type=path_type,
        )

        self._execute_successful = False

    def execute(self):
        log.log(TRACE, "creating python entry point %s", self.target_full_path)
        if on_win:
            python_full_path = None
        else:
            target_python_version = self.transaction_context["target_python_version"]
            python_short_path = get_python_short_path(target_python_version)
            python_full_path = join(
                context.target_prefix_override or self.target_prefix,
                win_path_ok(python_short_path),
            )

        create_python_entry_point(
            self.target_full_path, python_full_path, self.module, self.func
        )
        try:
            self.prefix_path_data.size_in_bytes = getsize(self.target_full_path)
        except OSError:
            log.log(TRACE, "could not get size for %s", self.target_full_path)
        self._execute_successful = True

    def reverse(self):
        if self._execute_successful:
            log.log(
                TRACE, "reversing python entry point creation %s", self.target_full_path
            )
            rm_rf(self.target_full_path)


class CreatePrefixRecordAction(CreateInPrefixPathAction):
    # this is the action that creates a packages json file in the conda-meta/ directory

    @classmethod
    def create_actions(
        cls,
        transaction_context,
        package_info,
        target_prefix,
        requested_link_type,
        requested_spec: MatchSpec | list[MatchSpec],
        all_link_path_actions,
    ):
        extracted_package_dir = package_info.extracted_package_dir
        target_short_path = f"conda-meta/{basename(extracted_package_dir)}.json"
        return (
            cls(
                transaction_context,
                package_info,
                target_prefix,
                target_short_path,
                requested_link_type,
                requested_spec,
                all_link_path_actions,
            ),
        )

    def __init__(
        self,
        transaction_context,
        package_info,
        target_prefix,
        target_short_path,
        requested_link_type,
        requested_spec: MatchSpec | list[MatchSpec],
        all_link_path_actions,
    ):
        super().__init__(
            transaction_context,
            package_info,
            None,
            None,
            target_prefix,
            target_short_path,
        )
        self.requested_link_type = requested_link_type
        self.requested_spec = requested_spec
        self.all_link_path_actions = list(all_link_path_actions)
        self._execute_successful = False

    def execute(self):
        requested_link_type = (
            LinkType.copy
            if self.requested_link_type == LinkType.clone
            else self.requested_link_type
        )
        # LinkType.clone is an install-time CoW optimization, not a persisted
        # prefix metadata mode. Record it as copy so older tooling is unaffected.
        link = Link(
            source=self.package_info.extracted_package_dir,
            type=requested_link_type,
        )
        extracted_package_dir = self.package_info.extracted_package_dir
        package_tarball_full_path = self.package_info.package_tarball_full_path

        def files_from_action(link_path_action):
            if isinstance(link_path_action, CompileMultiPycAction):
                return link_path_action.target_short_paths
            else:
                return (
                    (link_path_action.target_short_path,)
                    if isinstance(link_path_action, CreateInPrefixPathAction)
                    and (
                        not hasattr(link_path_action, "link_type")
                        or link_path_action.link_type != LinkType.directory
                    )
                    else ()
                )

        def paths_from_action(link_path_action):
            if isinstance(link_path_action, CompileMultiPycAction):
                return link_path_action.prefix_paths_data
            else:
                if (
                    not hasattr(link_path_action, "prefix_path_data")
                    or link_path_action.prefix_path_data is None
                ):
                    return ()
                else:
                    return (link_path_action.prefix_path_data,)

        files = list(
            chain.from_iterable(
                files_from_action(x) for x in self.all_link_path_actions if x
            )
        )
        paths_data = PathsData(
            paths_version=1,
            paths=chain.from_iterable(
                paths_from_action(x) for x in self.all_link_path_actions if x
            ),
        )

        if self.requested_spec:
            if isinstance(self.requested_spec, tuple | list):
                requested_specs = [str(spec) for spec in self.requested_spec]
                requested_spec_str = str(MatchSpec.merge(self.requested_spec)[0])
            else:
                requested_spec_str = str(self.requested_spec)
                requested_specs = (requested_spec_str,)
        else:
            requested_spec_str = None
            requested_specs = ()

        self.prefix_record = PrefixRecord.from_objects(
            self.package_info.repodata_record,
            # self.package_info.index_json_record,
            self.package_info.package_metadata,
            requested_spec=requested_spec_str,
            requested_specs=requested_specs,
            paths_data=paths_data,
            files=files,
            link=link,
            url=self.package_info.url,
            extracted_package_dir=extracted_package_dir,
            package_tarball_full_path=package_tarball_full_path,
        )

        log.log(TRACE, "creating linked package record %s", self.target_full_path)
        PrefixData(self.target_prefix).insert(self.prefix_record)
        self._execute_successful = True

    def reverse(self):
        log.log(
            TRACE, "reversing linked package record creation %s", self.target_full_path
        )
        if self._execute_successful:
            PrefixData(self.target_prefix).remove(
                self.package_info.repodata_record.name
            )


class UpdateHistoryAction(CreateInPrefixPathAction):
    @classmethod
    def create_actions(
        cls,
        transaction_context,
        target_prefix,
        remove_specs,
        update_specs,
        neutered_specs,
    ):
        target_short_path = join("conda-meta", "history")
        return (
            cls(
                transaction_context,
                target_prefix,
                target_short_path,
                remove_specs,
                update_specs,
                neutered_specs,
            ),
        )

    def __init__(
        self,
        transaction_context,
        target_prefix,
        target_short_path,
        remove_specs,
        update_specs,
        neutered_specs,
    ):
        super().__init__(
            transaction_context, None, None, None, target_prefix, target_short_path
        )
        self.remove_specs = remove_specs
        self.update_specs = update_specs
        self.neutered_specs = neutered_specs

        self.hold_path = self.target_full_path + CONDA_TEMP_EXTENSION

    def execute(self):
        log.log(TRACE, "updating environment history %s", self.target_full_path)

        if lexists(self.target_full_path):
            copy(self.target_full_path, self.hold_path)

        h = History(self.target_prefix)
        if not isfile(h.path):
            PrefixData(self.target_prefix).set_creation_time()
        h.update()
        h.write_specs(self.remove_specs, self.update_specs, self.neutered_specs)

    def reverse(self):
        if lexists(self.hold_path):
            log.log(TRACE, "moving %s => %s", self.hold_path, self.target_full_path)
            backoff_rename(self.hold_path, self.target_full_path, force=True)
        if isfile(hpath := History(self.target_prefix).path):
            rm_rf(hpath)

    def cleanup(self):
        rm_rf(self.hold_path)


class RegisterEnvironmentLocationAction(PathAction):
    def __init__(self, transaction_context, target_prefix):
        self.transaction_context = transaction_context
        self.target_prefix = target_prefix

        self._execute_successful = False

    def verify(self):
        user_environments_txt_file = get_user_environments_txt_file()
        try:
            touch(user_environments_txt_file, mkdir=True, sudo_safe=True)
            self._verified = True
        except NotWritableError:
            log.warning(
                "Unable to create environments file. Path not writable.\n"
                "  environment location: %s\n",
                user_environments_txt_file,
            )

    def execute(self):
        log.log(TRACE, "registering environment in catalog %s", self.target_prefix)

        register_env(self.target_prefix)
        self._execute_successful = True

    def reverse(self):
        pass

    def cleanup(self):
        pass

    @property
    def target_full_path(self):
        raise NotImplementedError()


# ######################################################
#  Removal of Paths within a Prefix
# ######################################################


class RemoveFromPrefixPathAction(PrefixPathAction):
    def __init__(
        self, transaction_context, linked_package_data, target_prefix, target_short_path
    ):
        super().__init__(transaction_context, target_prefix, target_short_path)
        self.linked_package_data = linked_package_data

    def verify(self):
        # inability to remove will trigger a rollback
        # can't definitely know if path can be removed until it's attempted and failed
        self._verified = True


class UnlinkPathAction(RemoveFromPrefixPathAction):
    def __init__(
        self,
        transaction_context,
        linked_package_data,
        target_prefix,
        target_short_path,
        link_type=LinkType.hardlink,
    ):
        super().__init__(
            transaction_context, linked_package_data, target_prefix, target_short_path
        )
        self.holding_short_path = self.target_short_path + CONDA_TEMP_EXTENSION
        self.holding_full_path = self.target_full_path + CONDA_TEMP_EXTENSION
        self.link_type = link_type

    def execute(self):
        if self.link_type != LinkType.directory:
            log.log(
                TRACE,
                "renaming %s => %s",
                self.target_short_path,
                self.holding_short_path,
            )
            backoff_rename(self.target_full_path, self.holding_full_path, force=True)

    def reverse(self):
        if self.link_type != LinkType.directory and lexists(self.holding_full_path):
            log.log(
                TRACE,
                "reversing rename %s => %s",
                self.holding_short_path,
                self.target_short_path,
            )
            backoff_rename(self.holding_full_path, self.target_full_path, force=True)

    def cleanup(self):
        if not isdir(self.holding_full_path):
            rm_rf(self.holding_full_path, clean_empty_parents=True)


class RemoveMenuAction(RemoveFromPrefixPathAction):
    @classmethod
    def create_actions(cls, transaction_context, linked_package_data, target_prefix):
        return tuple(
            cls(transaction_context, linked_package_data, target_prefix, trgt)
            for trgt in linked_package_data.files
            if bool(_MENU_RE.match(trgt))
        )

    def __init__(
        self, transaction_context, linked_package_data, target_prefix, target_short_path
    ):
        super().__init__(
            transaction_context, linked_package_data, target_prefix, target_short_path
        )

    def execute(self):
        log.log(TRACE, "removing menu for %s ", self.target_prefix)
        make_menu(self.target_prefix, self.target_short_path, remove=True)

    def reverse(self):
        log.log(TRACE, "re-creating menu for %s ", self.target_prefix)
        make_menu(self.target_prefix, self.target_short_path, remove=False)

    def cleanup(self):
        pass


class RemoveLinkedPackageRecordAction(UnlinkPathAction):
    def __init__(
        self, transaction_context, linked_package_data, target_prefix, target_short_path
    ):
        super().__init__(
            transaction_context, linked_package_data, target_prefix, target_short_path
        )

    def execute(self):
        super().execute()
        PrefixData(self.target_prefix).remove(self.linked_package_data.name)

    def reverse(self):
        super().reverse()
        PrefixData(self.target_prefix)._load_single_record(self.target_full_path)


class UnregisterEnvironmentLocationAction(PathAction):
    def __init__(self, transaction_context, target_prefix):
        self.transaction_context = transaction_context
        self.target_prefix = target_prefix

        self._execute_successful = False

    def verify(self):
        self._verified = True

    def execute(self):
        log.log(TRACE, "unregistering environment in catalog %s", self.target_prefix)

        unregister_env(self.target_prefix)
        self._execute_successful = True

    def reverse(self):
        pass

    def cleanup(self):
        pass

    @property
    def target_full_path(self):
        raise NotImplementedError()


# ######################################################
#  Fetch / Extract Actions
# ######################################################


class CacheUrlAction(PathAction):
    def __init__(
        self,
        url,
        target_pkgs_dir,
        target_package_basename,
        sha256=None,
        size=None,
        md5=None,
    ):
        self.url = url
        self.target_pkgs_dir = target_pkgs_dir
        self.target_package_basename = target_package_basename
        self.sha256 = sha256
        self.size = size
        self.md5 = md5
        self.hold_path = self.target_full_path + CONDA_TEMP_EXTENSION

    def verify(self):
        if "::" in self.url:
            raise ValueError("URL cannot contain '::'")
        self._verified = True

    def execute(self, progress_update_callback=None):
        # I hate inline imports, but I guess it's ok since we're importing from the conda.core
        # The alternative is passing the PackageCache class to CacheUrlAction __init__
        from .package_cache_data import PackageCacheData

        target_package_cache = PackageCacheData(self.target_pkgs_dir)

        log.log(TRACE, "caching url %s => %s", self.url, self.target_full_path)

        if lexists(self.hold_path):
            rm_rf(self.hold_path)

        if lexists(self.target_full_path):
            if self.url.startswith("file:/") and self.url == path_to_url(
                self.target_full_path
            ):
                # the source and destination are the same file, so we're done
                return
            else:
                backoff_rename(self.target_full_path, self.hold_path, force=True)

        if self.url.startswith("file:/"):
            source_path = url_to_path(self.url)
            self._execute_local(
                source_path, target_package_cache, progress_update_callback
            )
        else:
            self._execute_channel(target_package_cache, progress_update_callback)

    def _execute_local(
        self, source_path, target_package_cache, progress_update_callback=None
    ):
        from .package_cache_data import PackageCacheData

        if dirname(source_path) in context.pkgs_dirs:
            # if url points to another package cache, link to the writable cache
            create_hard_link_or_copy(source_path, self.target_full_path)
            source_package_cache = PackageCacheData(dirname(source_path))

            # the package is already in a cache, so it came from a remote url somewhere;
            #   make sure that remote url is the most recent url in the
            #   writable cache urls.txt
            origin_url = source_package_cache._urls_data.get_url(
                self.target_package_basename
            )
            if origin_url and has_platform(origin_url, context.known_subdirs):
                target_package_cache._urls_data.add_url(origin_url)
        else:
            # so our tarball source isn't a package cache, but that doesn't mean it's not
            #   in another package cache somewhere
            # let's try to find the actual, remote source url by matching md5sums, and then
            #   record that url as the remote source url in urls.txt
            # we do the search part of this operation before the create_link so that we
            #   don't md5sum-match the file created by 'create_link'
            # there is no point in looking for the tarball in the cache that we are writing
            #   this file into because we have already removed the previous file if there was
            #   any. This also makes sure that we ignore the md5sum of a possible extracted
            #   directory that might exist in this cache because we are going to overwrite it
            #   anyway when we extract the tarball.
            source_md5sum = compute_sum(source_path, "md5")
            exclude_caches = (self.target_pkgs_dir,)
            pc_entry = PackageCacheData.tarball_file_in_cache(
                source_path, source_md5sum, exclude_caches=exclude_caches
            )

            if pc_entry:
                origin_url = target_package_cache._urls_data.get_url(
                    pc_entry.extracted_package_dir
                )
            else:
                origin_url = None

            # copy the tarball to the writable cache
            create_link(
                source_path,
                self.target_full_path,
                link_type=LinkType.copy,
                force=context.force,
            )

            if origin_url and has_platform(origin_url, context.known_subdirs):
                target_package_cache._urls_data.add_url(origin_url)
            else:
                target_package_cache._urls_data.add_url(self.url)

    def _execute_channel(self, target_package_cache, progress_update_callback=None):
        kwargs = {}
        if self.size is not None:
            kwargs["size"] = self.size
        if self.sha256:
            kwargs["sha256"] = self.sha256
        elif self.md5:
            kwargs["md5"] = self.md5
        download(
            self.url,
            self.target_full_path,
            progress_update_callback=progress_update_callback,
            **kwargs,
        )
        target_package_cache._urls_data.add_url(self.url)

    def reverse(self):
        if lexists(self.hold_path):
            log.log(TRACE, "moving %s => %s", self.hold_path, self.target_full_path)
            backoff_rename(self.hold_path, self.target_full_path, force=True)

    def cleanup(self):
        rm_rf(self.hold_path)

    @property
    def target_full_path(self):
        return join(self.target_pkgs_dir, self.target_package_basename)

    def __str__(self):
        return f"CacheUrlAction<url={self.url!r}, target_full_path={self.target_full_path!r}>"


class ExtractPackageAction(PathAction):
    def __init__(
        self,
        source_full_path,
        target_pkgs_dir,
        target_extracted_dirname,
        record_or_spec,
        sha256,
        size,
        md5,
    ):
        self.source_full_path = source_full_path
        self.target_pkgs_dir = target_pkgs_dir
        self.target_extracted_dirname = target_extracted_dirname
        self.hold_path = self.target_full_path + CONDA_TEMP_EXTENSION
        self.record_or_spec = record_or_spec
        self.sha256 = sha256
        self.size = size
        self.md5 = md5

    def verify(self):
        self._verified = True

    def execute(self, progress_update_callback=None):
        # I hate inline imports, but I guess it's ok since we're importing from the conda.core
        # The alternative is passing the the classes to ExtractPackageAction __init__
        from .package_cache_data import PackageCacheData

        log.log(
            TRACE, "extracting %s => %s", self.source_full_path, self.target_full_path
        )

        if lexists(self.target_full_path):
            rm_rf(self.target_full_path)

        # extract the package using the appropriate plugin
        context.plugin_manager.extract_package(
            self.source_full_path,
            self.target_full_path,
        )

        try:
            raw_index_json = read_index_json(self.target_full_path)
        except (OSError, json.JSONDecodeError, FileNotFoundError):
            # At this point, we can assume the package tarball is bad.
            # Remove everything and move on.
            print(
                f"ERROR: Encountered corrupt package tarball at {self.source_full_path}. Conda has "
                "left it in place. Please report this to the maintainers "
                "of the package."
            )
            sys.exit(1)

        if isinstance(self.record_or_spec, MatchSpec):
            url = self.record_or_spec.get_raw_value("url")
            if not url:
                raise ValueError("URL cannot be empty.")
            channel = (
                Channel(url)
                if has_platform(url, context.known_subdirs)
                else Channel(None)
            )
            fn = basename(url)
            sha256 = self.sha256 or compute_sum(self.source_full_path, "sha256")
            size = getsize(self.source_full_path)
            if self.size is not None and size != self.size:
                raise RuntimeError(
                    f"Computed size ({size}) does not match expected value {self.size}"
                )
            md5 = self.md5 or compute_sum(self.source_full_path, "md5")
            repodata_record = PackageRecord.from_objects(
                raw_index_json,
                url=url,
                channel=channel,
                fn=fn,
                sha256=sha256,
                size=size,
                md5=md5,
            )
        else:
            repodata_record = PackageRecord.from_objects(
                self.record_or_spec, raw_index_json
            )

        repodata_record_path = join(
            self.target_full_path, "info", "repodata_record.json"
        )
        write_as_json_to_file(repodata_record_path, repodata_record)

        target_package_cache = PackageCacheData(self.target_pkgs_dir)
        package_cache_record = PackageCacheRecord.from_objects(
            repodata_record,
            package_tarball_full_path=self.source_full_path,
            extracted_package_dir=self.target_full_path,
        )
        target_package_cache.insert(package_cache_record)

    def reverse(self):
        rm_rf(self.target_full_path)
        if lexists(self.hold_path):
            log.log(TRACE, "moving %s => %s", self.hold_path, self.target_full_path)
            rm_rf(self.target_full_path)
            backoff_rename(self.hold_path, self.target_full_path)

    def cleanup(self):
        rm_rf(self.hold_path)

    @property
    def target_full_path(self):
        return join(self.target_pkgs_dir, self.target_extracted_dirname)

    def __str__(self):
        return f"ExtractPackageAction<source_full_path={self.source_full_path!r}, target_full_path={self.target_full_path!r}>"
