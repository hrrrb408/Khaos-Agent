"""Load skill files from disk.

Each skill is a single Markdown file. A leading ``---`` fenced block is parsed
as YAML frontmatter; the remainder is the skill body. Files without valid
frontmatter (or missing required ``name``/``description``) are skipped with a
warning rather than aborting the whole scan, mirroring Hermes' tolerant loader.
"""

from __future__ import annotations

import logging
import os
import stat
from pathlib import Path

import yaml

from khaos.skills.skill import Skill, SkillParseError, SkillTrustTier

logger = logging.getLogger(__name__)

# Recognized skill filenames: Hermes convention plus any .md in a skills dir.
_SKILL_FILENAMES = {"SKILL.md", "skill.md"}
_SKILL_SUFFIX = ".md"

_FRONTMATTER_DELIM = "---"
MAX_SKILL_FILES = 128
MAX_SKILL_FILE_BYTES = 1_048_576
MAX_SKILL_FRONTMATTER_BYTES = 65_536
MAX_SKILL_YAML_DEPTH = 16
MAX_SKILL_BODY_CHARS = 500_000
# Batch 9.6 (round-9 §二十): cap the number of CANDIDATE files scanned
# (opened + parsed), not just the number of successfully-loaded skills.
# Without this an attacker can place thousands of invalid YAML / missing-
# field / duplicate-name files that never increment ``len(skills)`` but
# each incur an open + read + parse + YAML compose.  The candidate cap
# stops the scan BEFORE any parse work.
MAX_SKILL_CANDIDATES = MAX_SKILL_FILES * 4  # 512 — tolerance for invalid files
# Batch 10.6 (round-10 §十): cap the number of directory ENTRIES scanned
# per directory (before any skill-file filtering).  Without this a skills
# root with millions of noise files is fully materialised into a list
# before the first yield.  The cap stops the scandir loop early.
MAX_SKILL_DIR_ENTRIES = 4096
# Batch 11.7 (round-11 §十一): GLOBAL directory-entry budget shared
# across all roots AND all subdirectories.  Round-10's per-directory cap
# still allowed 4096 subdirs × 4096 entries ≈ 16.7M scandir iterations.
# This global cap stops the multiplicative blowup.
MAX_SKILL_TOTAL_DIRECTORY_ENTRIES = 8192
# Batch 11.7: cap the number of subdirectories descended into (each
# subdir incurs a second scandir).  Without this a root with 4096
# subdirs triggers 4096 extra scans.
MAX_SKILL_SUBDIRECTORIES = 256
# Batch 10.6 (round-10 §十): cap the total number of composed YAML nodes
# traversed during depth checking.  A pathological YAML document can have
# a huge flat structure that is within the depth limit but has millions
# of nodes, consuming CPU.  This budget aborts the traversal early.
MAX_SKILL_YAML_NODES = 10_000


class SkillLoader:
    """Scan directories for skill files and parse them into Skill objects."""

    def __init__(self, roots: list[Path] | None = None):
        self.roots = [Path(root) for root in (roots or [])]

    def load_all(self, trust_tier: SkillTrustTier = SkillTrustTier.PROJECT) -> list[Skill]:
        """Load every parseable skill from all roots.

        Order: roots are scanned in the order given; within a root, files are
        sorted by name for deterministic output. First ``name`` wins on
        collision (shadowing), mirroring Hermes' first-match-wins rule.

        P2-5: ``trust_tier`` stamps every loaded skill with where it came
        from (PROJECT by default — repository skills are the untrusted case).
        Callers loading from the user-global ``~/.khaos/skills`` pass
        ``SkillTrustTier.USER``.

        Batch 9.6 (round-9 §二十): the file-count cap now counts
        CANDIDATES (files opened/parsed), not just successfully-loaded
        skills.  Previously an attacker could place thousands of invalid
        YAML / missing-field / duplicate-name files that never incremented
        ``len(skills)`` but each incurred an open + read + parse.  The
        candidate cap (MAX_SKILL_CANDIDATES) stops the scan before any
        parse work on the (N+1)th file.
        """
        seen_names: set[str] = set()
        skills: list[Skill] = []
        candidates_scanned = 0
        # Batch 11.7: a shared mutable global directory-entry budget
        # across ALL roots and subdirectories, so the scan cannot
        # multiplicatively blow up (4096 subdirs × 4096 entries).
        global_entry_budget = [0]
        for root in self.roots:
            for path in self._iter_skill_files(root, global_entry_budget):
                candidates_scanned += 1
                if candidates_scanned > MAX_SKILL_CANDIDATES:
                    logger.warning(
                        "skill candidate limit reached (%d scanned, %d "
                        "accepted); remaining files in %s ignored",
                        MAX_SKILL_CANDIDATES, len(skills), root,
                    )
                    return skills
                if len(skills) >= MAX_SKILL_FILES:
                    logger.warning(
                        "skill limit reached (%d); remaining files ignored",
                        MAX_SKILL_FILES,
                    )
                    return skills
                try:
                    skill = self.load_file(path, trust_tier=trust_tier)
                except SkillParseError as exc:
                    logger.warning("skipping skill %s: %s", path, exc)
                    continue
                except OSError as exc:
                    logger.warning("cannot read skill %s: %s", path, exc)
                    continue
                except RecursionError as exc:
                    # Batch 10.6: a cyclic YAML alias graph can blow the
                    # Python recursion limit.  Skip the offending skill
                    # instead of crashing the whole load_all() scan.
                    logger.warning("skipping skill %s: YAML recursion: %s", path, exc)
                    continue
                if skill.name in seen_names:
                    logger.debug("skill %s shadowed by earlier root", skill.name)
                    continue
                seen_names.add(skill.name)
                skills.append(skill)
        return skills

    def load_file(self, path: Path, trust_tier: SkillTrustTier = SkillTrustTier.PROJECT) -> Skill:
        """Parse a single skill file. Raise SkillParseError on invalid input.

        P2-5: ``trust_tier`` records where the skill was loaded from
        (PROJECT for repository skills, USER for ~/.khaos/skills, BUILTIN for
        shipped skills) so the prompt renderer can mark untrusted sources.
        """
        path = Path(path)
        if os.name == "nt" and not hasattr(os, "O_NOFOLLOW"):
            # Following a reparse point here could redirect an untrusted
            # skill outside its declared root. Until a Windows native
            # no-follow handle path is available, fail closed instead of
            # silently degrading to ordinary ``open`` semantics.
            raise SkillParseError(
                f"{path}: secure open failed: Windows no-follow handle support is unavailable"
            )
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(path, flags)
        except OSError as exc:
            raise SkillParseError(f"{path}: secure open failed: {exc}") from exc
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise SkillParseError(f"{path}: skill must be a regular file")
            if hasattr(os, "getuid") and info.st_uid != os.getuid():
                raise SkillParseError(f"{path}: skill is not owned by current user")
            if info.st_size > MAX_SKILL_FILE_BYTES:
                raise SkillParseError(
                    f"{path}: skill exceeds {MAX_SKILL_FILE_BYTES} bytes"
                )
            raw = os.read(fd, MAX_SKILL_FILE_BYTES + 1)
        finally:
            os.close(fd)
        if len(raw) > MAX_SKILL_FILE_BYTES:
            raise SkillParseError(f"{path}: skill exceeds size limit")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SkillParseError(f"{path}: skill is not UTF-8") from exc
        frontmatter, body = self._split_frontmatter(text)
        if frontmatter is None:
            raise SkillParseError(f"{path}: missing YAML frontmatter")
        if len(frontmatter.encode("utf-8")) > MAX_SKILL_FRONTMATTER_BYTES:
            raise SkillParseError(f"{path}: YAML frontmatter exceeds size limit")
        try:
            node = yaml.compose(frontmatter, Loader=yaml.SafeLoader)
            if node is not None and _yaml_depth(node) > MAX_SKILL_YAML_DEPTH:
                raise SkillParseError(
                    f"{path}: YAML nesting exceeds {MAX_SKILL_YAML_DEPTH}"
                )
            data = yaml.safe_load(frontmatter)
        except yaml.YAMLError as exc:
            raise SkillParseError(f"{path}: invalid YAML frontmatter: {exc}") from exc
        except RecursionError as exc:
            # Batch 10.6: a cyclic YAML alias graph blows the recursion
            # limit before the depth check can catch it.  Convert to a
            # parse error so load_all() can skip this single skill.
            raise SkillParseError(
                f"{path}: YAML frontmatter has a cyclic alias graph"
            ) from exc
        if not isinstance(data, dict):
            raise SkillParseError(f"{path}: frontmatter must be a mapping")

        name = str(data.get("name", "")).strip()
        description = str(data.get("description", "")).strip()
        if not name:
            raise SkillParseError(f"{path}: missing required field 'name'")
        if not description:
            raise SkillParseError(f"{path}: missing required field 'description'")

        category = str(data.get("category", "general")).strip() or "general"
        raw_triggers = data.get("triggers", []) or []
        if not isinstance(raw_triggers, list):
            raise SkillParseError(f"{path}: 'triggers' must be a list")

        body = body.strip()
        if len(body) > MAX_SKILL_BODY_CHARS:
            raise SkillParseError(f"{path}: skill body exceeds prompt budget")
        return Skill(
            name=name,
            description=description,
            category=category,
            triggers=[str(trigger) for trigger in raw_triggers],
            body=body,
            path=Path(path),
            trust_tier=trust_tier,
        )

    @staticmethod
    def _split_frontmatter(text: str) -> tuple[str | None, str]:
        """Split leading ``---\\n...\\n---\\n`` from the body.

        Returns ``(frontmatter_text_or_None, body)``. Only a frontmatter block
        that starts on the very first line is recognized.
        """
        stripped = text.lstrip("\ufeff")  # tolerate BOM
        if not stripped.startswith(_FRONTMATTER_DELIM):
            return None, text
        # First line is the opening delimiter.
        newline = stripped.find("\n")
        if newline == -1:
            return None, text
        rest = stripped[newline + 1 :]
        # Find the closing delimiter on its own line.
        close = rest.find(f"\n{_FRONTMATTER_DELIM}")
        if close == -1:
            return None, text
        frontmatter = rest[:close]
        after = rest[close + 1 + len(_FRONTMATTER_DELIM) :]
        # Skip the trailing newline after the closing delim.
        after = after.removeprefix("\n")
        return frontmatter, after

    @staticmethod
    def _iter_skill_files(root: Path, global_entry_budget: list[int] | None = None):
        """Yield candidate skill files under ``root`` (non-recursive top level
        plus one level of subdirectories named after the skill).

        Batch 10.6 (round-10 §十): cap scandir at MAX_SKILL_DIR_ENTRIES
        per directory.

        Batch 11.7 (round-11 §十一): a GLOBAL directory-entry budget
        (``global_entry_budget``, shared across all roots + subdirs) stops
        the multiplicative blowup where 4096 subdirs × 4096 entries ≈
        16.7M iterations.  Also caps the number of subdirectories
        descended into (MAX_SKILL_SUBDIRECTORIES).  Both are generous
        enough that legitimate skills roots are unaffected.
        """
        if global_entry_budget is None:
            global_entry_budget = [0]

        def _budget_exhausted() -> bool:
            return global_entry_budget[0] >= MAX_SKILL_TOTAL_DIRECTORY_ENTRIES  # type: ignore[operator]

        try:
            root_info = root.lstat()
        except OSError:
            return
        if not stat.S_ISDIR(root_info.st_mode) or root.is_symlink():
            return
        if hasattr(os, "getuid") and root_info.st_uid != os.getuid():
            logger.warning("skill root is not owned by current user: %s", root)
            return
        # Top-level skill files — collect up to MAX_SKILL_DIR_ENTRIES,
        # then sort the bounded list for deterministic order.
        top_level: list[Path] = []
        subdirs: list[Path] = []
        entries_scanned = 0
        budget_exceeded = False
        try:
            with os.scandir(root) as entries:
                # ``SKILL.md`` is the conventional root entry. Probe it
                # explicitly before consuming the bounded directory stream;
                # otherwise a large attacker-controlled prefix of noise
                # entries can hide the root skill behind the scan cap.
                conventional = root / "SKILL.md"
                if (
                    conventional.is_file()
                    and not conventional.is_symlink()
                    and _is_skill_filename(conventional)
                ):
                    top_level.append(conventional)
                for entry in entries:
                    entries_scanned += 1
                    global_entry_budget[0] += 1
                    if (
                        entries_scanned > MAX_SKILL_DIR_ENTRIES
                        or _budget_exhausted()
                    ):
                        budget_exceeded = True
                        break
                    entry_path = Path(entry.path)
                    if entry_path == conventional:
                        continue
                    if entry.is_file(follow_symlinks=False) and _is_skill_filename(entry_path):
                        top_level.append(entry_path)
                    elif entry.is_dir(follow_symlinks=False):
                        subdirs.append(entry_path)
        except OSError as exc:
            logger.warning("cannot scan skill root %s: %s", root, exc)
            return
        if budget_exceeded:
            logger.warning(
                "skill root %s scan truncated (per-dir %d / global %d "
                "budget); some skills may be missed",
                root, MAX_SKILL_DIR_ENTRIES, MAX_SKILL_TOTAL_DIRECTORY_ENTRIES,
            )
        yield from sorted(top_level, key=lambda p: p.name)
        # Subdirectory skills: <root>/<name>/SKILL.md
        # Batch 12.3 (round-12 §十三): sort subdirectories BEFORE truncating
        # so the cap is deterministic regardless of filesystem iteration order.
        subdirs_sorted = sorted(subdirs, key=lambda p: p.name)
        subdirs_to_scan = subdirs_sorted[:MAX_SKILL_SUBDIRECTORIES]
        if len(subdirs) > MAX_SKILL_SUBDIRECTORIES:
            logger.warning(
                "skill root %s has %d subdirectories; only scanning first %d",
                root, len(subdirs), MAX_SKILL_SUBDIRECTORIES,
            )
        for sub in sorted(subdirs_to_scan, key=lambda p: p.name):
            if _budget_exhausted():
                break
            child_files: list[Path] = []
            child_scanned = 0
            child_budget_exceeded = False
            try:
                with os.scandir(sub) as children:
                    for child in children:
                        child_scanned += 1
                        global_entry_budget[0] += 1
                        if (
                            child_scanned > MAX_SKILL_DIR_ENTRIES
                            or _budget_exhausted()
                        ):
                            child_budget_exceeded = True
                            break
                        child_path = Path(child.path)
                        if child.is_file(follow_symlinks=False) and _is_skill_filename(child_path):
                            child_files.append(child_path)
            except OSError as exc:
                logger.debug("cannot scan skill subdir %s: %s", sub, exc)
                continue
            if child_budget_exceeded:
                logger.debug(
                    "skill subdir %s scan truncated (budget)", sub,
                )
            for child_path in sorted(child_files, key=lambda p: p.name):
                yield child_path


def _yaml_depth(
    node: yaml.Node,
    depth: int = 1,
    active_stack: set[int] | None = None,
    seen: set[int] | None = None,
    *,
    node_count: list[int] | None = None,
) -> int:
    """Return maximum composed YAML node depth without constructing data.

    Batch 10.6 (round-10 §十): added cycle detection + a node-count budget.

    Batch 11.7 (round-11 §十一): separated ``active_stack`` (the current
    RECURSION path — nodes added on entry, removed on exit) from ``seen``
    (all unique nodes ever visited, for the budget).  Round-10's single
    ``visited`` set never removed nodes, so a legitimate DAG with a
    shared alias (``common: &common [...]; first: *common; second: *common``)
    was falsely rejected as a cycle the second time the shared node was
    reached via a different parent.  Now only a TRUE cycle (a node still
    on the active recursion stack) is rejected; shared aliases are allowed.
    """
    if active_stack is None:
        active_stack = set()
    if seen is None:
        seen = set()
    if node_count is None:
        node_count = [0]
    node_id = id(node)
    # True cycle: the node is still on the active recursion stack.
    if node_id in active_stack:
        return MAX_SKILL_YAML_DEPTH + 1
    # Budget: count unique nodes (a shared alias visited via two parents
    # counts once for budget purposes).
    if node_id not in seen:
        seen.add(node_id)
        node_count[0] += 1
        if node_count[0] > MAX_SKILL_YAML_NODES:
            return MAX_SKILL_YAML_DEPTH + 1
    if isinstance(node, yaml.MappingNode):
        children = [item for pair in node.value for item in pair]
    elif isinstance(node, yaml.SequenceNode):
        children = list(node.value)
    else:
        children = []
    # Push onto the active stack for the recursion, then pop so a sibling
    # or cousin visiting the same alias is not falsely flagged.
    active_stack.add(node_id)
    result = max(
        [depth, *(_yaml_depth(child, depth + 1, active_stack, seen, node_count=node_count) for child in children)]
    )
    active_stack.discard(node_id)
    return result


def _is_skill_filename(path: Path) -> bool:
    name = path.name
    if name in _SKILL_FILENAMES:
        return True
    return name.endswith(_SKILL_SUFFIX) and path.parent != Path(".")
