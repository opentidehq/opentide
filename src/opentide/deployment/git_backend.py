"""Packaged git operations via Dulwich (no system git binary required)."""

from __future__ import annotations

import importlib
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from dulwich import porcelain
from dulwich.diff_tree import CHANGE_ADD, CHANGE_MODIFY, CHANGE_RENAME, tree_changes
from dulwich.objects import Commit, ObjectID
from dulwich.refs import Ref
from dulwich.repo import Repo
from dulwich.walk import Walker


class GitLookupError(KeyError):
    """A ref or object the checkout does not hold, said in a sentence.

    Dulwich raises a bare ``KeyError(b"HEAD")``, whose ``str()`` is the key's
    repr, and a caller reporting ``str(exc)`` printed ``b'HEAD'``. It is still
    a :class:`KeyError`, so ``except KeyError`` keeps catching it.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message

    def __str__(self) -> str:
        return self.message


class NoCommitsError(GitLookupError):
    """``HEAD`` names a branch that has no commit yet, as right after ``git init``."""

    def __init__(self, path: Path) -> None:
        self.path = path
        super().__init__(f"The git repository at {path} has no commits yet")


def key_text(exc: KeyError) -> str:
    """The ref or object id a Dulwich ``KeyError`` names, as text."""
    key = exc.args[0] if exc.args else ""
    if isinstance(key, bytes):
        return key.decode("utf-8", errors="replace")
    return str(key)


def rust_extensions_available() -> bool:
    """Return True when Dulwich Rust acceleration modules are importable."""
    try:
        # The compiled module is optional and has no stub to resolve statically.
        importlib.import_module("dulwich._diff_tree")
    except ImportError:
        return False
    return True


def open_repo(path: str | Path) -> DulwichRepo:
    """Open a Dulwich repository at *path*."""
    return DulwichRepo(path)


def _object_hex(sha: bytes) -> str:
    return sha.decode("ascii")


def _parse_author_name(author: bytes | str) -> str:
    text = author.decode("utf-8", errors="replace") if isinstance(author, bytes) else author
    if "<" in text:
        return text.split("<", 1)[0].strip()
    return text.strip()


def _normalize_ref(ref: str) -> bytes:
    if ref.startswith("refs/"):
        return ref.encode("utf-8")
    if ref.startswith("origin/"):
        return f"refs/remotes/{ref}".encode()
    if ref == "HEAD":
        return b"HEAD"
    return f"refs/heads/{ref}".encode()


@dataclass(frozen=True)
class Author:
    name: str


@dataclass
class CommitInfo:
    hexsha: str
    message: str
    author: Author
    parents: list[CommitInfo]
    _tree: ObjectID
    _store: Repo

    @classmethod
    def from_commit(cls, commit: Commit, store: Repo) -> CommitInfo:
        # One level only. Recursing through every ancestor overflows the
        # Python stack once history is deeper than the recursion limit, and
        # ``repo.commit()`` / ``repo.head`` then abort the deploy.
        parents = [cls._immediate_parent(parent_id, store) for parent_id in commit.parents]
        message = commit.message
        if isinstance(message, bytes):
            message = message.decode("utf-8", errors="replace")
        return cls(
            hexsha=_object_hex(commit.id),
            message=str(message).strip(),
            author=Author(name=_parse_author_name(commit.author)),
            parents=parents,
            _tree=commit.tree,
            _store=store,
        )

    @classmethod
    def _immediate_parent(cls, parent_id: ObjectID, store: Repo) -> CommitInfo:
        """Parent id, message, and tree, without that parent's own parents.

        A shallow clone names the parent and does not contain its object.
        The id is still recorded so callers can say which commit is missing.
        """
        try:
            loaded = store[parent_id]
        except KeyError:
            loaded = None
        if isinstance(loaded, Commit):
            message = loaded.message
            if isinstance(message, bytes):
                message = message.decode("utf-8", errors="replace")
            text = str(message).strip()
            author = _parse_author_name(loaded.author)
            tree = loaded.tree
        else:
            text = ""
            author = ""
            tree = ObjectID(b"")
        return cls(
            hexsha=_object_hex(parent_id),
            message=text,
            author=Author(name=author),
            parents=[],
            _tree=tree,
            _store=store,
        )

    def diff(self, other: CommitInfo) -> DiffIndex:
        return tree_diff(self._store, self, other)


@dataclass(frozen=True)
class DiffEntry:
    change_type: str
    b_path: str | None


class DiffIndex:
    def __init__(self, entries: list[DiffEntry]) -> None:
        self._entries = entries

    def iter_change_type(self, change_type: str) -> Iterator[DiffEntry]:
        mapping = {"A": CHANGE_ADD, "M": CHANGE_MODIFY, "R": CHANGE_RENAME}
        wanted = mapping[change_type]
        for entry in self._entries:
            if entry.change_type == wanted:
                yield entry

    def __iter__(self) -> Iterator[DiffEntry]:
        return iter(self._entries)


class _OriginRemote:
    def __init__(self, repo: DulwichRepo) -> None:
        self._repo = repo

    def fetch(self) -> None:
        # ``porcelain.fetch`` with no remote asks for the active branch. A
        # pull-request checkout is detached, and Dulwich then indexes
        # ``follow(HEAD)[0][1]`` which is only ``[HEAD]`` — ``IndexError:
        # list index out of range`` (#402, #415). Name origin explicitly.
        porcelain.fetch(self._repo._repo, remote_location=b"origin", quiet=True)


@dataclass(frozen=True)
class _RemoteRef:
    name: str


class _RemoteCollection:
    def __init__(self, repo: DulwichRepo) -> None:
        self._repo = repo
        self.origin = _OriginRemote(repo)

    @property
    def refs(self) -> list[_RemoteRef]:
        return [
            _RemoteRef(name.decode("utf-8", errors="replace")) for name in self._repo._repo.refs
        ]


def tree_diff(store: Repo, base: CommitInfo, head: CommitInfo) -> DiffIndex:
    try:
        changes = list(tree_changes(store.object_store, base._tree, head._tree))
    except KeyError as exc:
        # A tree or blob a shallow or partial clone does not hold.
        raise GitLookupError(f"Could not find git object {key_text(exc)}") from None
    entries: list[DiffEntry] = []
    for change in changes:
        if change.type not in (CHANGE_ADD, CHANGE_MODIFY, CHANGE_RENAME):
            continue
        path = None
        if change.new and change.new.path:
            path = change.new.path.decode("utf-8", errors="replace")
        elif change.old and change.old.path:
            path = change.old.path.decode("utf-8", errors="replace")
        entries.append(DiffEntry(change_type=change.type, b_path=path))
    return DiffIndex(entries)


class DulwichRepo:
    """GitPython-shaped adapter over a Dulwich :class:`Repo`."""

    def __init__(self, path: str | Path) -> None:
        repo_path = str(path)
        self._repo = Repo(repo_path)
        self.path = Path(repo_path)
        self.remotes = type("Remotes", (), {"origin": _OriginRemote(self)})()

    @property
    def working_dir(self) -> str:
        return str(self.path)

    def _head_sha(self) -> ObjectID:
        """The commit ``HEAD`` names; :class:`NoCommitsError` when there is none yet."""
        try:
            return self._repo.head()
        except KeyError:
            raise NoCommitsError(self.path) from None

    @property
    def has_commits(self) -> bool:
        """Whether ``HEAD`` names a commit. ``False`` right after ``git init``."""
        try:
            self._head_sha()
        except NoCommitsError:
            return False
        return True

    @property
    def head(self) -> CommitInfo:
        return self.commit(_object_hex(self._head_sha()))

    def commit(self, sha: str | CommitInfo) -> CommitInfo:
        if isinstance(sha, CommitInfo):
            return sha
        try:
            commit = self._repo[sha.encode("ascii")]
        except KeyError:
            raise Exception(f"Could not find git commit {sha}") from None
        if not isinstance(commit, Commit):
            raise TypeError(f"Object {sha} is not a commit")
        return CommitInfo.from_commit(commit, self._repo)

    def _resolve_sha(self, ref: str) -> ObjectID:
        ref_bytes = _normalize_ref(ref)
        if ref_bytes == b"HEAD":
            return self._head_sha()
        candidates = [ref_bytes]
        raw = ref.encode("utf-8")
        if raw != ref_bytes:
            candidates.append(raw)
        for candidate in candidates:
            try:
                return self._repo.refs[Ref(candidate)]
            except KeyError:
                continue
        raise GitLookupError(f"Could not find git ref {ref}")

    def iter_commits(
        self, ref: str | None = None, max_count: int | None = None
    ) -> Iterator[CommitInfo]:
        start = [self._resolve_sha(ref)] if ref is not None else [self._head_sha()]
        walker = Walker(self._repo.object_store, start, max_entries=max_count)
        try:
            for entry in walker:
                yield CommitInfo.from_commit(entry.commit, self._repo)
        except KeyError as exc:
            missing = exc.args[0] if exc.args else None
            if not isinstance(missing, bytes):
                raise

    def merge_base(self, *refs: str) -> list[CommitInfo]:
        try:
            shas = porcelain.merge_base(self._repo, list(refs))
        except KeyError as exc:
            raise GitLookupError(f"Could not find git commit {key_text(exc)}") from None
        return [self.commit(_object_hex(sha)) for sha in shas]

    def remote(self) -> _RemoteCollection:
        return _RemoteCollection(self)
