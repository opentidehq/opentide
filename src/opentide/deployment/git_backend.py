"""Packaged git operations via Dulwich (no system git binary required)."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from dulwich import porcelain
from dulwich.diff_tree import CHANGE_ADD, CHANGE_MODIFY, CHANGE_RENAME, tree_changes
from dulwich.objects import Commit
from dulwich.repo import Repo
from dulwich.walk import Walker


def rust_extensions_available() -> bool:
    """Return True when Dulwich Rust acceleration modules are importable."""
    try:
        import dulwich._diff_tree  # noqa: F401
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
        return f"refs/remotes/{ref}".encode("utf-8")
    if ref == "HEAD":
        return b"HEAD"
    return f"refs/heads/{ref}".encode("utf-8")


@dataclass(frozen=True)
class Author:
    name: str


@dataclass
class CommitInfo:
    hexsha: str
    message: str
    author: Author
    parents: list[CommitInfo]
    _tree: bytes
    _store: Repo

    @classmethod
    def from_commit(cls, commit: Commit, store: Repo) -> CommitInfo:
        parents = [cls.from_commit(store[parent], store) for parent in commit.parents]
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
        porcelain.fetch(self._repo._repo, quiet=True)


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
            _RemoteRef(name.decode("utf-8", errors="replace"))
            for name in self._repo._repo.refs.keys()
        ]


def tree_diff(store: Repo, base: CommitInfo, head: CommitInfo) -> DiffIndex:
    entries: list[DiffEntry] = []
    for change in tree_changes(store.object_store, base._tree, head._tree):
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

    @property
    def head(self) -> CommitInfo:
        return self.commit(_object_hex(self._repo.head()))

    def commit(self, sha: str | CommitInfo) -> CommitInfo:
        if isinstance(sha, CommitInfo):
            return sha
        commit = self._repo[sha.encode("ascii")]
        if not isinstance(commit, Commit):
            raise TypeError(f"Object {sha} is not a commit")
        return CommitInfo.from_commit(commit, self._repo)

    def _resolve_sha(self, ref: str) -> bytes:
        ref_bytes = _normalize_ref(ref)
        if ref_bytes == b"HEAD":
            return self._repo.head()
        try:
            return self._repo.lookup_ref(ref_bytes)
        except KeyError:
            return self._repo.lookup_ref(ref.encode("utf-8"))

    def iter_commits(self, ref: str | None = None, max_count: int | None = None) -> Iterator[CommitInfo]:
        start = [self._resolve_sha(ref)] if ref is not None else [self._repo.head()]
        kwargs: dict[str, int] = {}
        if max_count is not None:
            kwargs["max_entries"] = max_count
        for entry in Walker(self._repo, start, **kwargs):
            yield CommitInfo.from_commit(self._repo[entry.commit.id], self._repo)

    def merge_base(self, *refs: str) -> list[CommitInfo]:
        shas = porcelain.merge_base(self._repo, list(refs))
        return [self.commit(_object_hex(sha)) for sha in shas]

    def remote(self) -> _RemoteCollection:
        return _RemoteCollection(self)
