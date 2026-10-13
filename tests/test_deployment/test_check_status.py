"""`check_status()` maps a status NAME to the strategy it carries.

The `str` branch returned `StatusStrategy[status.name]` -- indexing the enum by
the status *name* (`DESIGN`, `PRODUCTION`) instead of its *strategy* (`INERT`,
`RELEASE`). No status name is a `StatusStrategy` member, so that branch could
only raise `KeyError`, never return, against a signature promising a
`StatusStrategy`.

It was unreachable in practice: `DeploymentStatus.__post_init__` coerces the
string to the enum when the loader builds a status, so only a status
constructed outside that path could reach it. The INERT/LIVE methodology was
therefore correct in production -- this closes a latent trap and replaces two
bare `raise Exception` fallthroughs with typed, message-bearing errors.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from opentide.deployment.utils import check_status
from opentide.models.deployment_enums import StatusStrategy
from opentide.models.system_config import DeploymentStatus


@dataclass
class _RawStatus:
    """A status whose strategy is still a string.

    What `DeploymentStatus` looks like before `__post_init__` coerces it, and
    what a caller building a status by hand produces.
    """

    name: str
    description: str
    strategy: object


@pytest.fixture
def statuses(monkeypatch: pytest.MonkeyPatch):
    """Install a list of statuses as the deployment configuration."""

    def _install(items: list[object]) -> None:
        class _Deployment:
            statuses = items

        class _Configurations:
            Deployment = _Deployment()

        class _OpenTide:
            Configurations = _Configurations()

        monkeypatch.setattr("opentide.deployment.utils.OpenTide", _OpenTide())

    return _install


class TestTheLivePath:
    """What the loader actually produces, via `__post_init__`."""

    @pytest.mark.parametrize(
        ("status_name", "expected"),
        [
            ("DESIGN", StatusStrategy.INERT),
            ("STAGING", StatusStrategy.PREVIEW),
            ("PRODUCTION", StatusStrategy.RELEASE),
            ("DISABLED", StatusStrategy.DISABLEMENT),
            ("REMOVED", StatusStrategy.DELETION),
        ],
    )
    def test_a_coerced_status_resolves(
        self, status_name: str, expected: StatusStrategy, statuses
    ) -> None:
        built = DeploymentStatus(name=status_name, description="x", strategy=expected.name)
        # The loader's coercion is what makes this the live branch.
        assert isinstance(built.strategy, StatusStrategy)
        statuses([built])
        assert check_status(status_name) is expected


class TestTheStringBranch:
    """The branch that previously could only raise."""

    def test_a_string_strategy_resolves_to_that_strategy(self, statuses) -> None:
        statuses([_RawStatus(name="DESIGN", description="x", strategy="INERT")])
        assert check_status("DESIGN") is StatusStrategy.INERT

    def test_it_does_not_resolve_by_status_name(self, statuses) -> None:
        # The bug: `StatusStrategy[status.name]` would look up 'PRODUCTION',
        # which is not a member, and raise. The strategy is what counts.
        statuses([_RawStatus(name="PRODUCTION", description="x", strategy="RELEASE")])
        assert check_status("PRODUCTION") is StatusStrategy.RELEASE

    @pytest.mark.parametrize(
        "status_name", ["DESIGN", "DEVELOPMENT", "STAGING", "PRODUCTION", "DISABLED", "REMOVED"]
    )
    def test_no_status_name_is_a_strategy_member(self, status_name: str) -> None:
        # Why the old branch could never return: the two vocabularies are
        # disjoint by design.
        assert status_name not in StatusStrategy.__members__

    def test_an_unknown_strategy_raises_a_named_error(self, statuses) -> None:
        statuses([_RawStatus(name="DESIGN", description="x", strategy="NONSENSE")])
        with pytest.raises(ValueError, match="unknown strategy 'NONSENSE'") as caught:
            check_status("DESIGN")
        # The message must name the supported set, not just fail.
        assert "INERT" in str(caught.value)


class TestFallthroughsAreTyped:
    """Both bare `raise Exception` paths now say what went wrong."""

    def test_an_unknown_status_names_what_is_available(self, statuses) -> None:
        statuses([DeploymentStatus(name="DESIGN", description="x", strategy="INERT")])
        with pytest.raises(KeyError, match="MISSING") as caught:
            check_status("MISSING")
        assert "DESIGN" in str(caught.value)

    def test_an_unsupported_strategy_type_raises_type_error(self, statuses) -> None:
        statuses([_RawStatus(name="DESIGN", description="x", strategy=object())])
        with pytest.raises(TypeError, match="unsupported type"):
            check_status("DESIGN")

    def test_no_bare_exception_remains(self) -> None:
        import inspect

        source = inspect.getsource(check_status)
        assert "raise Exception" not in source
