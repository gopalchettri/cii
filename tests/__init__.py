"""The tests package: importing any test module, with or without pytest's run, sets the test databases first."""

import tests.conftest  # noqa: F401  # its environment: never the live MongoDB database or Redis databases
