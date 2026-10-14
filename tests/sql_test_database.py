"""The SQL test database (BLUEPRINT R-11): built fresh from tests/sql/schema.sql, tests/sql/seed.sql and
every procedure file in scripts/sql/ (procedure_files), on the server CII_DB_DSN names but under a database
of its own. The write procedures are tested here, never in DevTest5, whose library the laptop's TSG (and v1)
read."""

import re
from pathlib import Path

from sqlalchemy import Engine, create_engine
from sqlalchemy.engine import make_url

from app.core.config import get_settings
from tests.checkout import CHECKOUT, REPO

SQL_TEST_DATABASE = f"cii_tsg_sql_test_{CHECKOUT}"  # one per checkout: never another's
_BATCH_SEPARATOR = re.compile(r"^\s*GO\s*$", re.IGNORECASE | re.MULTILINE)
#: A procedure file is tsg_<Name>.sql, the name a plain identifier. Anything else beside it ("tsg_X copy.sql",
#: kept by the owner as a backup, 2026-10-13) is never installed or granted (G217).
PROCEDURE_FILE = re.compile(r"tsg_[A-Za-z0-9_]+")


def procedure_files(folder: Path = REPO / "scripts" / "sql") -> list[Path]:
    """The procedure files of `folder`, in name order: tsg_<Name>.sql only, never a backup copy."""
    return sorted(path for path in folder.glob("tsg_*.sql") if PROCEDURE_FILE.fullmatch(path.stem))


def build_sql_test_database() -> Engine:
    """Drops the test database if it exists, creates it, and runs the schema, the seed and every tsg_
    procedure into it. Returns an engine on it (autocommit: each procedure owns its transaction, as in the
    app)."""
    server = make_url(get_settings().db_dsn)
    master = create_engine(server.set(database="master"), isolation_level="AUTOCOMMIT")
    with master.connect() as connection:
        connection.exec_driver_sql(
            f"IF DB_ID(N'{SQL_TEST_DATABASE}') IS NOT NULL BEGIN "
            f"ALTER DATABASE [{SQL_TEST_DATABASE}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; "
            f"DROP DATABASE [{SQL_TEST_DATABASE}]; END"
        )
        connection.exec_driver_sql(f"CREATE DATABASE [{SQL_TEST_DATABASE}]")
    master.dispose()
    engine = create_engine(server.set(database=SQL_TEST_DATABASE), isolation_level="AUTOCOMMIT")
    scripts = [
        REPO / "tests" / "sql" / "schema.sql",
        REPO / "tests" / "sql" / "seed.sql",
        *procedure_files(),
    ]
    with engine.connect() as connection:
        for script in scripts:
            for batch in _BATCH_SEPARATOR.split(script.read_text(encoding="utf-8")):
                if batch.strip():
                    connection.exec_driver_sql(batch)
    return engine
