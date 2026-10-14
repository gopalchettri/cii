"""The asset and supporting-system facts of a run (owner 2026-10-11): every column dbo.tsg_GetAssetContext
returns for the asset and for each system is a fact every step uses, and nothing else is
(scripts/sql/tsg_GetAssetContext.sql). Which facts a run requires is set per environment
(ASSET_PROPERTIES_REQUIRED and SYSTEM_PROPERTIES_REQUIRED, app/core/config.py)."""

from enum import StrEnum
from typing import Final


class ContextProperties:
    #: The columns the procedure must return in its asset row and in each system row: names, cards and the
    #: IT/OT control pool need them (the ids never reach the AI). Every other column is a fact.
    HEAD: Final = ("id", "name", "category_code")
    #: The dropdown names' columns (part 5): the option's code and name, and the number its dropdown facts
    #: hold, under whichever name the procedure returns it (owner 2026-10-12: the installed procedure decides,
    #: value or id; the facts it returns hold the same number).
    OPTION_COLUMNS: Final = ("code", "name")
    OPTION_KEYS: Final = ("value", "id")
    #: Never a required fact: always there (a system's alias, SYS1..n, is the app's own).
    ALWAYS_USED: Final = (*HEAD, "alias")
    #: An asset column named entity_... describes the whole organisation (the procedure's @EntityID), not this
    #: asset: the AI gets it on a line of its own, as background (owner 2026-10-12; G208). A naming rule of
    #: the procedure, like HEAD: no column is picked by name (G206).
    ORGANISATION_PREFIX: Final = "entity_"
    #: The writer's brief keeps those facts under this one key, so it never tells them as the asset's (G208).
    ORGANISATION_BRIEF_KEY: Final = "organisation_background_not_this_asset"
    #: G232: the deployment's country (THREAT_CONTEXT_COUNTRY), a fact planning and the story writer read
    #: while external intelligence is on.
    COUNTRY_KEY: Final = "country"
    #: The request field a refusal names, for the asset facts the request (not the asset) decides.
    REQUEST_FIELDS: Final = {
        "sector": "sector_id",
        "sub_sector": "subsector_id",
        "critical_service": "service_id",
    }


class PropertyMessage(StrEnum):
    ALWAYS_USED = "{setting} names {names}: always used, so never a required fact. Remove them."
    NOT_RETURNED = (
        "{setting} names {names}, which dbo.tsg_GetAssetContext does not return: add the column to the "
        "procedure or remove the name from the setting."
    )
    HEAD_MISSING = "dbo.tsg_GetAssetContext must return {columns} in its {rows} rows; it does not."
    OPTIONS_OUT_OF_DATE = (
        "dbo.tsg_GetAssetContext's dropdown names (part 5) must return code, name and value (or id), not "
        "{found}. Fix the procedure's part 5."
    )
    RESERVED = (
        "dbo.tsg_GetAssetContext returns {columns} in its {rows} rows: reserved names, never shown to the "
        "AI. Rename them with AS (e.g. AS asset_criticality)."
    )
    REQUIRED_MISSING = "Required properties are not recorded: {gaps}."
    NOT_RECORDED = "{owner}: {names} not recorded."
