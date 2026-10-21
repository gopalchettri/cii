"""Request bodies of the remediation API: a plan request with its register data, a review and a regenerate."""

import re
from dataclasses import dataclass
from datetime import UTC, date, datetime
from decimal import Decimal
from typing import Annotated, Any, ClassVar, Literal

from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    JsonValue,
    StrictInt,
    StringConstraints,
    WithJsonSchema,
    field_validator,
    model_validator,
)

from app.core.constants import Decision, Limits, Remediation, RemediationMessage, Review, YesNo
from app.models.scenario.views import SqlId, StartRunRequest

#: What a library control code looks like ("CII-CID-202"): groups joined by separators, with a digit. It only
#: routes a plain string; nothing is refused for failing it.
_CODE_SHAPE = re.compile(r"[A-Za-z0-9]+(?:[-_./][A-Za-z0-9]+)+")
_PUNCTUATION_OR_SPACE = re.compile(r"[\W_]+")


def _blank_is_absent(value: Any) -> Any:
    """`""` means "not given", never a failure: the platform's form sends it for an empty field."""
    return None if isinstance(value, str) and not value.strip() else value


Blank = BeforeValidator(_blank_is_absent)
_Score = Annotated[
    Decimal,
    Field(ge=0, max_digits=Remediation.RATING_MAX_DIGITS, decimal_places=Remediation.RATING_DECIMALS),
]
#: A register score: exact (a decimal, never a float), 0 or more, at most 15 digits, 4 after the point.
# ponytail: a JSON number arrives as a float, so a score written with more than 15 significant digits may be
# rounded before this check; a register sending such scores sends them as strings.
Rating = Annotated[_Score | None, Blank, WithJsonSchema({"type": ["number", "null"], "minimum": 0})]


def _calendar_date(value: Any) -> Any:
    """A date, or the date part of a date-time as written (no offset applied, so the day never shifts)."""
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.strip()).date()
        except ValueError:
            return value  # pydantic answers with its own date error
    return value


CalendarDate = Annotated[date | None, Blank, BeforeValidator(_calendar_date)]


#: Optional text fields: blank means not given; longer than the limit → 422.
_Code = Annotated[Annotated[str, Field(max_length=Remediation.CONTROL_CODE_MAX_CHARS)] | None, Blank]
_ControlText = Annotated[Annotated[str, Field(max_length=Remediation.CONTROL_TEXT_MAX_CHARS)] | None, Blank]
_Name = Annotated[Annotated[str, Field(max_length=Remediation.NAME_MAX_CHARS)] | None, Blank]
_Justification = Annotated[
    Annotated[str, Field(max_length=Remediation.JUSTIFICATION_MAX_CHARS)] | None, Blank
]
_ThreatName = Annotated[Annotated[str, Field(max_length=Remediation.THREAT_NAME_MAX_CHARS)] | None, Blank]
_TypeName = Annotated[Annotated[str, Field(max_length=Remediation.TYPE_NAME_MAX_CHARS)] | None, Blank]
_RecordId = Annotated[Annotated[str, Field(max_length=Review.MAX_ID_CHARS)] | None, Blank]
_Comment = Annotated[Annotated[str, Field(max_length=Remediation.COMMENT_MAX_CHARS)] | None, Blank]
#: A library row's id: blank means not given.
_LibraryId = Annotated[Annotated[int, Field(gt=0, le=Limits.MAX_SQL_INT)] | None, Blank]
#: A register flag, 1 yes or 0 no, as a JSON integer: true, "1" and 1.0 are refused (422).
_Flag = Annotated[StrictInt, Field(ge=0, le=1)]


class ControlRef(BaseModel):
    """One control: its library id, code or name, or any mix. A plain string is a reference too: its text is
    the name, and also the code when it looks like one. Whether it exists is the library's question (S46)."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    control_id: _LibraryId = None
    control_code: _Code = None
    control_name: _ControlText = None

    @model_validator(mode="before")
    @classmethod
    def accept_a_plain_string(cls, value: Any) -> Any:
        """A plain string becomes a reference: the name, and the code when it looks like one."""
        if not isinstance(value, str):
            return value
        text = value.strip()
        looks_like_a_code = (
            len(text) <= Remediation.CONTROL_CODE_MAX_CHARS
            and _CODE_SHAPE.fullmatch(text) is not None
            and any(character.isdigit() for character in text)
        )
        return {"control_code": text if looks_like_a_code else None, "control_name": text}

    @model_validator(mode="after")
    def check_it_names_a_control(self) -> "ControlRef":
        """An entry that names no control is refused."""
        if self.control_id is None and not self.control_code and not self.control_name:
            raise ValueError(RemediationMessage.CONTROL_REF_EMPTY)
        return self

    def key(self) -> tuple[str, Any]:
        """The strongest key it carries (id, code, then case-blind name): one key names one control."""
        if self.control_id is not None:
            return "control_id", self.control_id
        if self.control_code:
            return "control_code", self.control_code.casefold()
        return "control_name", (self.control_name or "").casefold()


def _drop_blank_entries(entries: Any) -> Any:
    """`["", ""]` from an empty form means no control; an object that names nothing is still refused."""
    if not isinstance(entries, list):
        return entries
    return [entry for entry in entries if _blank_is_absent(entry) is not None]


class RegisterControlRef(ControlRef):
    """An existing control in the register: the control, and the supporting systems it is on (required when
    existing_controls_all_supporting_system_applicable is 0)."""

    supporting_system_ids: Annotated[list[SqlId] | None, Blank] = None


def _first_of_each(entries: list[RegisterControlRef]) -> list[RegisterControlRef]:
    """A control listed twice is one control: the first entry kept, with every system either one names."""
    kept: dict[tuple[str, Any], RegisterControlRef] = {}
    for entry in entries:
        first = kept.setdefault(entry.key(), entry)
        if first is not entry and entry.supporting_system_ids:
            merged = dict.fromkeys([*(first.supporting_system_ids or []), *entry.supporting_system_ids])
            kept[entry.key()] = first.model_copy(update={"supporting_system_ids": list(merged)})
    return list(kept.values())


RegisterControls = Annotated[
    list[RegisterControlRef],
    BeforeValidator(_drop_blank_entries),
    AfterValidator(_first_of_each),
    Field(max_length=Remediation.MAX_CONTROL_REFS),
]
#: Repeats kept, so a 422 names the entry's place in the request; resolving them keeps each library row once.
ScenarioControls = Annotated[
    list[ControlRef], BeforeValidator(_drop_blank_entries), Field(max_length=Remediation.MAX_CONTROL_REFS)
]


def _has_letters(name: str | None) -> str | None:
    """A name made of punctuation or spaces alone is refused."""
    if name is not None and not _PUNCTUATION_OR_SPACE.sub("", name):
        raise ValueError(RemediationMessage.NAME_WITHOUT_LETTERS)
    return name


@dataclass(frozen=True)
class LibraryRef:
    """A library category, type or threat as a hand-written scenario names it (id, name or both)."""

    id: int | None
    name: str | None


#: A library row's name: blank means not given; punctuation or spaces alone → 422 (never a nameless row).
_CategoryName = Annotated[_Name, AfterValidator(_has_letters)]
_TypeNameText = Annotated[_TypeName, AfterValidator(_has_letters)]
_ThreatNameText = Annotated[_ThreatName, AfterValidator(_has_letters)]


_Statement = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=Remediation.STATEMENT_MAX_CHARS)
]


class ManualScenario(StartRunRequest):
    """A hand-written scenario (Rule R2), v1's `manual_scenario` (owner, 2026-10-15): the asset and systems as
    a run start names them (the same checks), the entity, the threat by library row in v1's six flat fields,
    and the two statements. The type and the threat are each named by id, name or both; the category is
    optional (else the threat's, else the type's). It has no title (A-11): `scenario_title` is refused."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, str_strip_whitespace=True)
    FIELD_PREFIX: ClassVar[str] = "body.manual_scenario"

    entity_id: SqlId = Field(description="The caller's entity, as v1 sends it: must equal X-Entity-Id (403).")
    threat_category_id: _LibraryId = None
    threat_category_name: _CategoryName = None
    threat_type_id: _LibraryId = None
    threat_type_name: _TypeNameText = None
    threat_id: _LibraryId = None
    threat_name: _ThreatNameText = None
    threat_scenario: _Statement  # " " is not a statement: stripped, then at least one character
    risk_statement: _Statement
    mapped_controls: Annotated[ScenarioControls | None, Blank] = None  # none → mapped as a generated one

    @model_validator(mode="after")
    def check_the_threat_is_named(self) -> "ManualScenario":
        """The type and the threat are each named by id or name."""
        if self.threat_type_id is None and not self.threat_type_name:
            raise ValueError(RemediationMessage.THREAT_TYPE_REQUIRED)
        if self.threat_id is None and not self.threat_name:
            raise ValueError(RemediationMessage.THREAT_REQUIRED)
        return self

    @property
    def threat_category(self) -> LibraryRef | None:
        """The category as named, or None when it is not named."""
        if self.threat_category_id is None and not self.threat_category_name:
            return None
        return LibraryRef(self.threat_category_id, self.threat_category_name)

    @property
    def threat_type(self) -> LibraryRef:
        """The threat type as named."""
        return LibraryRef(self.threat_type_id, self.threat_type_name)

    @property
    def threat(self) -> LibraryRef:
        """The threat as named."""
        return LibraryRef(self.threat_id, self.threat_name)


#: The register's data, as the platform sends it with either kind.
_REGISTER_EXAMPLE: dict[str, Any] = {
    "all_supporting_systems_applicable": 1,
    "existing_controls_all_supporting_system_applicable": 1,
    "existing_controls": [{"control_code": "CII-CID-202"}, "User Awareness"],
    "likelihood_rating": 4,
    "impact_rating": 5,
    "final_risk_rating": 20,
    "risk_level": "Critical",
    "risk_identification_date": "2026-09-15T09:30:00Z",
    "risk_owner": "Head of OT Operations",
    "impacted_business_division": "Power Generation Operations",
    "existing_controls_all_subsystems_justification": "Controls are deployed on corporate IT systems only.",
    "mitigation_start_date": "2026-10-01",
    "mitigation_end_date": "2026-12-31",
}
#: With existing_controls_all_supporting_system_applicable 0, each existing control names its systems.
_REGISTER_BY_SYSTEM_EXAMPLE: dict[str, Any] = _REGISTER_EXAMPLE | {
    "all_supporting_systems_applicable": 0,
    "existing_controls_all_supporting_system_applicable": 0,
    "existing_controls": [
        {"control_code": "CII-CID-202", "supporting_system_ids": [2301]},
        {"control_name": "User Awareness", "supporting_system_ids": [2301, 2302]},
    ],
}

#: The two published bodies of `POST /v1/remediation` (Swagger's example picker), one per kind of scenario.
PLAN_REQUEST_EXAMPLES: list[JsonValue] = [
    # A generated scenario: the run's id and the accepted scenario's id (from GET /v1/sessions/{id}/results).
    {
        "is_manual": False,
        "session_id": "<session_id>",
        "scenario_id": "<accepted scenario_id>",
        **_REGISTER_EXAMPLE,
    },
    # A hand-written scenario (send an Idempotency-Key header with it): TSG saves it, accepts it and plans it.
    {
        "is_manual": True,
        "manual_scenario": {
            "asset_id": 1166,
            "entity_id": 1,
            "supporting_system_id": [2301, 2302],
            "threat_category_name": "Tampering",
            "threat_type_name": "Malware/Ransomware",
            "threat_name": "Ransomware encrypts the historian server",
            "threat_scenario": "An attacker phishes an engineer, moves to the historian and encrypts it.",
            "risk_statement": "Operators lose process history and plant reporting stops for days.",
            "mapped_controls": [{"control_code": "CII-CID-213"}],
        },
        **_REGISTER_BY_SYSTEM_EXAMPLE,
    },
]
#: The request fields that name the scenario; every other PlanRequest field is the register's.
_SCENARIO_FIELDS = {"is_manual", "session_id", "scenario_id", "manual_scenario"}


class PlanRequest(BaseModel):
    """Body of `POST /v1/remediation`: v1's ONE request for both kinds of scenario (owner, 2026-10-15), each
    kind sending its own half (mixing them is a 422), and the register's data."""

    model_config = ConfigDict(extra="forbid", json_schema_extra={"examples": PLAN_REQUEST_EXAMPLES})

    all_supporting_systems_applicable: _Flag = Field(
        description="1: the risk applies to all supporting systems; 0: only to the scenario's own systems."
    )
    existing_controls_all_supporting_system_applicable: _Flag = Field(
        description="1: the existing controls are on all supporting systems; 0: each existing control lists "
        "the supporting systems it is on (supporting_system_ids)."
    )
    existing_controls: Annotated[RegisterControls | None, Blank] = None
    likelihood_rating: Rating = None
    impact_rating: Rating = None
    final_risk_rating: Rating = None  # taken as-is, never re-derived
    risk_level: _Name = None  # Critical, High, Medium, Low, or the register's own
    risk_identification_date: Annotated[datetime | None, Blank] = None
    risk_owner: _Name = None
    impacted_business_division: _Name = None
    existing_controls_all_subsystems: Annotated[YesNo | None, Blank] = Field(
        None,
        description="Kept for older callers and not used: existing_controls_all_supporting_system_applicable "
        "decides.",
    )
    existing_controls_all_subsystems_justification: _Justification = None
    mitigation_start_date: CalendarDate = None
    mitigation_end_date: CalendarDate = None
    is_manual: bool = Field(
        description="false: the scenario already exists in TSG (send session_id + scenario_id). true: a "
        "person wrote it (send manual_scenario and an Idempotency-Key header); TSG saves it and plans it."
    )
    session_id: _RecordId = Field(None, description="is_manual=false only: the run that holds the scenario.")
    scenario_id: _RecordId = Field(None, description="is_manual=false only: the accepted scenario to plan.")
    manual_scenario: ManualScenario | None = Field(
        None, description="is_manual=true only: the scenario a person wrote."
    )

    @field_validator("risk_identification_date")
    @classmethod
    def in_utc(cls, value: datetime | None) -> datetime | None:
        """An offset is applied (an instant, unlike the window's dates); a naive time is taken as UTC."""
        if value is None:
            return None
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)

    @model_validator(mode="after")
    def check_the_window(self) -> "PlanRequest":
        """The mitigation window's two dates come together, in order."""
        start, end = self.mitigation_start_date, self.mitigation_end_date
        if (start is None) != (end is None):
            raise ValueError(RemediationMessage.WINDOW_PAIR)
        if start is not None and end is not None and end < start:
            raise ValueError(RemediationMessage.WINDOW_ORDER)
        return self

    @model_validator(mode="after")
    def check_one_kind(self) -> "PlanRequest":
        """Each kind sends its own half and never the other's."""
        if self.is_manual:
            if self.manual_scenario is None:
                raise ValueError(RemediationMessage.MANUAL_NEEDS_SCENARIO)
            if self.session_id is not None or self.scenario_id is not None:
                raise ValueError(RemediationMessage.MANUAL_SENDS_NO_IDS)
        else:
            if self.session_id is None or self.scenario_id is None:
                raise ValueError(RemediationMessage.GENERATED_NEEDS_IDS)
            if self.manual_scenario is not None:
                raise ValueError(RemediationMessage.GENERATED_SENDS_NO_SCENARIO)
        return self

    @model_validator(mode="after")
    def check_existing_control_systems(self) -> "PlanRequest":
        """Existing controls not on all supporting systems each say which systems they are on."""
        if self.existing_controls_all_supporting_system_applicable == 0:
            for position, ref in enumerate(self.existing_controls or []):
                if not ref.supporting_system_ids:
                    control = ref.control_code or ref.control_name or f"control_id {ref.control_id}"
                    raise ValueError(
                        RemediationMessage.SYSTEMS_REQUIRED.format(position=position, control=control)
                    )
        return self

    def register(self) -> dict[str, Any]:
        """The register half as stored: ratings as exact decimal strings, dates as ISO text."""
        stored = self.model_dump(mode="json", exclude=_SCENARIO_FIELDS)
        for rating in ("likelihood_rating", "impact_rating", "final_risk_rating"):
            value = getattr(self, rating)
            stored[rating] = None if value is None else str(value)
        return stored


class ReviewRequest(BaseModel):
    """v1's one review call (owner, 2026-10-15): accept or reject a version."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={"examples": [{"decision": "accepted"}, {"decision": "rejected", "version": 2}]},
    )

    version: Annotated[int, Field(gt=0)] | None = Field(
        None, description="The version to decide; leave it out for the newest finished one."
    )
    comment: _Comment = Field(None, description="Why (stored with the decision; up to 2,000 characters).")
    decision: Literal[Decision.ACCEPTED, Decision.REJECTED] = Field(
        description="accepted or rejected. Accepting a version makes it THE plan: an earlier accepted "
        "version goes back to pending."
    )


class RegenerateRequest(BaseModel):
    """Nothing: the latest version's register data is reused; any field → 422."""

    model_config = ConfigDict(extra="forbid", json_schema_extra={"examples": [{}]})
