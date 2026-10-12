"""Request bodies of the remediation API Every register field is optional and `""` means "not given";
an unknown field is refused (422), never ignored."""

import re
from datetime import UTC, date, datetime
from decimal import Decimal
from typing import Annotated, Any, ClassVar

from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    StringConstraints,
    WithJsonSchema,
    field_validator,
    model_validator,
)

from app.core.constants import Limits, Remediation, RemediationMessage, Review, YesNo
from app.models.scenarios import StartRunRequest

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
# rounded before this check (v1 read the raw digits); a register sending such scores sends them as strings.
Rating = Annotated[_Score | None, Blank, WithJsonSchema({"type": ["number", "null"], "minimum": 0})]


def _calendar_date(value: Any) -> Any:
    """A date, or the date part of a date-time AS WRITTEN: the register sends "2026-09-18T15:38:19.853", and
    the caller's 1 October stays 1 October (applying an offset first could date the window a day early)."""
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
_Comment = Annotated[Annotated[str, Field(max_length=Remediation.COMMENT_MAX_CHARS)] | None, Blank]
_ThreatName = Annotated[Annotated[str, Field(max_length=Remediation.THREAT_NAME_MAX_CHARS)] | None, Blank]
_TypeName = Annotated[Annotated[str, Field(max_length=Remediation.TYPE_NAME_MAX_CHARS)] | None, Blank]
_ScenarioId = Annotated[Annotated[str, Field(max_length=Review.MAX_ID_CHARS)] | None, Blank]


class ControlRef(BaseModel):
    """One control: its library id, code or name, or any mix. A plain string is a reference too: its text is
    the name, and also the code when it looks like one. Whether it exists is the library's question (S46)."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    control_id: Annotated[Annotated[int, Field(gt=0, le=Limits.MAX_SQL_INT)] | None, Blank] = None
    control_code: _Code = None
    control_name: _ControlText = None

    @model_validator(mode="before")
    @classmethod
    def accept_a_plain_string(cls, value: Any) -> Any:
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
        if self.control_id is None and not self.control_code and not self.control_name:
            raise ValueError(RemediationMessage.CONTROL_REF_EMPTY)
        return self

    def key(self) -> tuple[str, Any]:
        """The strongest key this entry carries (id, then code, then name; text compared case-blind): two
        entries with the same strongest key name one control."""
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


def _first_of_each(entries: list[ControlRef]) -> list[ControlRef]:
    """The register's baseline: a control listed twice covers what it covered once, so the repeat is
    dropped."""
    kept: dict[tuple[str, Any], ControlRef] = {}
    for entry in entries:
        kept.setdefault(entry.key(), entry)
    return list(kept.values())


def _each_once(entries: list[ControlRef]) -> list[ControlRef]:
    """A hand-written scenario's controls become its controls: a repeat is refused, never silently merged."""
    seen: set[tuple[str, Any]] = set()
    for entry in entries:
        if entry.key() in seen:
            raise ValueError(RemediationMessage.CONTROL_NAMED_TWICE.format(key=entry.key()[0]))
        seen.add(entry.key())
    return entries


_ControlRefs = Annotated[list[ControlRef], BeforeValidator(_drop_blank_entries)]
RegisterControls = Annotated[
    _ControlRefs, AfterValidator(_first_of_each), Field(max_length=Remediation.MAX_CONTROL_REFS)
]
ScenarioControls = Annotated[
    _ControlRefs, AfterValidator(_each_once), Field(max_length=Remediation.MAX_CONTROL_REFS)
]


class RegisterData(BaseModel):
    """The register's risk data the platform sends with a plan request (v1 TreatmentPlanBody): echoed into the
    plan, never invented by the AI; the risk owner's name never reaches the AI."""

    model_config = ConfigDict(extra="forbid")

    existing_controls: Annotated[RegisterControls | None, Blank] = None
    likelihood_rating: Rating = None
    impact_rating: Rating = None
    final_risk_rating: Rating = None  # taken as-is, never re-derived
    risk_level: _Name = None  # Critical, High, Medium, Low, or the register's own
    risk_identification_date: Annotated[datetime | None, Blank] = None
    risk_owner: _Name = None
    impacted_business_division: _Name = None
    existing_controls_all_subsystems: Annotated[YesNo | None, Blank] = None
    existing_controls_all_subsystems_justification: _Justification = None
    mitigation_start_date: CalendarDate = None
    mitigation_end_date: CalendarDate = None

    @field_validator("risk_identification_date")
    @classmethod
    def in_utc(cls, value: datetime | None) -> datetime | None:
        """An offset is applied (an instant, unlike the window's calendar dates); a naive time is taken as
        UTC."""
        if value is None:
            return None
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)

    @model_validator(mode="after")
    def check_the_window(self) -> "RegisterData":
        start, end = self.mitigation_start_date, self.mitigation_end_date
        if (start is None) != (end is None):
            raise ValueError(RemediationMessage.WINDOW_PAIR)
        if start is not None and end is not None and end < start:
            raise ValueError(RemediationMessage.WINDOW_ORDER)
        return self

    def register(self) -> dict[str, Any]:
        """The register half as stored (BLUEPRINT §12.2): ratings as exact decimal strings, dates as ISO
        text."""
        stored = self.model_dump(mode="json", include=set(RegisterData.model_fields))
        for rating in ("likelihood_rating", "impact_rating", "final_risk_rating"):
            value = getattr(self, rating)
            stored[rating] = None if value is None else str(value)
        return stored


def _has_letters(name: str | None) -> str | None:
    if name is not None and not _PUNCTUATION_OR_SPACE.sub("", name):
        raise ValueError(RemediationMessage.NAME_WITHOUT_LETTERS)
    return name


class LibraryRef(BaseModel):
    """A threat-library row named by its id, its name, or both (both must then agree: the library decides)."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    id: Annotated[Annotated[int, Field(gt=0, le=Limits.MAX_SQL_INT)] | None, Blank] = None
    name: Annotated[_ThreatName, AfterValidator(_has_letters)] = None

    @model_validator(mode="after")
    def check_it_names_a_row(self) -> "LibraryRef":
        if self.id is None and not self.name:
            raise ValueError(RemediationMessage.LIBRARY_REF_EMPTY)
        return self


class TypeRef(LibraryRef):
    """A threat type: its name fits Threat_Type.ThreatTypeName, so a proposal never fails inside SQL
    Server."""

    name: Annotated[_TypeName, AfterValidator(_has_letters)] = None


class CategoryRef(LibraryRef):
    name: Annotated[_Name, AfterValidator(_has_letters)] = None


_Statement = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=Remediation.STATEMENT_MAX_CHARS)
]


class ManualScenario(StartRunRequest):
    """A hand-written scenario (Rule R2): the asset and systems as a run start names them (the same checks),
    the threat by library row, and the two statements. It has no title (A-11): `scenario_title` is refused."""

    FIELD_PREFIX: ClassVar[str] = "body.manual_scenario"

    threat_category: CategoryRef | None = None  # none → the threat's or the type's category
    threat_type: TypeRef
    threat: LibraryRef
    threat_scenario: _Statement  # " " is not a statement: stripped, then at least one character
    risk_statement: _Statement
    mapped_controls: Annotated[ScenarioControls | None, Blank] = None  # none → mapped as a generated one


class PlanRequest(RegisterData):
    """Body of #11: a plan for one accepted generated scenario (`scenario_id`) or for a hand-written one
    (`manual_scenario`, with an Idempotency-Key), the register's data beside it."""

    scenario_id: _ScenarioId = None
    manual_scenario: ManualScenario | None = None

    @model_validator(mode="after")
    def check_one_scenario(self) -> "PlanRequest":
        if (self.scenario_id is None) == (self.manual_scenario is None):
            raise ValueError(RemediationMessage.ONE_SCENARIO)
        return self


class DecisionRequest(BaseModel):
    """Body of #12 accept and #13 reject: a version (default: the newest done one) and a comment."""

    model_config = ConfigDict(extra="forbid")

    version: Annotated[int, Field(gt=0)] | None = None
    comment: _Comment = None


class RegenerateRequest(BaseModel):
    """Body of #14: nothing (the latest version's register data is reused); any field → 422."""

    model_config = ConfigDict(extra="forbid")
