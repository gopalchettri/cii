# SDE: mitre-pipeline (22 Nov 2026, ADR-011)

## Built
- **`GET /v1/mitre_sessions/{id}/results`:** the same page as `/v1/sessions/{id}/results`, 404 for a run that
  is not a MITRE run.
- **Actor slices:** the new setting `MITRE_ACTOR_SLICE_TOKENS_LIMIT` is in every env file, `deploy/configmap.yaml`
  and `tests/conftest.py`. The actor answer room is 8192.
- **Further round** (`worker/scenario/mitre/mitre_tasks.py`):
  - `read_open_paths_planning_more_when_short` asks before writing when the open paths are fewer than the set's goal;
  - `plan_more_when_none_left` asks at the end only when nothing is left open.
- **Writer repairs** (`mitre_engine.py`):
  - `check_written_techniques` and `check_written_groups` return what they left out;
  - `check_written_mitre_facts` combines them;
  - `text_naming_dropped_items` keeps the re-ask when the text names a left-out item.
  - A repair logs `mitre.writer_answer_repaired`.
  - The constants `TOO_MANY_GROUPS` and `GROUP_LISTED_TWICE` were removed and `DROPPED_ITEM_IN_TEXT` was added;
    the enums pin was rewritten.

- **Results shape (owner, 22 Nov: additive re-freeze of `ui_api_frozen.json`):** `build_scenario_view` gives a
  MITRE card every relevant group as `actors` (with `mitre_id`, `url`, `relevance`, `documented_techniques`) and
  `attack_techniques`, so `/v1/sessions/{id}/results` and `/v1/mitre_sessions/{id}/results` return the same cards.
- **Treatment plan (22 Nov):** its `scenario` block keeps the stored keys and adds the /results ones (`summary_controls`,
  `summary_actors` in `schemas/remediation.py`, `actor_views` now in `schemas/scenarios.py`); a library control the
  register names outside the scenario's controls and alternatives gives `EXISTING_CONTROL_NOT_FOR_THIS_RISK`.
- **Writer input:** `opening_sentences` (`search/mitre/mitre_index.py`) cuts each technique description to its
  opening sentences within `WRITER_TECHNIQUE_DESCRIPTION_CHARACTERS` (400); `relevance_reason` is gone from the
  candidate groups and from the writer prompt.

## Kimi calls (live, asset 1166)
| Step | Calls |
|---|---|
| create | actors 2, planner, duplicate check, writer, pick = 6 (4 when the actors are reused) |
| next set | writer, pick = 2; +2 (planner, duplicate check) for the set that runs short of paths |
| writer re-ask | +1 only when a scenario has a problem code can't remove |

## Debt
- One create is about 92k tokens a minute against the dev quota of 100k (see ADR-011, Risk).
