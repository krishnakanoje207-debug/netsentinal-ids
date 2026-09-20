"""What the Copilot is allowed to return.

The model does not produce a summary; it produces a candidate summary, which this
schema either accepts or rejects. That inversion is the whole design. A language
model given an alert will write something plausible whatever it was fed, so the
guarantee cannot be "the model behaves" - it has to be "output that is not of this
shape never reaches an analyst".

Three properties are enforced here rather than hoped for:

* **Bounded fields.** Every string has a maximum length, so a model that starts
  reciting cannot fill a page of the dashboard or a JSONB column.
* **A closed set of verdicts.** ``assessment`` is one of three values. Free text
  would let the model invent a fourth that no filter matches and no analyst expects.
* **No actions, only suggestions.** ``next_steps`` is a list of sentences an analyst
  reads. Nothing here is executable, nothing here names an endpoint to call, and the
  Copilot has no path to the response gate - by construction, not by instruction.

``schema_valid`` on the stored row is what this returns: rejected output is kept
rather than discarded, because a pattern of invalid output is a signal about the
model, the prompt or somebody probing it.
"""

from __future__ import annotations

import enum

from pydantic import BaseModel, ConfigDict, Field


class Assessment(str, enum.Enum):
    """The three answers an analyst actually acts on."""

    likely_malicious = "likely_malicious"
    needs_investigation = "needs_investigation"
    likely_benign = "likely_benign"


class AlertSummary(BaseModel):
    # Anything the model invents beyond these fields is a rejection, not an extra:
    # a summary carrying an unexpected key is a summary that was not written to this
    # contract, and guessing which half to trust is not a judgement worth making.
    model_config = ConfigDict(extra="forbid")

    headline: str = Field(min_length=3, max_length=120)
    what_happened: str = Field(min_length=10, max_length=1000)
    #: Why the detector scored it as it did, in the analyst's language. The model is
    #: given the SHAP contributions and asked to put them in a sentence - it is not
    #: asked to decide which features mattered, which it cannot know.
    why_it_scored: str = Field(min_length=10, max_length=1000)
    assessment: Assessment
    next_steps: list[str] = Field(min_length=1, max_length=5)

    @property
    def as_row(self) -> dict:
        """The JSONB payload for ``copilot_summaries.summary_json``."""
        return self.model_dump(mode="json")


def validate(payload: object) -> AlertSummary:
    """Parse a candidate summary. Raises ``pydantic.ValidationError`` if it is not one.

    Deliberately thin: the caller stores the rejection as well as the acceptance, so
    this must not swallow the reason.
    """
    return AlertSummary.model_validate(payload)


#: The JSON Schema handed to the model, so the request states the contract the reply
#: is going to be held to. Ollama enforces the shape during generation; this schema
#: is still re-checked on the way back, because a served model is another system and
#: "it promised" is not a validation strategy.
def json_schema() -> dict:
    return AlertSummary.model_json_schema()
