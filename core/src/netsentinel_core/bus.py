"""Topic names shared by the producer and its consumers.

A string constant rather than configuration: the sensor writing to one topic name
and the writer reading from another is a failure with no symptom - the pipeline
simply stays silent - so the two sides are made to import the same name.

Here rather than in the sensor package because core is the only thing both sides
depend on. It costs nothing: core is deliberately tiny, and this adds no imports.
"""

from __future__ import annotations

#: Scored flows, keyed by flow id so one flow's records stay in order within a
#: partition. Retained rather than acked and forgotten, so the stream can be
#: replayed when a model is retrained.
FLOW_TOPIC = "netsentinel.flows"
