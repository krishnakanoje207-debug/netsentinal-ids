# Site policy for the lab sensor. Replaces the image's local.zeek.
#
# JSON rather than Zeek's TSV: Vector parses every line with parse_json, and the
# fields map in zeek_logs is built from the JSON keys.
@load policy/tuning/json-logs.zeek

# Everything zkg installed, which in this image is the JA4+ scripts (see Dockerfile).
@load packages
