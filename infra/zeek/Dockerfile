# Zeek with FoxIO's JA4+ package baked in.
#
# The scripts-only package (foxio/ja4-zeek-scripts), not the plugin (foxio/ja4): the
# plugin is C++ and needs a compiler and CMake the stock image does not carry, which
# would triple the image for a lab bridge's worth of traffic. The script package
# produces the same ja4/ja4s/ja4h fields in ssl.log, http.log and conn.log.
#
# Installed at build time rather than on container start, so the sensor never
# depends on GitHub being reachable to come up.
FROM zeek/zeek:8.0.10

RUN zkg install --force --skiptests --version v1.0.0 foxio/ja4-zeek-scripts
