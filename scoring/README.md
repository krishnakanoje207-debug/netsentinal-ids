# scoring

`netsentinel-scoring` — M2's layer 4. Loads the exported ONNX models, scores a
`FlowFeatures` from `netsentinel-core`, fuses the tier scores into one risk score,
and carries the explanation alongside it.

Its own package because it needs `onnxruntime`, which `core` — imported by the
sensor, the API and training alike — must not drag in.

Runs in-process beside the sensor on the cloud VM, so inference costs no network
hop (M2 §4, sub-5 ms budget).
