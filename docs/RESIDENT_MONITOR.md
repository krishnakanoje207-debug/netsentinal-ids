# Local resident monitor

Install and start once from this checkout:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File lab/local/monitor_this_pc.ps1 -Action Install
```

The Windows task **NetSentinel Local Monitor** runs as the signed-in user with
limited privileges. It starts at that user's sign-in, including after reboot.
Approve the separate Windows UAC prompt for packet capture each time a new watch
starts. It cannot capture before sign-in or when that prompt is refused. There is
one launch attempt; failure or denied consent does not trigger repeated prompts.
Use `-Action Start` to retry after resolving the error.

The task owns the watch independently of this chat, terminals, dashboard and
browser. It opens no browser and starts no additional dashboard servers. Task
settings prevent duplicate task instances; exclusive file locks also prevent a
second watcher. It has no run-time limit and permits battery operation. Sleep
pauses capture; after wake the existing loop can continue if the capture driver
and child processes remain healthy. Resume after actual sleep is not verified.
No traffic is observed
while the machine is asleep, powered off, or signed out. A real reboot/suspend
must be tested separately; task configuration alone is not proof of capture.
If the capture, sensor or writer exits, the watch records failure and stops its
other children. It does not automatically retry or ask UAC repeatedly. Read the
error, resolve it and run Start (or sign in again). Historical alerts remain
available during capture failure; they do not indicate continuing observation.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File lab/local/monitor_this_pc.ps1 -Action Status
powershell -NoProfile -ExecutionPolicy Bypass -File lab/local/monitor_this_pc.ps1 -Action Stop
powershell -NoProfile -ExecutionPolicy Bypass -File lab/local/monitor_this_pc.ps1 -Action Start
powershell -NoProfile -ExecutionPolicy Bypass -File lab/local/monitor_this_pc.ps1 -Action Uninstall
```

Stop and Uninstall request orderly capture → sensor → writer shutdown. Allow the
current capture window and writer to drain. Uninstall also removes the login
task. Neither action deletes captured windows, credentials or database history.
Stop remains stopped until an explicit Start or the next sign-in. Uninstall is
the way to disable future sign-in starts. Avoid Task Manager's force-end command;
it can orphan pktmon, requiring an administrator to run `pktmon stop`.

`lab/local/out/live/status.json` records launcher lifecycle and UTC update time;
`resident.log` records startup/errors. Real capture evidence is new PCAPNG windows
under the current run's `windows` directory and advancing sensor/writer output.
A running task or existing historical alerts alone do not prove fresh capture.
Traffic is real local IPv4 traffic only; capture/scoring has stop/start gaps.
