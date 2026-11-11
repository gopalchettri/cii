# UAT: pod clocks out of step ("sent 5 times and never started")

## What was wrong, in one paragraph

On 2026-10-24 every UAT run failed at its first stage: "The job was sent 5 times and never started, so it was given
up." The pods' clocks disagreed by up to 76 seconds (Celery: "Substantial drift ... 76 seconds"). A job's due time
is written with the clock of the pod that queues it, and a worker took a job only if that time had come by **its
own** clock, give or take 5 seconds. A worker 76 s behind therefore saw every job as "not due yet" and dropped it
(`job.not_claimed`) until the reaper gave up.

Since then every pod reads the time from one shared clock, MongoDB's (`app/core/clock.py`). Each pod measures its
own clock against MongoDB's when it starts and every minute after, and corrects for the difference. Jobs, leases
and the `/ready` heartbeat now work at any skew. The servers' clocks should still be fixed, and the `ClockSkew`
alert says when one is not.

## What happens by itself (nothing to do)

- **Correcting:** every pod corrects its own time all the time. No setting and no deploy step is needed.
- **Watching:** every pod reports `tsg_clock_offset_seconds`, MongoDB's clock minus its own. The `ClockSkew` alert
  (warning) fires when any pod is more than 5 s off for 5 minutes. The dashboard's problem list shows it as "A pod's
  clock is off: its node needs time sync".
- **Explaining:** a dropped job's log line says why: `job.not_claimed` with `reason=not_due` (and `due_in_seconds`),
  `missing` (this worker reads another database), `other_epoch`, `other_task`, `leased` (`job_worker` holds it) or
  `status_<x>`. A retry that came early (Celery counts its delay on its own pod's clock) and is due within 125 s is
  not dropped: it is sent again for its due time, at the front of its queue, and the line says `sent_again=true`.

## When `ClockSkew` fires: fix the node (cluster admin)

1. Find the pod's node (changes nothing):

   ```
   oc -n ai-threatgen get pods -o wide
   oc -n ai-common get pods -o wide -l part-of=tsg-monitoring
   ```

2. Check the node's time sync (needs cluster-admin; changes nothing):

   ```
   oc debug node/<node-name> -- chroot /host chronyc tracking
   ```

   A synced node shows "Leap status: Normal" and a "System time" well under a second. Anything else means the node
   is not syncing.

3. Fix it as the platform team does for OpenShift: chrony is configured through a `MachineConfig` that names the
   company's NTP servers. Once the nodes sync, the alert clears within minutes. No app change or restart is needed.

## Checking every pod's clock by hand (optional)

From any Windows or Linux machine with Python 3.8+, logged in with `oc` (reads only; the script is one file and
needs nothing else):

```
python scripts/uat_clock_check.py
```

UTC is the standard: the clock of the machine running it, so keep that machine synced (`w32tm /query /status`).
It reads MongoDB, Redis (from inside the `tsg-api` pods, with the app's own connections) and every pod in every
project your login sees, except OpenShift's own (`openshift*`, `kube-*`). It prints a plain log for the support
team and saves it as `clock_check_<UTC time>.log` in the current folder:

- **READINGS**: one line per clock, the time it shows and its gap from UTC, marked `[GAP]` (more than 2 s;
  `--max-skew` changes it), `[OK]` or `[N/A]` (not read, with why). Each pod line names its node.
- **SUMMARY**: each gap, numbered, with who fixes it. A pod has no clock of its own: it uses its node's, so a
  node's gap shows on every pod on it and the node is what gets fixed (the cluster admin, with the `chronyc`
  command given). MongoDB and Redis run outside the cluster: their own admins turn on time sync.

Exit code 0 means no gap, 1 a gap, 2 that MongoDB, Redis or every pod could not be read.

Without Python, from a Linux shell or the OpenShift web terminal, logged in with `oc`. It prints each pod's node
and how far its clock is from the shell's; within about ±2 s is fine.

```
NS=ai-threatgen; for p in $(oc get pods -n $NS -o name); do here=$(date -u +%s); there=$(oc exec -n $NS ${p#pod/} -- date -u +%s 2>/dev/null); node=$(oc get $p -n $NS -o jsonpath='{.spec.nodeName}'); if [ -n "$there" ]; then echo "$p node=$node pod_minus_here=$((there-here))s"; else echo "$p node=$node (no date command)"; fi; done
```

TSG's app pods all run in `ai-threatgen`.
