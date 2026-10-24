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
  `missing` (this worker reads another database), `other_epoch`, `other_task`, `leased` or `status_<x>`.

## When `ClockSkew` fires: fix the node (cluster admin)

1. Find the pod's node (changes nothing):

   ```
   oc -n ai-threatgen get pods -o wide
   oc -n ai-remediation get pods -o wide
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

From a Linux shell or the OpenShift web terminal, logged in with `oc`. It prints each pod's node and how far its
clock is from the shell's; within about ±2 s is fine.

```
NS=ai-threatgen; for p in $(oc get pods -n $NS -o name); do here=$(date -u +%s); there=$(oc exec -n $NS ${p#pod/} -- date -u +%s 2>/dev/null); node=$(oc get $p -n $NS -o jsonpath='{.spec.nodeName}'); if [ -n "$there" ]; then echo "$p node=$node pod_minus_here=$((there-here))s"; else echo "$p node=$node (no date command)"; fi; done
```

Run it again with `NS=ai-remediation`.
