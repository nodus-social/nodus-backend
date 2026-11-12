# 05 — Workers on Kubernetes

Status: draft · Last revised: 2026-11-07

The worker is a second deployment of the same codebase. It exists so that a post
does not wait for fan-out, and so that delivery to a slow instance cannot consume a
request thread.

## Job table contract

```sql
kind         text     -- deliver | fan_out | media_process | ingest_remote | prune
priority     smallint -- higher first: deliver 100, fan_out 50, media 20, ingest 10, prune 0
subject_id   text     -- the status/account the job is about, NULL for global jobs
earliest_at  timestamptz NOT NULL DEFAULT now()
attempts     int      NOT NULL DEFAULT 0
locked_by    text     -- worker pod name, NULL when free
locked_until timestamptz
last_error   text
```

Claiming is one statement, so two pods cannot take the same row:

```sql
UPDATE job SET locked_by = $1, locked_until = now() + interval '2 minutes', attempts = attempts + 1
WHERE id = (
  SELECT id FROM job
  WHERE finished_at IS NULL AND (locked_until IS NULL OR locked_until < now())
    AND earliest_at <= now()
  ORDER BY priority DESC, earliest_at
  FOR UPDATE SKIP LOCKED
  LIMIT 1
)
RETURNING id, kind, payload, attempts;
```

- **Lease, not delete.** A pod killed mid-job leaves `locked_until` in the past and
  the row returns to the pool. There is no dead-letter state: a job either succeeds,
  is rescheduled with a later `earliest_at`, or is discarded after `MAX_ATTEMPTS`
  (delivery 10, ingest 5) with `last_error` kept for the operator.
- **`subject_id` participates in a partial unique index** (`job_outstanding_subject`)
  so a second "fan out status X" cannot be enqueued while the first is outstanding —
  the same lesson the recommender's queue learned the hard way.

## Kinds

| Kind | Does | Runs |
| --- | --- | --- |
| `fan_out` | materialises `timeline_entry` for a local status in batches | on publish, delete, edit |
| `deliver` | one HTTP POST per remote inbox, signed | on publish, delete, follow changes |
| `media_process` | decodes, transcodes, generates blurhash, uploads variants | on upload |
| `ingest_remote` | fetches a remote actor, status or thread | on demand (lazy), and refresh |
| `prune` | tombstoned statuses > 30 d, finished jobs > 7 d, expired tokens | hourly, one pod |

## Runtime shape

- One loop per replica: claim → handle → repeat, with a bounded concurrency
  (`WORKER_CONCURRENCY`, default 8) and per-kind semaphores so a burst of `fan_out`
  cannot starve `deliver`.
- The loop **sleeps until the next `earliest_at`** rather than polling on a fixed
  interval when the queue is empty: `LISTEN job_queue` wakes it immediately when a
  job is enqueued, with a 30 s timer as a fallback if the notification is lost.
- Shutdown: SIGTERM stops claiming, waits for in-flight jobs (deadline
  `terminationGracePeriodSeconds: 60`), then rolls back any uncommitted work.

## Scaling

The metric that matters is **backlog**, not CPU: delivery is I/O-bound and a pod can
be 5% busy while 40 000 jobs wait.

```yaml
# excerpt, full manifests in k8s/
kind: HorizontalPodAutoscaler
spec:
  scaleTargetRef: { kind: Deployment, name: nodus-server-worker }
  metrics:
    - type: External
      external:
        metric: { name: nodus_job_backlog, selector: { matchLabels: { kind: deliver } } }
        target: { type: AverageValue, averageValue: "500" }
  minReplicas: 1
  maxReplicas: 12
  behavior:
    scaleDown: { stabilizationWindowSeconds: 600 }   # a burst is not a reason to churn pods
```

`nodus_job_backlog` is exported by the worker itself (`COUNT(*) WHERE finished_at IS
NULL AND earliest_at <= now()`), so no extra exporter is needed.

The API deployment scales on CPU and request rate; it must never scale on backlog,
because the API does not drain the backlog.

## Migrations and rollouts

`nodus-server --migrate-only` runs as a `Job` with `backoffLimit: 0` in an
`initContainer`-free step before `kubectl rollout`. Both deployments then start
against a schema that is already at head. Because the old worker keeps running
during a rollout, migrations must be additive within a release (`docs/04-storage.md`).

## Probes

- `GET /healthz` — process up. Used by `livenessProbe` after a 30 s initial delay.
- `GET /readyz` — database reachable, migrations at head, and (worker only) at least
  one job claimed since the last minute when the backlog is non-zero. A worker that
  cannot claim is not ready even though its process is fine.
