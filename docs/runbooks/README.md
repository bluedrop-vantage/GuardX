# GuardX operator runbooks

Alert-linked runbooks for on-call operators. Each runbook lists the
Prometheus signal, what it means, how to diagnose, how to fix, and how to
prevent recurrence.

| Runbook | Alert / Trigger | Class |
| ----- | ----- | ----- |
| [bundle-stale.md](bundle-stale.md) | `GuardXBundleStale` / `GuardXBundleAgeCritical` | policy drift |
| [chain-anchor-fail.md](chain-anchor-fail.md) | `verify_chain` non-zero | compliance-critical |
| [provider-outage.md](provider-outage.md) | `GuardXDetectorErrorSpike` | detector health |
| [fail-open.md](fail-open.md) | `GuardXFailOpenOccurring` | security incident |
| [oidc-setup.md](oidc-setup.md) | onboarding | operator setup |

Alert rules live in [deploy/helm/alerts/guardx-alerts.yaml](../../deploy/helm/alerts/guardx-alerts.yaml).
Grafana dashboard: [deploy/helm/dashboards/gateway.json](../../deploy/helm/dashboards/gateway.json).
