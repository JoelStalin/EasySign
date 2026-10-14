# Scrum delivery playbook

## Roles
Product Owner: business value, priorities, regulatory gates and acceptance. Scrum Master: facilitates planning, daily scrum, review, retrospective, removes impediments. Developers: cross-functional engineering, QA, AppSec, DevOps, UX and legal SMEs. No AI model is claimed to have executed independent review unless evidence exists.

## Cadence
Two-week sprints. Sprint Planning: sprint goal, capacity and forecast. Daily Scrum: 15 minutes. Backlog refinement weekly. Sprint Review: working increment and evidence. Retrospective: measurable improvement. Backlog reprioritized by Product Owner; compliance blockers override feature deadlines.

## Definition of Ready
User story with persona, value, acceptance scenarios, dependencies, regulatory classification, threat impact, sizing and test strategy. No ambiguous external provider assumptions.

## Definition of Done
- Peer review and clean code; no dead code, clear naming, cohesive modules, bounded dependencies, documented ADRs.
- Unit/integration/contract/E2E tests pass in CI; coverage measured (target >=85% for critical business logic; all identified critical security branches tested).
- SAST, dependency/SCA, secrets scanning, SBOM, IaC scanning; no untreated critical findings.
- Authorization and tenant isolation tests; OWASP ASVS-based checks; threat model updated.
- DAST and scoped pentesting before release, findings triaged and remediated with retest evidence.
- Audit/observability, rollback, documentation, migrations, accessibility and privacy checks.
- Acceptance evidence linked to GitHub issue/PR. No production claim without independent acceptance review.

## Workflow
Backlog -> Ready -> In Progress -> Code Review -> QA/Security -> PO Acceptance -> Done. WIP limits and blocked reasons tracked in issues/projects. Use feature branches and PRs, protect main, prohibit force pushes.

## Metrics
Lead/cycle time, escaped defects, deployment frequency, change failure rate, mean recovery time, vulnerability remediation SLA and sprint goal success. Do not equate story points with developer productivity.
