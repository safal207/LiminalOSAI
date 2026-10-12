# Technical review request — draft

Prepared for an OpenAI developer-community discussion or a technical review
request. No message has been sent and no OpenAI reviewer, endorsement or
integration is established. Use the relevant channel's submission format.

## Subject

Request for review: reproducible agent-action revocation and lost-response tests

## Message

Hello,

I'm Alexey Safonov, a QA engineer developing a public experiment for controlling
agent actions at a host broker and an owned receiver.

The question is practical: what evidence establishes the result when a worker
has stopped, a request is still queued, or a response is lost after a commit?

Our frozen Docker queue experiment compares three configurations: sandbox,
process stop, and process stop plus receiver-backed authorization and revocation.
The queued synthetic record commits in the first two configurations and is
blocked in the third. The useful authorized operation completes in each.
Separate fault tests retain UNKNOWN after response loss, block replay at the
revoked-root fence, reconcile against the receiver without a second commit,
and detect a scripted FAILED worker claim that contradicts a recorded commit.

Would someone be interested in independently reproducing one bounded scenario
or reviewing the methodology and its applicability to agent tool boundaries?
A failed or partial reproduction would be valuable.

- [Review package and code, PR #203](https://github.com/safal207/LiminalOSAI/pull/203)
- [First-run instructions](https://github.com/safal207/LiminalOSAI/blob/agent/receiver-backed-control-20261011/docs/AGENT_CONTROL_CLEAN_RUN.md#first-external-run-no-docker-or-model-key)
- [Recorded CI run](https://github.com/safal207/LiminalOSAI/actions/runs/38210262967)
- [External reproduction discussion](https://github.com/safal207/LiminalOSAI/issues/201)

The local profile requires no model key or Docker; the full profile requires
Linux/Docker. These are finite engineering fixtures with synthetic records at
owned receivers. Live-model evaluation has not run, external human reproduction
is not established, and the PR remains unmerged. The experiment assumes a
trusted host, broker, receiver and keys; it does not establish general sandbox
escape prevention or model honesty.

Thank you,
Alexey Safonov / safal207

## Verified entry points (checked 2026-10-12)

- [OpenAI developer community](https://developers.openai.com/community): developer
  discussion and a project/demo submission route. A community post is a request
  for feedback; it does not establish engagement by an OpenAI engineering team.
- [Researcher Access Program](https://openai.com/form/researcher-access-program/):
  research API-credit applications. Its
  [FAQ](https://help.openai.com/en/articles/10139500-researcher-access-program-faq)
  requires an active research affiliation and an API-supported country. This
  package makes no eligibility or award claim.
- [Safety Bug Bounty](https://openai.com/index/safety-bug-bounty/): specific
  reproducible safety findings in OpenAI products. Our owned-fixture results
  do not establish a vulnerability in an OpenAI product and are not a bounty
  submission.
