# Hugging Face Space deployment — 2026-11-10

Space: [DrStone113/malpdfdetection](https://huggingface.co/spaces/DrStone113/malpdfdetection).
Application: [direct URL](https://drstone113-malpdfdetection.hf.space).

## Deployed revisions

| Item | Revision |
| --- | --- |
| Previous Space | `58e0017f8e4a2ff9324d0c7fac77a133cb38e258` |
| Application security deployment | `7ca6c4748abb055d47b32f259774936ce18d8908` |
| Final Space, including TLS-proxy correction | `e5a122521a702cb983281f5d3b35d2e1475f9e9b` |
| Windows source | `67cb50898bb41fe8437e130b3e55c6d216035ed9` |

The Hub API reports `RUNNING` with the final runtime SHA matching the pushed
Space SHA. Hardware remains `zero-a10g` with one replica. Existing Space README,
SDK configuration and model binaries were preserved. Packaged source files and
the deployed UI match the Windows release source.

## Measured verification

- Preflight application regression: 110 passed; later credential/proxy checks:
  47 passed. These overlapping groups must not be added together.
- No-PDF hosted-CI commands reproduced locally in an isolated environment:
  16 passed.
- Native dependency audit of the resolved production requirements: 30
  dependencies, zero known vulnerabilities reported. This does not audit every
  platform-managed Gradio/ZeroGPU package.
- Source/content/security synthetic gate: 237 passed; no Python comments added.

Post-deployment HTTPS checks all passed on the final runtime:

1. Deployed HTML equals the release source and has no provider-key literal.
2. Session cookies include Secure, HttpOnly and Partitioned flags.
3. Both ONNX models load and health reports healthy.
4. A same-origin upload of the existing reviewed benign PDF returns BENIGN with
   explicit occlusion provenance.
5. A separate browser cookie jar sees no inherited document/history and receives
   404 for the first session's scan ID.
6. A foreign Origin cannot delete the owner's document (403).
7. CDR download retains >80% bytes, identical page count and nonempty identical
   extracted text.
8. Original and cleaned page-preview images are available.
9. A benign PDF inside nested MIME is inspected and the email passes.
10. Deterministic chat works; unconfigured cloud mode explicitly returns 503.

The controlled scan job was deleted after verification. Only the approved benign
fixture (`ef43e7f9e1c138d5d5279fe3c16e54c7d0a63c1a056f5008550872e31b4b0fa7`)
was uploaded; no suspicious/raw corpus or real malware was processed on the Space.
These are live HTTP/API checks, not a claim of full browser/iframe E2E coverage.

## Deployment-specific corrections and remaining action

The initial live same-origin upload returned 403 because Hugging Face terminates
HTTPS before the app's internal HTTP URL. `MALPDF_PUBLIC_ORIGIN` is now configured
as the exact public HTTPS origin; the final source uses that trusted server value
for Origin checks and cookie flags, without accepting arbitrary forwarded
headers. The same live upload then passed.

An existing cloud-provider credential was embedded in the public UI. It was
removed and cloud requests moved to the session-scoped backend. The old value
was never reused or copied into Space Secrets. Cloud AI therefore uses the
existing fallback until the owner revokes/rotates the old key and configures a
replacement as `VILAO_API_KEY` in Space Secrets. Old public Git history may still
contain the exposed value; no destructive history rewrite was performed.

Detailed local evidence is under ignored
`artifacts/tmp/hf-deploy-20261110/`: `live-verification.json`,
`application-tests.xml`, `proxy-tests.xml`, `ci-web-security.xml`, and
`dependency-audit.json`. No secret values are included in this report.
