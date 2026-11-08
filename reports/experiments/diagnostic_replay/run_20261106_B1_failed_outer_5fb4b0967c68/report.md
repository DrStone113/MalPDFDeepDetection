# BUG-007B1 — Diagnostic Replay

Run: `5fb4b0967c68c75237f3ede29295ed7c1596af6611c7af626fb6facef84de3d0`

Planned: 74; diagnostic records: 0; graphs restored: 0.
Root causes remain null where the evidence establishes only a mechanism. Matching signatures do not prove a common root cause.
Baseline exit codes are legacy post-cleanup observations. Replay exit and cleanup codes are separate.
Outer shard setup/supervisor diagnostics are in outer_diagnostics.json; missing per-PDF attempts remain null.
Graph restored means a nonempty projection under the unchanged graph definition and node cap 200; model inputs remain unavailable.

| Baseline index | Split | Label | Replay status | Exit before cleanup | Cleanup exit | Last phase | Exception | Nodes | Edges | Mechanism |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 126 | train | 1 | null | null | null | null | null | null | null | null |
| 245 | validation | 1 | null | null | null | null | null | null | null | null |
| 255 | train | 0 | null | null | null | null | null | null | null | null |
| 265 | train | 1 | null | null | null | null | null | null | null | null |
| 275 | train | 1 | null | null | null | null | null | null | null | null |
| 285 | train | 1 | null | null | null | null | null | null | null | null |
| 287 | train | 1 | null | null | null | null | null | null | null | null |
| 292 | train | 0 | null | null | null | null | null | null | null | null |
| 295 | test | 1 | null | null | null | null | null | null | null | null |
| 297 | validation | 0 | null | null | null | null | null | null | null | null |
| 305 | validation | 0 | null | null | null | null | null | null | null | null |
| 307 | train | 0 | null | null | null | null | null | null | null | null |
| 315 | train | 1 | null | null | null | null | null | null | null | null |
| 317 | validation | 1 | null | null | null | null | null | null | null | null |
| 325 | train | 0 | null | null | null | null | null | null | null | null |
| 327 | train | 0 | null | null | null | null | null | null | null | null |
| 335 | train | 1 | null | null | null | null | null | null | null | null |
| 337 | validation | 1 | null | null | null | null | null | null | null | null |
| 345 | train | 1 | null | null | null | null | null | null | null | null |
| 347 | train | 1 | null | null | null | null | null | null | null | null |
| 355 | test | 1 | null | null | null | null | null | null | null | null |
| 357 | train | 0 | null | null | null | null | null | null | null | null |
| 365 | train | 1 | null | null | null | null | null | null | null | null |
| 367 | validation | 0 | null | null | null | null | null | null | null | null |
| 375 | validation | 0 | null | null | null | null | null | null | null | null |
| 377 | test | 1 | null | null | null | null | null | null | null | null |
| 385 | train | 0 | null | null | null | null | null | null | null | null |
| 387 | train | 1 | null | null | null | null | null | null | null | null |
| 395 | train | 1 | null | null | null | null | null | null | null | null |
| 397 | test | 0 | null | null | null | null | null | null | null | null |
| 405 | train | 1 | null | null | null | null | null | null | null | null |
| 407 | train | 0 | null | null | null | null | null | null | null | null |
| 415 | validation | 0 | null | null | null | null | null | null | null | null |
| 417 | test | 0 | null | null | null | null | null | null | null | null |
| 425 | train | 1 | null | null | null | null | null | null | null | null |
| 435 | train | 0 | null | null | null | null | null | null | null | null |
| 445 | validation | 1 | null | null | null | null | null | null | null | null |
| 455 | train | 0 | null | null | null | null | null | null | null | null |
| 465 | train | 1 | null | null | null | null | null | null | null | null |
| 475 | validation | 1 | null | null | null | null | null | null | null | null |
| 485 | validation | 1 | null | null | null | null | null | null | null | null |
| 495 | validation | 0 | null | null | null | null | null | null | null | null |
| 496 | train | 0 | null | null | null | null | null | null | null | null |
| 505 | validation | 0 | null | null | null | null | null | null | null | null |
| 515 | validation | 1 | null | null | null | null | null | null | null | null |
| 525 | train | 1 | null | null | null | null | null | null | null | null |
| 535 | validation | 1 | null | null | null | null | null | null | null | null |
| 545 | train | 1 | null | null | null | null | null | null | null | null |
| 555 | test | 1 | null | null | null | null | null | null | null | null |
| 565 | validation | 0 | null | null | null | null | null | null | null | null |
| 575 | train | 1 | null | null | null | null | null | null | null | null |
| 585 | train | 0 | null | null | null | null | null | null | null | null |
| 595 | train | 0 | null | null | null | null | null | null | null | null |
| 605 | train | 0 | null | null | null | null | null | null | null | null |
| 615 | test | 0 | null | null | null | null | null | null | null | null |
| 625 | train | 1 | null | null | null | null | null | null | null | null |
| 635 | test | 0 | null | null | null | null | null | null | null | null |
| 645 | train | 0 | null | null | null | null | null | null | null | null |
| 655 | test | 0 | null | null | null | null | null | null | null | null |
| 665 | train | 1 | null | null | null | null | null | null | null | null |
| 675 | train | 1 | null | null | null | null | null | null | null | null |
| 685 | test | 1 | null | null | null | null | null | null | null | null |
| 695 | train | 1 | null | null | null | null | null | null | null | null |
| 705 | train | 1 | null | null | null | null | null | null | null | null |
| 715 | test | 0 | null | null | null | null | null | null | null | null |
| 725 | train | 1 | null | null | null | null | null | null | null | null |
| 735 | train | 1 | null | null | null | null | null | null | null | null |
| 745 | train | 1 | null | null | null | null | null | null | null | null |
| 749 | train | 0 | null | null | null | null | null | null | null | null |
| 755 | validation | 1 | null | null | null | null | null | null | null | null |
| 765 | test | 0 | null | null | null | null | null | null | null | null |
| 775 | train | 0 | null | null | null | null | null | null | null | null |
| 785 | train | 1 | null | null | null | null | null | null | null | null |
| 795 | train | 0 | null | null | null | null | null | null | null | null |
