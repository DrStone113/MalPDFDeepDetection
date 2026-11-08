# BUG-007B1 — Diagnostic Replay

Run: `6f9cc944ed98304746fbbb5bc7066d9fb1c8d5b6a737ffd0f08205390527d575`

Planned: 74; diagnostic records: 74; graphs restored: 71.
Root causes remain null where the evidence establishes only a mechanism. Matching signatures do not prove a common root cause.
Baseline exit codes are legacy post-cleanup observations. Replay exit and cleanup codes are separate.
Outer shard setup/supervisor diagnostics are in outer_diagnostics.json; missing per-PDF attempts remain null.
Graph restored means a nonempty projection under the unchanged graph definition and node cap 200; model inputs remain unavailable.

| Baseline index | Split | Label | Replay status | Exit before cleanup | Cleanup exit | Last phase | Exception | Nodes | Edges | Mechanism |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 126 | train | 1 | timeout | null | -9 | parse_pdf | null | 55 | 47 | wall_timeout |
| 245 | validation | 1 | timeout | null | -9 | parser_analysis | null | 119 | 79 | wall_timeout |
| 255 | train | 0 | timeout | null | -9 | raw_forensic | null | 200 | 68 | wall_timeout |
| 265 | train | 1 | timeout | null | -9 | parser_analysis | null | 200 | 44 | wall_timeout |
| 275 | train | 1 | timeout | null | -9 | parser_analysis | null | 200 | 27 | wall_timeout |
| 285 | train | 1 | timeout | null | -9 | parser_analysis | null | 200 | 93 | wall_timeout |
| 287 | train | 1 | partial | null | -9 | result_serialization | null | 1 | 0 | no_worker_failure_observed |
| 292 | train | 0 | timeout | null | -9 | parse_pdf | null | 0 | 0 | wall_timeout |
| 295 | test | 1 | timeout | null | -9 | raw_forensic | null | 200 | 113 | wall_timeout |
| 297 | validation | 0 | unsupported | null | -9 | result_serialization | null | 120 | 100 | no_worker_failure_observed |
| 305 | validation | 0 | bounded_complete | null | -9 | result_serialization | null | 57 | 29 | no_worker_failure_observed |
| 307 | train | 0 | unsupported | null | -9 | result_serialization | null | 179 | 75 | no_worker_failure_observed |
| 315 | train | 1 | unsupported | null | -9 | result_serialization | null | 40 | 46 | no_worker_failure_observed |
| 317 | validation | 1 | decode_error | null | -9 | result_serialization | null | 77 | 55 | no_worker_failure_observed |
| 325 | train | 0 | timeout | null | -9 | stream_decode | null | 200 | 30 | wall_timeout |
| 327 | train | 0 | unsupported | null | -9 | result_serialization | null | 120 | 100 | no_worker_failure_observed |
| 335 | train | 1 | unsupported | null | -9 | result_serialization | null | 98 | 94 | no_worker_failure_observed |
| 337 | validation | 1 | timeout | null | -9 | parser_analysis | null | 119 | 79 | wall_timeout |
| 345 | train | 1 | unsupported | null | -9 | result_serialization | null | 176 | 90 | no_worker_failure_observed |
| 347 | train | 1 | timeout | null | -9 | raw_forensic | null | 200 | 66 | wall_timeout |
| 355 | test | 1 | unsupported | null | -9 | result_serialization | null | 100 | 71 | no_worker_failure_observed |
| 357 | train | 0 | timeout | null | -9 | raw_forensic | null | 155 | 73 | wall_timeout |
| 365 | train | 1 | timeout | null | -9 | parse_pdf | null | 200 | 118 | wall_timeout |
| 367 | validation | 0 | timeout | null | -9 | parser_analysis | null | 119 | 79 | wall_timeout |
| 375 | validation | 0 | bounded_complete | null | -9 | result_serialization | null | 200 | 32 | no_worker_failure_observed |
| 377 | test | 1 | unsupported | null | -9 | result_serialization | null | 100 | 71 | no_worker_failure_observed |
| 385 | train | 0 | bounded_complete | null | -9 | result_serialization | null | 15 | 16 | no_worker_failure_observed |
| 387 | train | 1 | bounded_complete | null | -9 | result_serialization | null | 30 | 27 | no_worker_failure_observed |
| 395 | train | 1 | timeout | null | -9 | raw_forensic | null | 200 | 106 | wall_timeout |
| 397 | test | 0 | unsupported | null | -9 | result_serialization | null | 100 | 71 | no_worker_failure_observed |
| 405 | train | 1 | unsupported | null | -9 | result_serialization | null | 46 | 39 | no_worker_failure_observed |
| 407 | train | 0 | timeout | null | -9 | parser_analysis | null | 0 | 0 | wall_timeout |
| 415 | validation | 0 | bounded_complete | null | -9 | result_serialization | null | 54 | 48 | no_worker_failure_observed |
| 417 | test | 0 | unsupported | null | -9 | result_serialization | null | 100 | 71 | no_worker_failure_observed |
| 425 | train | 1 | bounded_complete | null | -9 | result_serialization | null | 86 | 60 | no_worker_failure_observed |
| 435 | train | 0 | bounded_complete | null | -9 | result_serialization | null | 200 | 32 | no_worker_failure_observed |
| 445 | validation | 1 | timeout | null | -9 | parse_pdf | null | 200 | 109 | wall_timeout |
| 455 | train | 0 | timeout | null | -9 | raw_forensic | null | 200 | 85 | wall_timeout |
| 465 | train | 1 | bounded_complete | null | -9 | result_serialization | null | 73 | 59 | no_worker_failure_observed |
| 475 | validation | 1 | unsupported | null | -9 | result_serialization | null | 80 | 64 | no_worker_failure_observed |
| 485 | validation | 1 | decode_error | null | -9 | result_serialization | null | 77 | 55 | no_worker_failure_observed |
| 495 | validation | 0 | bounded_complete | null | -9 | result_serialization | null | 200 | 32 | no_worker_failure_observed |
| 496 | train | 0 | timeout | null | -9 | checkpoint_serialization | null | 79 | 55 | wall_timeout |
| 505 | validation | 0 | timeout | null | -9 | parser_analysis | null | 119 | 79 | wall_timeout |
| 515 | validation | 1 | bounded_complete | null | -9 | result_serialization | null | 200 | 32 | no_worker_failure_observed |
| 525 | train | 1 | timeout | null | -9 | raw_forensic | null | 200 | 46 | wall_timeout |
| 535 | validation | 1 | timeout | null | -9 | parser_analysis | null | 119 | 79 | wall_timeout |
| 545 | train | 1 | timeout | null | -9 | stream_decode | null | 200 | 30 | wall_timeout |
| 555 | test | 1 | unsupported | null | -9 | result_serialization | null | 100 | 71 | no_worker_failure_observed |
| 565 | validation | 0 | partial | null | -9 | result_serialization | null | 65 | 50 | no_worker_failure_observed |
| 575 | train | 1 | partial | null | -9 | result_serialization | null | 65 | 50 | no_worker_failure_observed |
| 585 | train | 0 | timeout | null | -9 | stream_decode | null | 200 | 102 | wall_timeout |
| 595 | train | 0 | timeout | null | -9 | stream_decode | null | 200 | 63 | wall_timeout |
| 605 | train | 0 | bounded_complete | null | -9 | result_serialization | null | 57 | 51 | no_worker_failure_observed |
| 615 | test | 0 | partial | null | -9 | result_serialization | null | 1 | 0 | no_worker_failure_observed |
| 625 | train | 1 | unsupported | null | -9 | result_serialization | null | 88 | 60 | no_worker_failure_observed |
| 635 | test | 0 | timeout | null | -9 | raw_forensic | null | 200 | 107 | wall_timeout |
| 645 | train | 0 | unsupported | null | -9 | result_serialization | null | 80 | 68 | no_worker_failure_observed |
| 655 | test | 0 | unsupported | null | -9 | result_serialization | null | 100 | 71 | no_worker_failure_observed |
| 665 | train | 1 | bounded_complete | null | -9 | result_serialization | null | 77 | 52 | no_worker_failure_observed |
| 675 | train | 1 | timeout | null | -9 | stream_decode | null | 200 | 32 | wall_timeout |
| 685 | test | 1 | bounded_complete | null | -9 | result_serialization | null | 200 | 113 | no_worker_failure_observed |
| 695 | train | 1 | unsupported | null | -9 | result_serialization | null | 43 | 39 | no_worker_failure_observed |
| 705 | train | 1 | bounded_complete | null | -9 | result_serialization | null | 57 | 51 | no_worker_failure_observed |
| 715 | test | 0 | bounded_complete | null | -9 | result_serialization | null | 55 | 45 | no_worker_failure_observed |
| 725 | train | 1 | bounded_complete | null | -9 | result_serialization | null | 200 | 67 | no_worker_failure_observed |
| 735 | train | 1 | bounded_complete | null | -9 | result_serialization | null | 57 | 51 | no_worker_failure_observed |
| 745 | train | 1 | timeout | null | -9 | parser_analysis | null | 200 | 118 | wall_timeout |
| 749 | train | 0 | timeout | null | -9 | parser_analysis | null | 0 | 0 | wall_timeout |
| 755 | validation | 1 | timeout | null | -9 | parser_analysis | null | 119 | 79 | wall_timeout |
| 765 | test | 0 | unsupported | null | -9 | result_serialization | null | 100 | 71 | no_worker_failure_observed |
| 775 | train | 0 | decode_error | null | -9 | result_serialization | null | 36 | 33 | no_worker_failure_observed |
| 785 | train | 1 | unsupported | null | -9 | result_serialization | null | 98 | 94 | no_worker_failure_observed |
| 795 | train | 0 | bounded_complete | -9 | -9 | byte_images | EOFError | 133 | 117 | signal_exit_unresolved |
