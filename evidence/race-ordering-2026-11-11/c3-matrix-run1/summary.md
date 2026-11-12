| scenario | guard | token | must | counted tries were | counted | cell | blocks (last check → first callback, achieved offsets) | not counted |
|---|---|---|---|---|---|---|---|---|
| s1-same-block | guard-vulnerable | test | broke | broke | 3 of 3 | PASS | checks to callback 81→83 offs [0, 0]; checks to callback 82→84 offs [0, 0]; checks to callback 83→85 offs [0, 0] | - |
| s1-same-block | guard-fixed | test | held | held | 3 of 3 | PASS | checks to callback 81→83 offs [0, 0]; checks to callback 82→84 offs [0, 0]; checks to callback 80→82 offs [0, 0] | - |
| s1-same-block | M5 | test | broke | broke | 3 of 3 | PASS | checks to callback 111→113 offs [0, 0]; checks to callback 111→113 offs [0, 0]; checks to callback 111→113 offs [0, 0] | - |
| s1-same-block | vault-a | test | held | held | 3 of 3 | PASS | checks to callback 111→113 offs [0, 0]; checks to callback 114→116 offs [0, 0]; checks to callback 113→115 offs [0, 0] | - |
| s1-same-block | race-m1 | test | held | held | 3 of 3 | PASS | checks to callback 112→114 offs [0, 0]; checks to callback 113→115 offs [0, 0]; checks to callback 113→115 offs [0, 0] | - |
| s2-next-block | race-m1 | test | broke | broke | 3 of 3 | PASS | checks to callback 113→114 offs [0, 1]; checks to callback 112→113 offs [0, 1]; checks to callback 113→114 offs [0, 1] | - |
| s2-next-block | vault-a | test | held | held | 3 of 3 | PASS | checks to callback 113→114 offs [0, 1]; checks to callback 111→112 offs [0, 1]; checks to callback 112→113 offs [0, 1] | - |
| s2-next-block | guard-vulnerable | test | broke | broke | 3 of 3 | PASS | checks to callback 81→82 offs [0, 1]; checks to callback 81→82 offs [0, 1]; checks to callback 82→83 offs [0, 1] | - |
| s2-next-block | guard-fixed | test | held | held | 3 of 3 | PASS | checks to callback 83→84 offs [0, 1]; checks to callback 82→83 offs [0, 1]; checks to callback 83→84 offs [0, 1] | - |
| s2-next-block | M5 | test | broke | broke | 3 of 3 | PASS | checks to callback 111→112 offs [0, 1]; checks to callback 115→116 offs [0, 1]; checks to callback 111→112 offs [0, 1] | - |
| s1-twin-sequential | guard-vulnerable | test | held | held | 3 of 3 | PASS | checks to callback 87→84 offs [0, 5]; checks to callback 86→83 offs [0, 5]; checks to callback 86→83 offs [0, 5] | - |
| s1-twin-sequential | M5 | test | held | held | 3 of 3 | PASS | checks to callback 115→112 offs [0, 5]; checks to callback 117→114 offs [0, 5]; checks to callback 116→113 offs [0, 5] | - |
| s2-twin-sequential | race-m1 | test | held | held | 3 of 3 | PASS | checks to callback 117→114 offs [0, 5]; checks to callback 117→114 offs [0, 5]; checks to callback 115→112 offs [0, 5] | - |
| s2-twin-sequential | guard-vulnerable | test | held | held | 3 of 3 | PASS | checks to callback 85→82 offs [0, 5]; checks to callback 84→81 offs [0, 5]; checks to callback 85→82 offs [0, 5] | - |
| s2-twin-sequential | M5 | test | held | held | 3 of 3 | PASS | checks to callback 115→112 offs [0, 5]; checks to callback 115→112 offs [0, 5]; checks to callback 116→113 offs [0, 5] | - |
| s5-too-late | guard-vulnerable | test | held | held | 3 of 3 | PASS | checks to callback 86→83 offs [0, 5]; checks to callback 88→85 offs [0, 5]; checks to callback 87→84 offs [0, 5] | - |
| s5-too-late | guard-fixed | test | held | held | 3 of 3 | PASS | checks to callback 85→82 offs [0, 5]; checks to callback 87→84 offs [0, 5]; checks to callback 86→83 offs [0, 5] | - |
| s3-held-answer | race-m2 | slow | broke | broke | 3 of 3 | PASS | checks to callback 117→122 offs [0, 4]; checks to callback 121→126 offs [0, 4]; checks to callback 118→122 offs [0, 4] | - |
| s3-held-answer | vault-a | slow | held | held | 3 of 3 | PASS | checks to callback 119→123 offs [0, 4]; checks to callback 120→124 offs [0, 4]; checks to callback 118→122 offs [0, 4] | - |
| s3-held-answer | guard-vulnerable | slow | broke | broke | 3 of 3 | PASS | checks to callback 89→94 offs [0, 4]; checks to callback 89→94 offs [0, 4]; checks to callback 87→92 offs [0, 4] | - |
| s3-held-answer | guard-fixed | slow | held | held | 3 of 3 | PASS | checks to callback 87→91 offs [0, 4]; checks to callback 86→90 offs [0, 4]; checks to callback 86→90 offs [0, 4] | - |
| s3-twin-sequential | race-m2 | slow | held | held | 3 of 3 | PASS | checks to callback 117→114 offs [0, 5]; checks to callback 116→113 offs [0, 5]; checks to callback 115→112 offs [0, 5] | - |
| s1-same-block | race-m2 | test | held | held | 3 of 3 | PASS | checks to callback 113→115 offs [0, 0]; checks to callback 112→114 offs [0, 0]; checks to callback 112→114 offs [0, 0] | - |
| s2-next-block | race-m2 | test | held | held | 3 of 3 | PASS | checks to callback 113→114 offs [0, 1]; checks to callback 113→114 offs [0, 1]; checks to callback 114→115 offs [0, 1] | - |
| s2-next-block | race-m1 | slow | broke | broke | 3 of 3 | PASS | checks to callback 112→113 offs [0, 1]; checks to callback 114→115 offs [0, 1]; checks to callback 112→113 offs [0, 1] | - |
| s4-cap-timed | race-m3 | test | cap-broke | cap-broke | 3 of 3 | PASS | checks to callback 113→114 offs [0, 0, 1]; checks to callback 115→116 offs [0, 0, 1]; checks to callback 116→117 offs [0, 0, 1] | - |
| s4-cap-timed | vault-a | test | cap-held | cap-held | 3 of 3 | PASS | checks to callback 111→112 offs [0, 0, 1]; checks to callback 112→113 offs [0, 0, 1]; checks to callback 119→120 offs [0, 0, 1] | - |
| s4-cap-held | race-m3 | slow | cap-broke | - | 0 of 5 | FAIL |  | try 1: not-produced; try 2: not-produced; try 3: not-produced; try 4: not-produced; try 5: not-produced |
| s4-cap-held | vault-a | slow | cap-held | - | 0 of 5 | FAIL |  | try 1: not-produced; try 2: not-produced; try 3: not-produced; try 4: not-produced; try 5: not-produced |
| s4-twin-sequential | race-m3 | test | cap-held | cap-held | 3 of 3 | PASS | checks to callback 125→117 offs [0, 5, 10]; checks to callback 123→115 offs [0, 5, 10]; checks to callback 120→112 offs [0, 5, 10] | - |

race-c3: 30 cells, 28 passed; counted tries 84, not counted 10; wall 501 s
