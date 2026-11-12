| scenario | guard | must | counted tries were | counted | cell | blocks (last check → first callback, achieved offsets) | not counted |
|---|---|---|---|---|---|---|---|
| s1-same-block | guard-vulnerable | broke | broke | 3 of 3 | PASS | checks to callback 83→85 offs [0, 0]; checks to callback 85→87 offs [0, 0]; checks to callback 86→88 offs [0, 0] | - |
| s1-same-block | guard-fixed | held | held | 3 of 3 | PASS | checks to callback 83→85 offs [0, 0]; checks to callback 85→87 offs [0, 0]; checks to callback 84→86 offs [0, 0] | - |
| s1-same-block | M5 | broke | broke | 3 of 3 | PASS | checks to callback 112→114 offs [0, 0]; checks to callback 112→114 offs [0, 0]; checks to callback 115→117 offs [0, 0] | - |
| s1-same-block | vault-a | held | held | 3 of 3 | PASS | checks to callback 114→116 offs [0, 0]; checks to callback 112→114 offs [0, 0]; checks to callback 111→113 offs [0, 0] | - |
| s1-same-block | race-m1 | held | held | 3 of 3 | PASS | checks to callback 113→115 offs [0, 0]; checks to callback 111→113 offs [0, 0]; checks to callback 113→115 offs [0, 0] | - |
| s2-next-block | race-m1 | broke | broke | 3 of 3 | PASS | checks to callback 112→113 offs [0, 1]; checks to callback 113→114 offs [0, 1]; checks to callback 115→116 offs [0, 1] | - |
| s2-next-block | vault-a | held | held | 3 of 3 | PASS | checks to callback 114→115 offs [0, 1]; checks to callback 116→117 offs [0, 1]; checks to callback 114→115 offs [0, 1] | - |
| s2-next-block | guard-vulnerable | broke | broke | 3 of 3 | PASS | checks to callback 85→86 offs [0, 1]; checks to callback 86→87 offs [0, 1]; checks to callback 83→84 offs [0, 1] | - |
| s2-next-block | guard-fixed | held | held | 3 of 3 | PASS | checks to callback 85→86 offs [0, 1]; checks to callback 88→89 offs [0, 1]; checks to callback 84→85 offs [0, 1] | - |
| s2-next-block | M5 | broke | broke | 3 of 3 | PASS | checks to callback 114→115 offs [0, 1]; checks to callback 116→117 offs [0, 1]; checks to callback 115→116 offs [0, 1] | - |
| s1-twin-sequential | guard-vulnerable | held | held | 3 of 3 | PASS | checks to callback 86→83 offs [0, 5]; checks to callback 86→83 offs [0, 5]; checks to callback 86→83 offs [0, 5] | - |
| s1-twin-sequential | M5 | held | held | 3 of 3 | PASS | checks to callback 117→114 offs [0, 5]; checks to callback 118→115 offs [0, 5]; checks to callback 116→113 offs [0, 5] | - |
| s2-twin-sequential | race-m1 | held | held | 3 of 3 | PASS | checks to callback 118→115 offs [0, 5]; checks to callback 119→116 offs [0, 5]; checks to callback 115→112 offs [0, 5] | - |
| s2-twin-sequential | guard-vulnerable | held | held | 3 of 3 | PASS | checks to callback 87→84 offs [0, 5]; checks to callback 87→84 offs [0, 5]; checks to callback 87→84 offs [0, 5] | - |
| s2-twin-sequential | M5 | held | held | 3 of 3 | PASS | checks to callback 120→117 offs [0, 5]; checks to callback 117→114 offs [0, 5]; checks to callback 115→112 offs [0, 5] | - |
| s5-too-late | guard-vulnerable | held | held | 3 of 3 | PASS | checks to callback 88→85 offs [0, 5]; checks to callback 88→85 offs [0, 5]; checks to callback 84→81 offs [0, 5] | - |
| s5-too-late | guard-fixed | held | held | 3 of 3 | PASS | checks to callback 84→81 offs [0, 5]; checks to callback 86→83 offs [0, 5]; checks to callback 89→86 offs [0, 5] | - |

race-c2: 17 cells, 17 passed; counted tries 51, not counted 0; wall 283 s
