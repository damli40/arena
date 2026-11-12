# Note on the archived commitments (added 2026-11-12, after two merge reviews)

The files in this folder are kept byte for byte as they were committed, so run files made on an earlier
set still check against the commitment they name. One field in them was wrong:
`"disjoint_from_public_library": true`.

- Set 1 (`835729d9...`) and set 2 (`e35a4c1f...`): wrong. Each held an attack whose steps equal a hunt
  proposal tracked in `evidence/hunts/`, and one whose steps equal a tracked library attack apart from a
  wait value. The old check read only the library and the intents suite, on the current branch, exactly.
- Set 2 (`e35a4c1f...`) and set 3 (`d314e04f...`): also wrong for one more attack, whose steps equal a file
  tracked on a sibling branch that had not merged yet.

Those attacks were retired: set 3 replaced the first, and set 4 replaced the other two. From set 4 on,
`tools/hidden/hidden.py` compares every hidden attack with every attack-shaped `.json` tracked on any
branch the repository knows, exactly and up to gas and wait values, and refuses a match. Other variants
of public attacks (different invoices, order or actors) can still exist in a hidden set; the check does
not refuse those.
