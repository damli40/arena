# Note on the archived commitments (added 2026-11-12, after two merge reviews)

The files in this folder are kept byte for byte as they were committed, so run files made on an earlier
set still check against the commitment they name. One field in them was wrong:
`"disjoint_from_public_library": true`.

- Sets 1 (`835729d9...`), 2 (`e35a4c1f...`) and 3 (`d314e04f...`): wrong. Each held one or more attacks
  whose steps equal, exactly or apart from a wait value, an attack file tracked in this repository or on a
  sibling branch that had not merged yet. The old check read only the library and the intents suite, on
  the current branch, and only exact copies.

Those attacks were retired: set 3 replaced the first, and set 4 replaced the other two. From set 4 on,
`tools/hidden/hidden.py` compares every hidden attack with every attack-shaped `.json` tracked on any
branch the repository knows, exactly and up to gas and wait values, and refuses a match. Other variants
of public attacks (different invoices, order or actors) can still exist in a hidden set; the check does
not refuse those.
