"""Apply ONE planted flaw to a copy of targets/vault-a/src/lib.rs.

    python3 -I tools/mutation/mutate.py <id> <lib.rs>     edit the file in place
    python3 -I tools/mutation/mutate.py --list            print the mutant ids

Each mutant is a list of exact (old, new) string replacements. Every `old` must
occur exactly once in the file, or the script fails, so a mutant can never
silently apply to the wrong line or to nothing. M0 changes nothing (build check).
Pre-registration: evidence/mutation-plan.md.
"""
import sys

MUTANTS = {
    "M0": [],
    # payee check in pay removed entirely
    "M1": [(
        "            match self.payees.get(&inv.receiver) {\n"
        "                Some(g) if *g == inv.payee_generation => {}\n"
        "                _ => env::panic_str(\"receiver is no longer a payee\"),\n"
        "            }\n",
        "            // MUTANT M1: payee check removed\n",
    )],
    # daily-cap check removed
    "M2": [(
        "        require!(new_spent <= self.daily_cap, \"daily cap exceeded\");\n",
        "        // MUTANT M2: daily-cap check removed\n",
    )],
    # cap checked per payment instead of as a running total
    "M3": [(
        "        require!(new_spent <= self.daily_cap, \"daily cap exceeded\");\n",
        "        require!(amount <= self.daily_cap, \"daily cap exceeded\"); // MUTANT M3: per payment\n",
    )],
    # already-paid check removed: a Paid invoice is payable again
    "M4": [(
        "                InvoiceStatus::Paid => env::panic_str(\"invoice already paid\"),\n"
        "                InvoiceStatus::Cancelled => env::panic_str(\"invoice cancelled\"),\n",
        "                InvoiceStatus::Paid => {} // MUTANT M4: already-paid check removed\n"
        "                InvoiceStatus::Cancelled => env::panic_str(\"invoice cancelled\"),\n",
    )],
    # record the payment only in the callback (the double-pay race)
    "M5": [
        (
            "            inv.status = InvoiceStatus::Pending;\n",
            "            // MUTANT M5: not marked Pending before the transfer\n",
        ),
        (
            "            Some(inv) if inv.status == InvoiceStatus::Pending => {\n",
            "            Some(inv) if inv.status == InvoiceStatus::Pending || inv.status == InvoiceStatus::Approved => { // MUTANT M5\n",
        ),
    ],
    # expiry check removed
    "M6": [(
        "            require!(now < inv.expires_at_ns, \"invoice expired\");\n",
        "            // MUTANT M6: expiry check removed\n",
    )],
    # cancelled-invoice check removed
    "M7": [(
        "                InvoiceStatus::Cancelled => env::panic_str(\"invoice cancelled\"),\n",
        "                InvoiceStatus::Cancelled => {} // MUTANT M7: cancelled check removed\n",
    )],
    # agent-only check removed: any account can call pay
    "M8": [(
        "        require!(env::predecessor_account_id() == self.agent, \"only the agent can pay\");\n",
        "        // MUTANT M8: agent-only check removed\n",
    )],
    # failed transfer releases the cap reservation twice
    "M9": [(
        "                self.spent_amount = self.spent_amount.saturating_sub(amount);\n",
        "                self.spent_amount = self.spent_amount.saturating_sub(amount.saturating_mul(2)); // MUTANT M9\n",
    )],
    # payee generation ignored: remove-then-re-add revives old invoices
    "M10": [(
        "                Some(g) if *g == inv.payee_generation => {}\n",
        "                Some(_) => {} // MUTANT M10: payee generation ignored\n",
    )],
    # gas pre-check in pay removed (added 2026-11-12, plan: evidence/mutation-plan-2026-11-12.md)
    "M11": [(
        "        require!(remaining >= needed, \"not enough gas attached to pay safely\");\n",
        "        let _ = (remaining, needed); // MUTANT M11: gas pre-check removed\n",
    )],
}


def main():
    if sys.argv[1:] == ["--list"]:
        print(" ".join(MUTANTS))
        return
    if len(sys.argv) != 3 or sys.argv[1] not in MUTANTS:
        sys.exit("usage: mutate.py <" + "|".join(MUTANTS) + "> <lib.rs>  |  mutate.py --list")
    mid, path = sys.argv[1], sys.argv[2]
    src = open(path, encoding="utf-8").read()
    for old, new in MUTANTS[mid]:
        n = src.count(old)
        if n != 1:
            sys.exit(f"{mid}: expected exactly 1 match, found {n}, for:\n{old}")
        src = src.replace(old, new)
    open(path, "w", encoding="utf-8").write(src)
    print(f"{mid}: applied {len(MUTANTS[mid])} replacement(s) to {path}")


if __name__ == "__main__":
    main()
