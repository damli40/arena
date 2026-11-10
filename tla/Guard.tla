-------------------------------- MODULE Guard --------------------------------
(***************************************************************************)
(* Arena's payment guard (contracts/guard/src/lib.rs) on near-tla.         *)
(*                                                                         *)
(* A hand-written model of the Rust code, not the code itself.  Line       *)
(* numbers below are lib.rs as of 2026-11-10 (420 lines).                  *)
(*                                                                         *)
(* Accounts: owner OW, agent AG, guard G, token FT, one receiver per       *)
(* invoice.  The token is near-tla's standard NEP-141 (module Tokens).     *)
(* Receipts, callbacks, promise results, forced failures and the 1-yocto   *)
(* deposit refunds are near-tla's NearAsync, unmodified.                   *)
(*                                                                         *)
(* Mode = "vulnerable_fixture" | "fixed"   (lib.rs:53-60, picked at init)  *)
(*                                                                         *)
(* Simplifications (evidence/tla-plan.md):                                 *)
(*  - invoices are approved at the start; approve_invoice is not a step;   *)
(*  - the ledger g.exp starts at the guard's real balance, as if the owner *)
(*    had called sync_ledger after funding; sync_ledger is not a step;     *)
(*  - transfers_started, confirmed_payouts, logs are not modelled;         *)
(*  - the reconcile waiting rule (RECONCILE_MIN_BLOCKS, lib.rs:44,         *)
(*    :246-253) is the ASSUMPTION WaitRule, not time: near-tla receipts    *)
(*    have no deadline, so a block count cannot bound when one runs.       *)
(*                                                                         *)
(* Added 2026-11-11 (evidence/proofs-adversarial-review-2026-11-11.md):    *)
(*  - Donate: TRUE adds one outside token holder DN who may send 100       *)
(*    tokens to the guard, once (review H1).  FALSE (every original check) *)
(*    leaves the model exactly as it was: DN does not exist.               *)
(*  - GhostRec: TRUE records which invoices on_reconcile set back to       *)
(*    Approved (ghost recApp), for one witness (review L3).  FALSE keeps   *)
(*    recApp = {} forever, so state counts are unchanged.                  *)
(***************************************************************************)
EXTENDS Tokens

CONSTANTS
    Mode,        \* "vulnerable_fixture" | "fixed"
    NInv,        \* number of invoices
    MaxPay,      \* number of pay transactions (any invoice)
    MaxRec,      \* number of reconcile transactions (any invoice)
    WaitRule,    \* TRUE: reconcile runs only after the pending pay settled
    Donate,      \* TRUE: an outside account may send 100 tokens to the guard once (review H1)
    GhostRec     \* TRUE: track recApp for Wit_repaid_after_reconcile (review L3)

VARIABLES
    g,           \* the guard's own state, see GInit
    cbFailed,    \* ghost: invoices whose on_transfer was forced to fail, not yet reconciled
    npay, nrec, ntx,
    ndon,        \* outside transfers into the guard so far (stays 0 unless Donate)
    recApp       \* ghost: invoices on_reconcile set back to Approved (stays {} unless GhostRec)

guardVars == <<g, cbFailed, npay, nrec, ntx, ndon, recApp>>
vars == <<platformVars, tk, guardVars>>

OW == "owner"
AG == "agent"
G  == "guard"
FT == "ft"
Inv  == 1..NInv
Rcv  == [i \in Inv |-> IF i = 1 THEN "sam" ELSE "sam2"]   \* one receiver per invoice
Amt  == [i \in Inv |-> 100]                                \* 100 test tokens, as on testnet
Fund == 1000                                               \* guard's token balance at start
NearG == MaxPay                                            \* guard's yoctoNEAR: 1 per ft_transfer
DN == "donor"                                              \* outside token holder (Donate only)
Others == IF Donate THEN {DN} ELSE {}
DonAmt == 100                                              \* what DN holds and sends: one invoice's amount
Holders == {G} \cup Others \cup {Rcv[i] : i \in Inv}
Accts == {OW, AG, G, FT} \cup Others \cup {Rcv[i] : i \in Inv}
TxIds == 1..(MaxPay + MaxRec + (IF Donate THEN 1 ELSE 0))
NearTotal == NearG + (IF Donate THEN 1 ELSE 0)             \* DN holds 1 yocto for its ft_transfer deposit

(* ---- values for the platform / token constants (bound in the .cfg) ----- *)
PFloor      == [a \in Accts |-> 0]
PTokHolders == [t \in {FT} |-> Holders]
PTokMin     == [t \in {FT} |-> 1]
PTokDev     == [t \in {FT} |-> {}]
PTokReserve == [t \in {FT} |-> 0]
NoGasTable  == [x \in {} |-> 0]
FalseDef    == FALSE                                    \* TrackSigner <- FalseDef: the guard checks predecessors, never the signer

(* ---- the guard ----------------------------------------------------------- *)
\* g.st     [Inv -> {"Approved","Pending","Paid"}]   Invoice.status (lib.rs:64-71)
\* g.pend   pending_count   (lib.rs:109)
\* g.ep     epoch           (lib.rs:110)
\* g.exp    expected_balance, synced at start (lib.rs:108)
\* g.ptx    ghost for WaitRule: the transaction that last made invoice i Pending
GInit == [st |-> [i \in Inv |-> "Approved"], pend |-> 0, ep |-> 0, exp |-> Fund,
          ptx |-> [i \in Inv |-> 0]]

O0 == Outcome({}, {}, RVal(EMPTY), 0, 0)
Err(msg) == <<OErr(O0, msg), g>>

\* pay(id), lib.rs:169-211.  A handler returns <<outcome, new g>>.
H_pay(r) ==
    LET i == r.a.cx[1]
        \* lib.rs:202-205: ft_transfer(receiver, amount) with 1 yocto attached ...
        xf == Rcpt(nid, r.tx, FT, G, "ft_transfer",
                   [FtArgs(Rcv[i], Amt[i], "") EXCEPT !.cx = <<i>>], TokYocto, G, nid + 1)
        \* ... .then(on_transfer(id)), lib.rs:206-210
        cb == Rcpt(nid + 1, r.tx, G, G, "on_transfer", CxArgs(i), 0, G, r.cb)
        O  == Outcome({xf}, {cb}, RProm, TokYocto, 2)
    IN CASE r.fr # AG                         -> Err("agent only")                 \* lib.rs:170
         [] g.st[i] = "Paid"                  -> Err("invoice already paid")       \* lib.rs:176
         [] Mode = "fixed" /\ g.st[i] = "Pending"
                                              -> Err("payment already in flight")  \* lib.rs:184
         [] Mode = "fixed"                    ->                                   \* lib.rs:186-187, :197-200
              <<O, [g EXCEPT !.st[i] = "Pending", !.pend = @ + 1, !.ep = @ + 1, !.ptx[i] = r.tx]>>
         [] OTHER                             -> <<O, g>>                          \* lib.rs:179-182: BUG, nothing recorded

\* on_transfer(id), lib.rs:214-226; #[private] (lib.rs:214).
\* transfer_confirmed (lib.rs:116-127): exactly one promise result, Ok or TooLong = confirmed,
\* Failed = not.  ft_transfer returns () (EMPTY), so "confirmed" = the result is not Failed.
H_on_transfer(r) ==
    LET i     == r.a.cx[1]
        ok    == ~IsFailed(r.res)
        O     == Outcome({}, {}, RVal(IF ok THEN 1 ELSE 0), 0, 0)
        wasP  == g.st[i] = "Pending"                                              \* lib.rs:393
    IN IF r.fr # G THEN Err("Method on_transfer is private")
       ELSE IF Mode = "vulnerable_fixture"
       \* on_transfer_fixture, lib.rs:361-384: Paid on success, nothing on failure
       THEN <<O, IF ok THEN [g EXCEPT !.st[i] = "Paid"] ELSE g>>
       \* on_transfer_fixed, lib.rs:388-419
       ELSE <<O, [g EXCEPT
                    !.st[i] = IF ok THEN "Paid"                                   \* lib.rs:404
                              ELSE IF wasP THEN "Approved" ELSE @,                \* lib.rs:409-412
                    !.exp   = IF ok THEN TMax(@ - Amt[i], 0) ELSE @,              \* lib.rs:405-408
                    !.pend  = IF wasP THEN TMax(@ - 1, 0) ELSE @,                 \* lib.rs:413-415
                    !.ep    = @ + 1]>>                                            \* lib.rs:416

\* reconcile(id), lib.rs:230-262.
H_reconcile(r) ==
    LET i  == r.a.cx[1]
        bv == Rcpt(nid, r.tx, FT, G, "ft_balance_of", [TA0 EXCEPT !.rc = G], 0, G, nid + 1)  \* lib.rs:254-256
        cb == Rcpt(nid + 1, r.tx, G, G, "on_reconcile", [TA0 EXCEPT !.cx = <<i, g.ep>>], 0, G, r.cb)  \* lib.rs:257-260
    IN CASE r.fr # OW                   -> Err("owner only")                            \* lib.rs:231
         [] Mode # "fixed"              -> Err("reconcile exists only in fixed mode")   \* lib.rs:232
         [] g.st[i] # "Pending"         -> Err("invoice is not Pending")                \* lib.rs:238
         [] g.pend # 1                  -> Err("ambiguous")                             \* lib.rs:239-245
         \* lib.rs:246-253, as an assumption: the pay that made i Pending has settled
         [] WaitRule /\ ~TxSettled(g.ptx[i]) -> Err("too early")
         [] OTHER                       -> <<Outcome({bv}, {cb}, RProm, 0, 2), g>>

\* on_reconcile(id, epoch_at_start), lib.rs:266-306; #[private] (lib.rs:266).
H_on_reconcile(r) ==
    LET i   == r.a.cx[1]
        e0  == r.a.cx[2]
        amt == Amt[i]
        act == r.res.v
        O   == Outcome({}, {}, RVal(0), 0, 0)
    IN CASE r.fr # G                     -> Err("Method on_reconcile is private")
         [] g.ep # e0                    -> Err("state changed while the balance was being read") \* lib.rs:273-276
         [] ~IsNum(r.res)                -> Err("balance read failed")                 \* lib.rs:271, :277
         [] g.st[i] # "Pending"          -> Err("invoice is no longer Pending")       \* lib.rs:280
         \* "the money left": actual = expected - amount (checked_sub), lib.rs:282-289
         [] g.exp >= amt /\ act = g.exp - amt ->
              <<O, [g EXCEPT !.st[i] = "Paid", !.exp = g.exp - amt,
                             !.pend = TMax(@ - 1, 0), !.ep = @ + 1]>>                \* lib.rs:300-301
         \* "the money is still here", lib.rs:290-293
         [] act = g.exp ->
              <<O, [g EXCEPT !.st[i] = "Approved", !.pend = TMax(@ - 1, 0), !.ep = @ + 1]>>
         [] OTHER                        -> Err("balance matches neither story")      \* lib.rs:294-298

RunG(r) ==
    LET p == CASE r.m = "pay"          -> H_pay(r)
               [] r.m = "on_transfer"  -> H_on_transfer(r)
               [] r.m = "reconcile"    -> H_reconcile(r)
               [] r.m = "on_reconcile" -> H_on_reconcile(r)
               [] OTHER                -> Err("method not found")
        O == p[1] IN
    /\ Exec(r, O)
    /\ g' = IF Ok(r, O) THEN p[2] ELSE g
    /\ cbFailed' = IF Ok(r, O) /\ r.m = "on_reconcile" THEN cbFailed \ {r.a.cx[1]} ELSE cbFailed
    /\ recApp' = IF GhostRec /\ Ok(r, O) /\ r.m = "on_reconcile" /\ p[2].st[r.a.cx[1]] = "Approved"
                 THEN recApp \cup {r.a.cx[1]} ELSE recApp
    /\ UNCHANGED <<tk, npay, nrec, ntx, ndon>>

RunTok(r) ==
    \E ch \in TokChoices(r) :
        LET O == TokHandle(r, ch) IN TokStep(r, O) /\ UNCHANGED guardVars

Step(r) ==
    CASE IsPlatformRcpt(r) -> PlatformStep(r) /\ UNCHANGED <<tk, guardVars>>  \* deposit refunds
      [] IsTokRcpt(r)      -> RunTok(r)
      [] OTHER             -> RunG(r)

(* ---- transactions --------------------------------------------------------- *)
\* The agent signs pay(i); any invoice, any time, up to MaxPay times.
PayTx ==
    /\ npay < MaxPay
    /\ \E i \in Inv :
         Submit(WithGas(Rcpt(nid, ntx + 1, G, AG, "pay", CxArgs(i), 0, AG, 0), 0))
    /\ npay' = npay + 1 /\ ntx' = ntx + 1
    /\ UNCHANGED <<tk, g, cbFailed, nrec, ndon, recApp>>

\* The owner signs reconcile(i); any invoice, any time, up to MaxRec times.
RecTx ==
    /\ nrec < MaxRec
    /\ \E i \in Inv :
         Submit(WithGas(Rcpt(nid, ntx + 1, G, OW, "reconcile", CxArgs(i), 0, OW, 0), 0))
    /\ nrec' = nrec + 1 /\ ntx' = ntx + 1
    /\ UNCHANGED <<tk, g, cbFailed, npay, ndon, recApp>>

\* A forced failure (MayFail / MaxFails): a panic, or out of gas, with no writes.
\* For on_transfer this is the fault-injection panic (lib.rs:216-219).
Fault ==
    \E r \in Runnable :
        /\ ForcedFail(r)
        /\ cbFailed' = IF r.m = "on_transfer" THEN cbFailed \cup {r.a.cx[1]} ELSE cbFailed
        /\ UNCHANGED <<tk, g, npay, nrec, ntx, ndon, recApp>>

Init ==
    /\ PlatformInit([a \in Accts |-> IF a = G THEN NearG ELSE IF a = DN THEN 1 ELSE 0], TxIds)
    /\ tk = [t \in {FT} |-> Ledger([h \in Holders |-> IF h = G THEN Fund
                                                      ELSE IF h = DN THEN DonAmt ELSE 0], Holders)]
    /\ g = GInit
    /\ cbFailed = {}
    /\ npay = 0 /\ nrec = 0 /\ ntx = 0
    /\ ndon = 0 /\ recApp = {}

\* Added 2026-11-11 (review H1). An outside account (the owner topping the guard up, or
\* anyone else) calls the token's ft_transfer(guard, 100), once, at any time. The guard
\* is not told: its ledger g.exp does not move. Only enabled when Donate = TRUE.
DonTx ==
    /\ Donate /\ ndon < 1
    /\ Submit(WithGas(Rcpt(nid, ntx + 1, FT, DN, "ft_transfer", FtArgs(G, DonAmt, ""), TokYocto, DN, 0), 0))
    /\ ndon' = ndon + 1 /\ ntx' = ntx + 1
    /\ UNCHANGED <<tk, g, cbFailed, npay, nrec, recApp>>

RunReceipt == \E r \in Runnable : Step(r)
Next == PayTx \/ RecTx \/ RunReceipt \/ Fault \/ DonTx
Spec == Init /\ [][Next]_vars

\* Trace filter for the run vuln_testnet_order (an ACTION_CONSTRAINT, not a property):
\* no transfer runs until every pay has been signed and has run its check, so both
\* checks come first, as on testnet, where both ran in one block
\* (evidence/testnet-2026-11-09.md).
TestnetOrder == (npay < MaxPay \/ \E r \in rq : r.m = "pay")
                    => ~(\E r \in rq : r.m = "ft_transfer" /\ r \notin rq')

(* ---- the property (evidence/tla-plan.md) ----------------------------------- *)
Received(i) == tk[FT].bal[Rcv[i]]

\* An invoice is never paid more than its amount (read from the token's ledger).
NoOverpay == \A i \in Inv : Received(i) <= Amt[i]

\* A failed transfer leaves it payable: once nothing is in flight, an invoice whose
\* receiver got nothing is Approved, or Pending only because its callback died.
FailedStaysPayable ==
    Idle => \A i \in Inv :
        Received(i) = 0 =>
            \/ g.st[i] = "Approved"
            \/ (g.st[i] = "Pending" /\ i \in cbFailed)

\* near-tla's library sanity checks.
Sane == NearConserved(NearTotal) /\ TokSupplyOK /\ TokTypeOK /\ NoOrphans

(* ---- witnesses: each must be REACHED (TLC reports Wit_x violated) ---------- *)
Wit_paid               == ~(\E i \in Inv : Received(i) = Amt[i])
Wit_race_setup         == ~(\E i \in Inv : g.st[i] = "Approved" /\
                               Cardinality({r \in Runnable : r.m = "pay" /\ r.a.cx[1] = i}) = 2)
Wit_refused_in_flight  == ~(\E r \in Runnable : r.m = "pay" /\ g.st[r.a.cx[1]] = "Pending")
Wit_repaid_after_failed_transfer ==
                          ~(fails = 1 /\ cbFailed = {} /\ \E i \in Inv : Received(i) = Amt[i])
Wit_stuck_pending      == ~(Idle /\ \E i \in cbFailed : g.st[i] = "Pending")
Wit_reconcile_says_paid ==
    ~(\E r \in Runnable : r.m = "on_reconcile" /\ IsNum(r.res) /\ g.ep = r.a.cx[2]
                          /\ g.st[r.a.cx[1]] = "Pending" /\ r.res.v = g.exp - Amt[r.a.cx[1]])
Wit_reconcile_says_approved ==
    ~(\E r \in Runnable : r.m = "on_reconcile" /\ IsNum(r.res) /\ g.ep = r.a.cx[2]
                          /\ g.st[r.a.cx[1]] = "Pending" /\ r.res.v = g.exp)
Wit_reconcile_ambiguous ==
    ~(\E r \in Runnable : r.m = "reconcile" /\ g.pend = 2)
\* Added 2026-11-11 (review L3): the whole recovery path completes. on_reconcile set the
\* invoice back to Approved, it was paid again, and the receiver holds exactly the amount.
\* Needs GhostRec = TRUE (recApp is always {} otherwise, so this cannot be reached).
Wit_repaid_after_reconcile ==
    ~(\E i \in recApp : Received(i) = Amt[i])
=============================================================================
