// Copied from tools/lookup/suites.mjs by site/build-lookup.mjs. Do not edit here.
// The one place that says what each Arena test suite means for a wallet.
//
// `setting` answers: "does this result depend on how the guard was set up, and can the lookup read that?"
//   { kind: "mode", value: "<m>" }  the result only applies to a guard whose get_mode() returns "<m>".
//                                    The lookup reads get_mode() and counts the result only on a match.
//   { kind: "unreadable", what }     the result depends on a setup choice this lookup cannot read
//                                    (a policy file, init arguments). Never counted as a pass.
// A suite that is not listed here is treated like "unreadable": shown, never counted as a pass.
export const SUITES = {
  "race-double-pay:mode=vulnerable_fixture": {
    test: "double-pay race test",
    what: "two pays for one invoice, sent to overlap on testnet",
    setting: { kind: "mode", value: "vulnerable_fixture" },
  },
  "race-double-pay:mode=fixed": {
    test: "double-pay race test",
    what: "two pays for one invoice, sent to overlap on testnet",
    setting: { kind: "mode", value: "fixed" },
  },
  // Suite name has no mode in it, but the receipt label and evidence say it was run on mode=fixed only.
  "proof-pay-race-inductive": {
    test: "pay-race proof run",
    what: "proofs on the guard source and model for the pay/callback race (not a claim that no invoice can ever be paid twice)",
    setting: { kind: "mode", value: "fixed" },
  },
  "injection-scripted": {
    test: "fooled-agent test (broad policy)",
    what: "a scripted agent fooled into paying the wrong party",
    setting: { kind: "unreadable", what: "the spending policy the vault was set up with" },
  },
  "injection-scripted-narrow": {
    test: "fooled-agent test (narrow policy)",
    what: "a scripted agent fooled into paying the wrong party",
    setting: { kind: "unreadable", what: "the spending policy the vault was set up with" },
  },
  "claims-coverage": {
    test: "claims-coverage test",
    what: "each claim the guard makes, tested on a local sandbox",
    setting: { kind: "unreadable", what: "the setup arguments the guard was started with" },
  },
};

// Receipts on chain do not store the transaction that published them. This table maps each published
// receipt to its publish transaction, copied from evidence/receipts-testnet-2026-11-1{0,1}-publish.log.
// Key: `${guard_code_hash}|${suite}|${published_at}` (published_at is the exact on-chain timestamp, so an
// entry can never be attached to a different receipt). Missing entry => the answer links the contract page.
export const PUBLISH_TXS = {
  "fcce82bf9bad46ae9c7d85952470faf664aa5905bea2df7111ab97601b773372|race-double-pay:mode=vulnerable_fixture|1794269839585340827": "Bd8RrTiWS3Pc6XxS8iRcRpZoio8HZPjhw3ZyYDhj89RC",
  "fcce82bf9bad46ae9c7d85952470faf664aa5905bea2df7111ab97601b773372|race-double-pay:mode=fixed|1794269841987566904": "76eNYghQggAzy6ycX8srDCeL76KWFkBUjRh8s8LFzHoW",
  "52a40f3200e313c1def01c3dabe85cec9669d69cee575d93560360b36598c7b1|injection-scripted|1794269843807446195": "8bKFEjxJeUMUAVvF4JRwzB9sJAbv7174J2KKmfL2TYpM",
  "52a40f3200e313c1def01c3dabe85cec9669d69cee575d93560360b36598c7b1|injection-scripted-narrow|1794269846260122234": "gx5NoMTU82jJasa5nrkXQDJskqeGMujWyMUvaHnB3Uh",
  "27c178e572dbd90a746f6078e8d98266a6e6059272cfc0d9cbc75fab5c50d6c2|claims-coverage|1794269848647683954": "HmY3cpSc4x9np6s63cXEwq2Tdm76wiEZvGBEovZXr5gL",
  "b44e991a469b510fbb871504be9c614dba8939aedb8223131852ce58ccd0dee6|claims-coverage|1794269850578711348": "AYnru69PzpuSj6CQG5ViEVsQYepHdzU9oa2gRTNNrX7o",
  "dc99ccdfc57ab5dc57a6d5aebdcf1571dbe74ed68e7e5a746002b7bc25ad7e46|claims-coverage|1794269852280423701": "7pNUNdowfj7VgEueDwJcXVxb9QVVv8C3xVH95n8vgnAY",
  "0382023bed1208667d8ef56af7223c2a46d8fa069caf1414c2aa84c08b48510e|race-double-pay:mode=vulnerable_fixture|1794327022853541570": "BFhjD3wrZafHa3ZJTsoAv5mtkg4eSnWKb7phxv6W2ypS",
  "0382023bed1208667d8ef56af7223c2a46d8fa069caf1414c2aa84c08b48510e|race-double-pay:mode=fixed|1794327024705760594": "92oZhohuHcH73HBDUQfp55ApXMnFMMEUoUVRKmoht949",
  "52a40f3200e313c1def01c3dabe85cec9669d69cee575d93560360b36598c7b1|injection-scripted|1794327026404391118": "ALorMpxwMBYxKuBbMsvNGxHMAzMY2atbLc37vA1qV7BG",
  "52a40f3200e313c1def01c3dabe85cec9669d69cee575d93560360b36598c7b1|injection-scripted-narrow|1794327028795450000": "9JGV6KUQW3zJzXs9ZyXs1Y2xHgHV9peKs6YQ2gPxG4qH",
  "27c178e572dbd90a746f6078e8d98266a6e6059272cfc0d9cbc75fab5c50d6c2|claims-coverage|1794327031394941742": "AvmByZzRNQWFzSJLVxBHzVRdCWF5Z2Mjan81Y8wcqXQv",
  "b44e991a469b510fbb871504be9c614dba8939aedb8223131852ce58ccd0dee6|claims-coverage|1794327033696305992": "4KQxfUJ3AbUJVs2HS5xm3huaN9whxeh2LZcp9J3Eey56",
  "dc99ccdfc57ab5dc57a6d5aebdcf1571dbe74ed68e7e5a746002b7bc25ad7e46|claims-coverage|1794327035506571786": "8c2WYcsod9BzuXJT5D6jpLPJtmxRs93PmKnhNcqL2K4f",
  "0382023bed1208667d8ef56af7223c2a46d8fa069caf1414c2aa84c08b48510e|proof-pay-race-inductive|1794327037932266177": "Gc13udsQVQJ4Yn1vX5wRLgdiWeejvHZ3ivW3STyAAqvd",
};
