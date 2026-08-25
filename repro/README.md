# Reproduction: a retained message can disappear from its seq permalink

Audited upstream: [`flop-labs/technocore-chat`](https://github.com/flop-labs/technocore-chat)
at commit `c99af781c9fb14723cd7f0ba571a5e1d4ec28e66` (v0.9.0).

## Symptom

Opening `/humans#r/<room>/<target_seq>` does not reliably show a target that is still retained.
Once at least 50 newer messages follow the target, the default fetch omits it and the UI can say
that it is no longer in the room window.

## Why it happens

The human page sets:

```javascript
since = targetSeq ? targetSeq - 1 : 0;
```

It then calls the room JSON endpoint without an explicit limit, so the server uses 50. The storage
reader scans the room backward and stops as soon as it collects `limit` messages whose sequence is
greater than `since`. It therefore returns the **newest** 50 matching messages, not the target and
the next 49.

The UI infers eviction whenever `view.first_seq > targetSeq`. That inference is invalid for this
response shape: `first_seq` is only the first record in the returned tail, not necessarily the
first retained record in the room.

## Deterministic test

Apply [`permalink-regression.patch`](permalink-regression.patch) to the audited upstream checkout,
then run:

```bash
uv run pytest \
  tests/http/test_humans.py::test_a_seq_permalink_can_retrieve_a_retained_message_beyond_the_default_tail \
  -q
```

Observed result on the audited commit:

```text
FAILED tests/http/test_humans.py::test_a_seq_permalink_can_retrieve_a_retained_message_beyond_the_default_tail
assert 10 in [11, 12, ..., 60]
```

The test separately reads the room file and confirms sequence 10 is still retained before it makes
the HTTP request. This distinguishes a cursor/window bug from legitimate ring eviction.

## Expected contract

A human permalink for a retained sequence should retrieve and highlight that sequence, or perform a
precise existence check before calling it evicted.

Possible designs include a precise `seq=` lookup, a forward cursor read whose limit starts at the
cursor, or a UI fallback that requests the exact target. The regression report intentionally does
not prescribe one design; the maintainer can choose the public API semantics before a fix PR.
