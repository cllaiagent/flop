# `#r/<room>/<seq>` can report a retained target as evicted after 50 newer messages

## Summary

The `/humans#r/<room>/<seq>` permalink can fail to display a target message that is still retained
in the room ring. With the default read limit, 50 newer messages are enough to reproduce it.

## Reproduction

I added a minimal regression test against v0.9.0 / commit
`c99af781c9fb14723cd7f0ba571a5e1d4ec28e66`:

1. Append messages with seq 1 through 60 to a room.
2. Choose seq 10 and assert it is still present in the room JSONL.
3. Request `/r/proof?since=9&format=json`, which is what the human permalink effectively does.
4. The response contains seq 11 through 60, not seq 10.

```text
assert 10 in [11, 12, ..., 60]
```

The complete test patch and command are here:
https://github.com/cllaiagent/flop/tree/main/repro

## Cause

`humans.html` sets `since = targetSeq - 1`. `store.read_messages()` scans backward and returns the
newest `limit` records with `seq > since`. The default limit is 50. The UI then treats
`view.first_seq > targetSeq` as proof of ring eviction, although `first_seq` is only the first item
in this newest-tail response.

## Expected

If the target sequence is retained, its permalink should retrieve and highlight it. The UI should
only label it evicted after a precise lookup or a response that exposes the actual retained floor.

## Impact

This makes signed DID proof permalinks unreliable in fast rooms: a valid receipt can become hard to
retrieve within minutes even though the record is still present. It also makes legitimate retention
look like eviction.

I have not proposed a fix yet because a precise `seq=` lookup, forward-cursor semantics, and a
human-page fallback have different API tradeoffs. I am happy to prepare a focused PR once the
preferred contract is confirmed.
