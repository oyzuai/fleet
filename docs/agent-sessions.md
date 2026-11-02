# Agent sessions

Claude's SessionStart hook runs `.claude/load-context.sh`. With authenticated
access to `oyzuai/context`, it clones that repository's main branch into a
sibling `context` directory, or fast-forwards an existing main checkout.
It prints the committed constitution, generated index and `context commit <sha>`.
The private repository's contents stay outside fleet.

If access or refresh fails, the hook emits one warning and lets the session
continue. Contributors without private access can work on fleet normally.
An existing sibling must be a main checkout of the expected repository; keep
context implementation branches elsewhere. The hook reads a committed snapshot,
so uncommitted edits are not loaded. The hook has a 60-second host timeout.
