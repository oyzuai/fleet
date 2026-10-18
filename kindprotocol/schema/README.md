# Vendored kind protocol schemas

Verbatim copies of `docs/contracts/kinds-v1alpha1/*.schema.json` from
`oyzuai/oyzu` at commit `1c62d28` (oyzu main). That includes the optional
`connectors.named`, the `verify` operation, the strategy property
`stages_first_deployment` and the plan risk flag `availability` (oyzu #288,
`446bd4e`). oyzu is the authority; change the schemas there first, then copy
them here with the matching `../testdata/examples`, regenerate
`../testdata/canonical-schemas.sha256` (`sha256sum *.schema.json` in this
directory) and update the commit in `../testdata/canonical-source.txt` and above.
`drift_test.go` fails when these files, the digest list or the examples diverge,
and the Go types are checked against these copies by `types_test.go`.
