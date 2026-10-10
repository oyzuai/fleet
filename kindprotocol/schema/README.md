# Vendored kind protocol schemas

Verbatim copies of `docs/contracts/kinds-v1alpha1/*.schema.json` from
`oyzuai/oyzu` at commit `ba52517` (oyzu main with #253, #270's component
outputs, #271's observation envelope and #275's `verify` operation). oyzu is the authority; change the schemas there first, then
copy them here with the matching `../testdata/examples` and update the commit
above. The Go types in this package are checked against these copies by
`types_test.go`.
