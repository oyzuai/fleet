# fleet

The Oyzu pool manager and executor.

`fleet` runs the machines that execute Oyzu builds. It has two programs:

- [`cmd/manager`](cmd/manager/) is the pool manager. It keeps pools of build
  machines available and hands them work.
- [`cmd/executor`](cmd/executor/) is the executor. It runs on a build machine,
  runs the work it is assigned and reports results.

This repository is a skeleton. Code moves here from the Oyzu platform as the
remote builder design settles.

## License

`fleet` is licensed under the [Functional Source License, Version 1.1, ALv2
Future License](LICENSE.md) (FSL-1.1-ALv2). Each version converts to the Apache
License, Version 2.0 two years after it is made available.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Contributions require a signed
Contributor License Agreement.
