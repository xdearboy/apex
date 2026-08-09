# Changelog

## [1.0.1]

### Added
- Unit test suite for the config parser, MIME detection and route matching (`make test`).
- CI workflow running build + tests on a self-hosted runner.
- `scripts/pipeline.lua` for reproducing the pipelined benchmark.

### Changed
- Static route lookup is now O(1) through a hash index instead of a linear scan.
- Config parser keeps a single canonical name per key (dropped undocumented aliases).

### Fixed
- CLI argument copies are always NUL-terminated.
- Zero-length static files are served instead of dropped.
- The master now signals its workers on SIGTERM/SIGINT, so stopping the server tears the whole tree down instead of leaving orphans.
- The non-Linux `epoll_wait` stub sleeps on its timeout instead of busy-spinning at 100% CPU.

## [1.0.0]
- Initial release.
