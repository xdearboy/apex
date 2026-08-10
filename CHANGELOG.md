# Changelog

## [1.1.0]

### Added
- `--reset-path` / `[server] reset_path`: connections hitting the given path are dropped with a TCP RST and no response, nginx `return 444` style. Off by default.

### Changed
- Peak RPS is sampled every second from the worker loop instead of only when `/stats` is polled, so it reflects real spikes.

### Security / Fixed
- Buffer incomplete requests across reads; a request split over multiple TCP segments is no longer lost (and no longer hangs the connection).
- Refuse non-GET request lines instead of walking into the body, closing off HTTP request smuggling.
- Accumulate pipelined responses in order so none are dropped when several arrive in one packet.
- Do not follow symlinks when indexing the static root, preventing reads outside it (e.g. a link to /etc/passwd) and symlink-loop recursion.
- Reap stalled TLS handshakes on a 10s deadline with a 5s sweep, blunting slowloris.
- Back off crash-looping workers (up to 30s) instead of respawning in a tight fork loop.
- Serve static files up to 128MB and log skips instead of silently returning 404.

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
