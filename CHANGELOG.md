# Changelog

## [0.2.3](https://github.com/manojbajaj95/authsome/compare/authsome-v0.2.2...authsome-v0.2.3) (2026-05-01)


### Documentation

* add demo video to README ([36a9e18](https://github.com/manojbajaj95/authsome/commit/36a9e18a9a482baad9693f4b906226197866f70f))
* add demo video to README ([83ed25a](https://github.com/manojbajaj95/authsome/commit/83ed25a750f57e255268cee87e776c7d1d1f7961))

## [0.2.2](https://github.com/manojbajaj95/authsome/compare/authsome-v0.2.1...authsome-v0.2.2) (2026-04-29)


### Features

* add audit logging ([e130f30](https://github.com/manojbajaj95/authsome/commit/e130f309adfa8474671e9a4d2d00464e0ae1b225))
* add JSON output support to audit log command ([5ca2cd7](https://github.com/manojbajaj95/authsome/commit/5ca2cd78eee1c01b4510a42b33e56d1c11ccc942))
* expand whoami context ([2dead00](https://github.com/manojbajaj95/authsome/commit/2dead00b959f0f7b14958eede370d673792236ec))
* implement structured audit logging for CLI actions and proxy events ([e33b2d5](https://github.com/manojbajaj95/authsome/commit/e33b2d5834543fea75557efcfdf49ee6ce8297af))
* migrate --no-audit option from root command to common CLI options decorator ([93f4913](https://github.com/manojbajaj95/authsome/commit/93f4913c85c1815a649dedf8b991488ccfdac63b))
* render list output as table ([9ac6750](https://github.com/manojbajaj95/authsome/commit/9ac6750809133598b7e625a626f43f145201046d))
* show connections in inspect ([3c25b10](https://github.com/manojbajaj95/authsome/commit/3c25b10e2195835b2e9e664898b05dc4f8084063))
* show expiry in list output ([55aa376](https://github.com/manojbajaj95/authsome/commit/55aa3764f5aa0e334d278d09c697e29ade47bfe4))
* support regex proxy host urls ([a57a7de](https://github.com/manojbajaj95/authsome/commit/a57a7de0093c28fafa3805ef444f548e82e34d4c))


### Bug Fixes

* added support for regex check for API keys ([1da9d36](https://github.com/manojbajaj95/authsome/commit/1da9d36cd20cf3e85b6ec9098c9aea8b51b5e7bd))
* added support for regex check for API keys ([2d8022e](https://github.com/manojbajaj95/authsome/commit/2d8022eb112226e15d31ff50079d1975b25afe79))
* count active providers once ([8faf814](https://github.com/manojbajaj95/authsome/commit/8faf814800793ddc23911058fea5e52df4afd4b9))
* export all connections when provider omitted ([2b5ec34](https://github.com/manojbajaj95/authsome/commit/2b5ec34bf57c0b2990145bef43fce53a16d5ac08))
* export all connections when provider omitted ([622992f](https://github.com/manojbajaj95/authsome/commit/622992ffa7d1e53f877cf1b380fa9dfaa31333a8))
* harden auth proxy routing ([3c3a7ad](https://github.com/manojbajaj95/authsome/commit/3c3a7adcc9e578aaa37dde7c0fa683b5a0483022))
* harden auth proxy routing ([0fd02c6](https://github.com/manojbajaj95/authsome/commit/0fd02c6530c2d83cd35d65d41e1e2155fa60214c))
* keep proxy routing on default connections ([946576a](https://github.com/manojbajaj95/authsome/commit/946576a65229dd1252a8d1ed099349973ab65178))
* make login idempotent ([cb327fa](https://github.com/manojbajaj95/authsome/commit/cb327fa389853e71c06792db8896c2f31c96de94))
* prefer specific proxy route prefixes ([679fa77](https://github.com/manojbajaj95/authsome/commit/679fa77762d6a1293fd0d87f1d84bced59cfe471))
* preserve connected state on refresh fallback ([7c8ff9f](https://github.com/manojbajaj95/authsome/commit/7c8ff9fb5ba9f93ccca1d0454a91808dd4f5d4ce))
* respect requested login context ([2902059](https://github.com/manojbajaj95/authsome/commit/29020591e7f4fc851178371b0ea5243f8d2b2678))
* update audit log event type and add comprehensive unit tests for AuditLogger ([96b6999](https://github.com/manojbajaj95/authsome/commit/96b6999e2f162d88c7a10a006896bd7377564ebe))
* update openai export test fixture ([05bd00d](https://github.com/manojbajaj95/authsome/commit/05bd00dd7fcd864a6cd9c3b8b6c33ae27c8e6704))
* warn when refresh falls back to cached token ([7b1af48](https://github.com/manojbajaj95/authsome/commit/7b1af483583f4bf3c35b8a7010b2c2c63853bc82))

## [0.2.1](https://github.com/manojbajaj95/authsome/compare/authsome-v0.2.0...authsome-v0.2.1) (2026-04-28)


### Bug Fixes

* set connection host_url directly from resolved definition ([149b347](https://github.com/manojbajaj95/authsome/commit/149b34705a8d107d99352faac15671c4ed975112))

## [0.2.0](https://github.com/manojbajaj95/authsome/compare/authsome-v0.1.12...authsome-v0.2.0) (2026-04-28)


### ⚠ BREAKING CHANGES

* Complete internal restructuring. All public Python API has moved; CLI commands and flags are unchanged.

### Features

* add --verbose and --log-file options to CLI with loguru sinks ([0058f09](https://github.com/manojbajaj95/authsome/commit/0058f09cd643eeecde7e902c66db35b7c8b17695))
* add base URL templating support for providers ([ee172db](https://github.com/manojbajaj95/authsome/commit/ee172dbbeed1cc1761a9eb52901d22e39060cad8))
* add host_url support to auth connections and update proxy server to match based on resolved connection hosts ([73c5f72](https://github.com/manojbajaj95/authsome/commit/73c5f7259840b3e4d2caeb83e8b71c34590de602))
* add support for dynamic URL templating using {base_url} in provider definitions and CLI ([156ecf0](https://github.com/manojbajaj95/authsome/commit/156ecf0cbfb8f1fa282e73cd0df695e017353a9c))
* added support for docs in providers ([#85](https://github.com/manojbajaj95/authsome/issues/85)) ([f112275](https://github.com/manojbajaj95/authsome/commit/f11227528ae02b75eb70d5b07f5f50abc733d482))
* inject combined system and mitmproxy CA bundle into subprocess … ([#90](https://github.com/manojbajaj95/authsome/issues/90)) ([b5d042b](https://github.com/manojbajaj95/authsome/commit/b5d042b5c975ff51a06909279441c28016757837))
* silence authsome library logger by default (loguru best practice) ([2fe4c88](https://github.com/manojbajaj95/authsome/commit/2fe4c88d900eb7303e80907ea432849b25db332c))
* v0.2.0 — Vault + AuthLayer architecture, InputProvider, FlowResult ([bfd75ee](https://github.com/manojbajaj95/authsome/commit/bfd75eeae0e82f41e8e7bc5647aa55503aea08b5))


### Bug Fixes

* added support for posthiz device flow ([#81](https://github.com/manojbajaj95/authsome/issues/81)) ([9b9a485](https://github.com/manojbajaj95/authsome/commit/9b9a485460b6214e6434772ad2b2a44fae01057a))
* allow SQLite connection across threads for proxy auth injection ([536d78b](https://github.com/manojbajaj95/authsome/commit/536d78b81fb4500cd862f1e34c50b392f80d70e5)), closes [#76](https://github.com/manojbajaj95/authsome/issues/76)
* device flow ([#89](https://github.com/manojbajaj95/authsome/issues/89)) ([b596ee1](https://github.com/manojbajaj95/authsome/commit/b596ee1fafab57f846f722293ac3b6ee84062962))
* resolve ty type check errors in dcr_pkce and vault ([dc471d2](https://github.com/manojbajaj95/authsome/commit/dc471d2aac54191e1d3af7d6b7c3322560ba0813))


### Documentation

* Add documentation for current design and future direction ([7cc0e2c](https://github.com/manojbajaj95/authsome/commit/7cc0e2cc37cfa5fdae4d03e01efd31a2db3d6391))
* clarify authsome architecture direction ([e4eef7a](https://github.com/manojbajaj95/authsome/commit/e4eef7a7e22738211e7e6c81e84936d2b0f52f2b))
* Remove superpower ([f53f86c](https://github.com/manojbajaj95/authsome/commit/f53f86c1fec9b289864e2cb9e946e3238b01d5e1))

## [0.1.12](https://github.com/manojbajaj95/authsome/compare/authsome-v0.1.11...authsome-v0.1.12) (2026-04-24)


### Features

* merge develop to main ([#74](https://github.com/manojbajaj95/authsome/issues/74)) ([b88d476](https://github.com/manojbajaj95/authsome/commit/b88d476a77d71e872783874ae34c5af286720c70))


### Bug Fixes

* add host_url to bundled providers and update docs for current API ([4c756a0](https://github.com/manojbajaj95/authsome/commit/4c756a07b40b5cc20ce338dcf655948027414177))

## [0.1.11](https://github.com/manojbajaj95/authsome/compare/authsome-v0.1.10...authsome-v0.1.11) (2026-04-24)


### Features

* add configuration files for a few more OAuth2 providers ([#47](https://github.com/manojbajaj95/authsome/issues/47)) ([d587881](https://github.com/manojbajaj95/authsome/commit/d58788167b36c9f4df59d36cd912b140424f88e6))
* add proxy runner, RC publishing, and OAuth scope support ([#53](https://github.com/manojbajaj95/authsome/issues/53)) ([456d9bd](https://github.com/manojbajaj95/authsome/commit/456d9bd81128819c3281b8e88603f8d39d14cf64))


### Documentation

* overhaul authsome skill and consolidate reference docs ([#46](https://github.com/manojbajaj95/authsome/issues/46)) ([4b7dad4](https://github.com/manojbajaj95/authsome/commit/4b7dad4fef2c9eed5b951192c1080bdb8511e632))
* update authsome skill description with detailed capabilities, usage guidelines, and security policies ([#39](https://github.com/manojbajaj95/authsome/issues/39)) ([6c0bf89](https://github.com/manojbajaj95/authsome/commit/6c0bf890c9ff61ce7faabb2d57da36403e849751))

## [0.1.10](https://github.com/manojbajaj95/authsome/compare/authsome-v0.1.9...authsome-v0.1.10) (2026-04-22)


### Features

* added redirect url  in popup broswer Ui ([#36](https://github.com/manojbajaj95/authsome/issues/36)) ([b292017](https://github.com/manojbajaj95/authsome/commit/b29201776b06779e8486bbca53e3158d649bd915))
* added support for ashby ([#42](https://github.com/manojbajaj95/authsome/issues/42)) ([b37724e](https://github.com/manojbajaj95/authsome/commit/b37724e52cc88c729971a0b5d30a80abc03df5aa))
* replace reset flow with force flag and reorganize provider lifecycle commands into logout, revoke, and remove ([#32](https://github.com/manojbajaj95/authsome/issues/32)) ([66b0583](https://github.com/manojbajaj95/authsome/commit/66b0583c5be921f83aaf1ade633ea240e572ab4a))


### Documentation

* refresh readme ([#30](https://github.com/manojbajaj95/authsome/issues/30)) ([12cbfae](https://github.com/manojbajaj95/authsome/commit/12cbfae72f57be82431a3c5bf8d81b1377e3f442))

## [0.1.9](https://github.com/manojbajaj95/authsome/compare/authsome-v0.1.8...authsome-v0.1.9) (2026-04-21)


### Features

* add --version / -v flag to CLI ([#22](https://github.com/manojbajaj95/authsome/issues/22)) ([688aefb](https://github.com/manojbajaj95/authsome/commit/688aefba7238909e2ee0fbf111b66e66e7996f8a))
* Add github templates and CONTRIBUTING.md ([#20](https://github.com/manojbajaj95/authsome/issues/20)) ([98e0136](https://github.com/manojbajaj95/authsome/commit/98e01369459d1652c86df5d090cea15ed17fcef7))
* introduce secure browser-based bridge for sensitive input collection and remove CLI credential flags ([#28](https://github.com/manojbajaj95/authsome/issues/28)) ([8302b10](https://github.com/manojbajaj95/authsome/commit/8302b105bf9ef0ef00a1da396cb91f0c134d54ce))
* provider for klaviyo added ([#25](https://github.com/manojbajaj95/authsome/issues/25)) ([32038af](https://github.com/manojbajaj95/authsome/commit/32038afaa0cb5b209a26a1cdccf2aa0572f17f59))


### Bug Fixes

* redirect url explicitly mentioned in register provider ([#27](https://github.com/manojbajaj95/authsome/issues/27)) ([78b6eeb](https://github.com/manojbajaj95/authsome/commit/78b6eeb9e2cf5ecbbc727dbb54a16af5144584d0))
* use model_dump(mode="json") to serialize datetime fields in CLI ([#23](https://github.com/manojbajaj95/authsome/issues/23)) ([551239a](https://github.com/manojbajaj95/authsome/commit/551239a7b0e37b7c2ce4b89c946e9ec05339ae49))


### Documentation

* add portable authsome spec v1 ([#26](https://github.com/manojbajaj95/authsome/issues/26)) ([307aa2c](https://github.com/manojbajaj95/authsome/commit/307aa2c53721009b5d8a4fdc7ff1dfcf24cb89bf))

## [0.1.8](https://github.com/manojbajaj95/authsome/compare/authsome-v0.1.7...authsome-v0.1.8) (2026-04-21)


### Features

* add client record type to function docstring ([1be12a9](https://github.com/manojbajaj95/authsome/commit/1be12a93638f8f33ef907802878620f339956b2a))


### Bug Fixes

* Fix the store key bug ([72433e7](https://github.com/manojbajaj95/authsome/commit/72433e73c5f1c5593b7da6b5109c0409d87164b5))

## [0.1.7](https://github.com/manojbajaj95/authsome/compare/authsome-v0.1.6...authsome-v0.1.7) (2026-04-21)


### Features

* implement common_options decorator to support global CLI flags across all commands ([72d08ed](https://github.com/manojbajaj95/authsome/commit/72d08ed9345f760bc79a9cafaa05da2dea99992b))

## [0.1.6](https://github.com/manojbajaj95/authsome/compare/authsome-v0.1.5...authsome-v0.1.6) (2026-04-21)


### Bug Fixes

* update incorrect imports and fix README ([5ca9da0](https://github.com/manojbajaj95/authsome/commit/5ca9da0e8de2e71b438cfbe86080453910668e2d))

## [0.1.5](https://github.com/manojbajaj95/authsome/compare/authsome-v0.1.4...authsome-v0.1.5) (2026-04-21)


### Features

* add 29 new API provider configurations to bundled_providers ([#9](https://github.com/manojbajaj95/authsome/issues/9)) ([f9d8af4](https://github.com/manojbajaj95/authsome/commit/f9d8af4685b0b6339373f3bc204a9e826b83a5a5))
* enable CLI support for providing client credentials and API keys during login; and persist aforementioned credentials in profile store ([#10](https://github.com/manojbajaj95/authsome/issues/10)) ([7c960db](https://github.com/manojbajaj95/authsome/commit/7c960db5956fa5b30bfbd7d091671ef0a21a1084))


### Documentation

* rewrite README with agent-first positioning and badges ([94e090b](https://github.com/manojbajaj95/authsome/commit/94e090beaf2b40ab3b318bef2fd85ea668d09342))

## [0.1.4](https://github.com/agentr-labs/authsome/compare/authsome-v0.1.3...authsome-v0.1.4) (2026-04-20)


### Bug Fixes

* update command execution to use double-quoted strings and process in shell ([157edad](https://github.com/agentr-labs/authsome/commit/157edad42f253f98d6767ce524972f52c47cdb39))

## [0.1.3](https://github.com/agentr-labs/authsome/compare/authsome-v0.1.2...authsome-v0.1.3) (2026-04-20)


### Documentation

* add CLI reference and provider registration guides and update main skill documentation ([#5](https://github.com/agentr-labs/authsome/issues/5)) ([3d9d3b3](https://github.com/agentr-labs/authsome/commit/3d9d3b345e6db1f20245dc87a480266c089c580a))

## [0.1.2](https://github.com/universal-mcp/authsome/compare/authsome-v0.1.1...authsome-v0.1.2) (2026-04-17)


### Features

* Improve cli and test public pkce oauth flow ([27c8d50](https://github.com/universal-mcp/authsome/commit/27c8d50fac896d9d84e51042fc0b37cb07131eb3))
* Show separate custom and bundled providers; highlight connections spearately; tested pkce public oauth flow ([0924521](https://github.com/universal-mcp/authsome/commit/092452168fd0404eca4fc1afc96fdab7397974ab))

## [0.1.1](https://github.com/universal-mcp/authsome/compare/authsome-v0.1.0...authsome-v0.1.1) (2026-04-17)


### Features

* add Google and Okta providers and reformat GitHub provider scopes ([cc02780](https://github.com/universal-mcp/authsome/commit/cc0278017bf3c03c5315132eeb9657bbe2583f9e))
* add Linear provider and standardize PKCE callback port to 7999 while updating GitHub flow to standard PKCE ([15b1069](https://github.com/universal-mcp/authsome/commit/15b1069b8cdf2c3b9a7e2c6496aa88355d2bd053))
* implement CLI with full command set ([5724f3c](https://github.com/universal-mcp/authsome/commit/5724f3cd0768cb69c6c8cb55d94af7e69232d35d))
* implement initial version of core auth framework ([3c980b4](https://github.com/universal-mcp/authsome/commit/3c980b4b60b24cba4e53802a291f05f62a6e2929))
