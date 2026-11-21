# Changelog

## 0.1.0 (2026-11-21)


### Features

* add connections, settings, keys, freshness and administration events ([#9](https://github.com/sinemacula/laravel-sso/issues/9)) ([0e741ff](https://github.com/sinemacula/laravel-sso/commit/0e741ff1b541da3f017078dabde41284268ce031))
* add domain claims, verification, rechecks and enforcement ([#10](https://github.com/sinemacula/laravel-sso/issues/10)) ([61172de](https://github.com/sinemacula/laravel-sso/commit/61172deea8b9207aeeaf87db6b3e0eb7b5e0d98f))
* add linking, provisioning, re-authentication and evidence ([#14](https://github.com/sinemacula/laravel-sso/issues/14)) ([4f4123d](https://github.com/sinemacula/laravel-sso/commit/4f4123d090c965c744a7a70dfaf1c81e552742be))
* add links, authorisation requests, discovery, completion and handoff codes ([#11](https://github.com/sinemacula/laravel-sso/issues/11)) ([72b69de](https://github.com/sinemacula/laravel-sso/commit/72b69de4305bc7af18d4966ab3b925d24d854240))
* add pruning, scheduled checks and operational hardening ([#18](https://github.com/sinemacula/laravel-sso/issues/18)) ([43b8240](https://github.com/sinemacula/laravel-sso/commit/43b8240d345f8cb50d7b1d0ddc050f003aadaa86))
* add the OpenID Connect driver ([#13](https://github.com/sinemacula/laravel-sso/issues/13)) ([5c9d54f](https://github.com/sinemacula/laravel-sso/commit/5c9d54fa88731491a868868ced23dc1092fb8064))
* add the package foundations ([#7](https://github.com/sinemacula/laravel-sso/issues/7)) ([3046a52](https://github.com/sinemacula/laravel-sso/commit/3046a528329f6f7be24d28773935ca2b08bafd1f))
* add the SAML 2.0 driver ([#12](https://github.com/sinemacula/laravel-sso/issues/12)) ([0b985c7](https://github.com/sinemacula/laravel-sso/commit/0b985c7c95d828871fad4c893d84daa4b5c8c252))
* ask a reauthentication start about the application it is started for ([#41](https://github.com/sinemacula/laravel-sso/issues/41)) ([38f6372](https://github.com/sinemacula/laravel-sso/commit/38f6372b8cac3cc95b9a22b8a44aec5f30c60767))
* ask freshness under each change's locks ([#49](https://github.com/sinemacula/laravel-sso/issues/49)) ([d785407](https://github.com/sinemacula/laravel-sso/commit/d785407a7d87a956424a0109af8b4e2230f20723))
* bind each seam's default under a private key the contract forwards to ([#39](https://github.com/sinemacula/laravel-sso/issues/39)) ([2406b40](https://github.com/sinemacula/laravel-sso/commit/2406b40dd80da6a7520343436f7ed37251cecc4d))
* carry the link id on every link lifecycle event ([#63](https://github.com/sinemacula/laravel-sso/issues/63)) ([e6da503](https://github.com/sinemacula/laravel-sso/commit/e6da503789c34fa00be514f1cff029d8d4c97c2d))
* change the policy version when a satisfying connection changes ([#47](https://github.com/sinemacula/laravel-sso/issues/47)) ([6fb41f5](https://github.com/sinemacula/laravel-sso/commit/6fb41f5d3c88fa8f274a66801fa6c7edda642faf))
* check the XML element registries and pass the repository to Features ([#40](https://github.com/sinemacula/laravel-sso/issues/40)) ([57264fb](https://github.com/sinemacula/laravel-sso/commit/57264fb98fe56f57f3fe430b2ffae69a6521321f))
* close the requirements with session context, guides and a verified matrix ([#20](https://github.com/sinemacula/laravel-sso/issues/20)) ([51b2b32](https://github.com/sinemacula/laravel-sso/commit/51b2b326f9650b97b49da720ee5c3b80d56f0207))
* export the context keys with their types and the administrative operation names ([#46](https://github.com/sinemacula/laravel-sso/issues/46)) ([2f6736d](https://github.com/sinemacula/laravel-sso/commit/2f6736d3106d23dbd2928a71aa0cb82d005a9a32))
* fail sso:check where pcre refuses saml strings above u+00ff ([#106](https://github.com/sinemacula/laravel-sso/issues/106)) ([61b4ef9](https://github.com/sinemacula/laravel-sso/commit/61b4ef91b40bc7a1739562617d6d730f3d5edc6d))
* give freshness and link confirmation the caller and its session ([#29](https://github.com/sinemacula/laravel-sso/issues/29)) ([e9f002d](https://github.com/sinemacula/laravel-sso/commit/e9f002d68da59bfed50a993bcd20244785765ccf))
* let a provisioning listener retry its whole transaction ([#38](https://github.com/sinemacula/laravel-sso/issues/38)) ([ec5678c](https://github.com/sinemacula/laravel-sso/commit/ec5678c9eeeab82d98b283c3eb6d347f8893855a))
* let composing packages add configuration checks ([#23](https://github.com/sinemacula/laravel-sso/issues/23)) ([16ed171](https://github.com/sinemacula/laravel-sso/commit/16ed17128a6f184c807040c5362b49bd1a0fb84c))
* let the exemption gate judge without reporting ([#51](https://github.com/sinemacula/laravel-sso/issues/51)) ([b9106d5](https://github.com/sinemacula/laravel-sso/commit/b9106d5e380b6c96d9cccf82a1b53df2c13fac6b))
* retry a standalone redemption's transaction on concurrency failures ([#37](https://github.com/sinemacula/laravel-sso/issues/37)) ([be077a0](https://github.com/sinemacula/laravel-sso/commit/be077a0a46c47a89835619cb0ecb48c18de19d82))
* ship contract kits for the seams a binder implements ([#50](https://github.com/sinemacula/laravel-sso/issues/50)) ([c2e5e93](https://github.com/sinemacula/laravel-sso/commit/c2e5e936e4233cd619038b09b010840cee80ed1b))
* take the client as a plain value in every core action ([#27](https://github.com/sinemacula/laravel-sso/issues/27)) ([b82516c](https://github.com/sinemacula/laravel-sso/commit/b82516c3994395e812208bcab3591bc80eadc4ab))
* widen several identities in one call ([#35](https://github.com/sinemacula/laravel-sso/issues/35)) ([6afcfd9](https://github.com/sinemacula/laravel-sso/commit/6afcfd998df0c219bbf702d1be74cc9f2eba1f36))


### Bug Fixes

* accept several encrypted keys on a saml assertion ([#115](https://github.com/sinemacula/laravel-sso/issues/115)) ([2bc5442](https://github.com/sinemacula/laravel-sso/commit/2bc54427ddc7507c55536e0187812df49b1c1111))
* clear the qlty findings and drop configuration the shared source provides ([#34](https://github.com/sinemacula/laravel-sso/issues/34)) ([b6706e2](https://github.com/sinemacula/laravel-sso/commit/b6706e22645dcc92e328d28764aea2ecbeaaf4cf))
* decrypt with the next encryption key ([#104](https://github.com/sinemacula/laravel-sso/issues/104)) ([6aedd1d](https://github.com/sinemacula/laravel-sso/commit/6aedd1d6aef01641a798d384d8ff7566731e3c3d))
* hold a raw context blank after trimming as none ([#66](https://github.com/sinemacula/laravel-sso/issues/66)) ([963e3d9](https://github.com/sinemacula/laravel-sso/commit/963e3d961f2a4d40fecd8cab1869568ead5f3c8f))
* hold the saml authn instant whenever the request forced authentication ([#110](https://github.com/sinemacula/laravel-sso/issues/110)) ([92a963a](https://github.com/sinemacula/laravel-sso/commit/92a963ad325122a4aea605f226de5ed32ab89a89))
* implement the SAML library's new inflate size limit ([#25](https://github.com/sinemacula/laravel-sso/issues/25)) ([481eb93](https://github.com/sinemacula/laravel-sso/commit/481eb939f9dbd2f6d69023875ef705bba25e3c9a))
* keep after-commit events when a commit callback begins a transaction ([#36](https://github.com/sinemacula/laravel-sso/issues/36)) ([9dde907](https://github.com/sinemacula/laravel-sso/commit/9dde907fb2918e647edbe7564b925e0c98912ee9))
* keep namespace declarations when re-rooting a signed saml element ([#117](https://github.com/sinemacula/laravel-sso/issues/117)) ([0a4f15c](https://github.com/sinemacula/laravel-sso/commit/0a4f15c62fa347354e90f0de500be4821d9b99b4))
* let a scope widening spare several tenants ([#61](https://github.com/sinemacula/laravel-sso/issues/61)) ([72738f1](https://github.com/sinemacula/laravel-sso/commit/72738f11c8bff3185145779b9e71c911938e5ce5))
* lock the whole inheritance path when judging an inherited rule ([#56](https://github.com/sinemacula/laravel-sso/issues/56)) ([3b4c998](https://github.com/sinemacula/laravel-sso/commit/3b4c99875b84085738c98c9aae600a4b0ba693d6))
* make LinkCandidatesChanged a serialisation failure Laravel retries ([#45](https://github.com/sinemacula/laravel-sso/issues/45)) ([39fe92a](https://github.com/sinemacula/laravel-sso/commit/39fe92aab09894f6b3aea0266556d945e00a460c))
* raise a connection version on key and domain claim writes ([#108](https://github.com/sinemacula/laravel-sso/issues/108)) ([2a5cbb3](https://github.com/sinemacula/laravel-sso/commit/2a5cbb35fb35a86f62b6d08f47c06c2278ab2f33))
* refuse whitespace in an evidence policy's context classes ([#67](https://github.com/sinemacula/laravel-sso/issues/67)) ([a545a72](https://github.com/sinemacula/laravel-sso/commit/a545a72a1d1ae6efd36f23c10c81105df1c65a48))
* renew an expired single-use key with one update ([#112](https://github.com/sinemacula/laravel-sso/issues/112)) ([cfa887f](https://github.com/sinemacula/laravel-sso/commit/cfa887f44233037607821ab876f2ecde2cd6e986))
* report a malformed operations setting rather than throw from the schedule ([#44](https://github.com/sinemacula/laravel-sso/issues/44)) ([9f718eb](https://github.com/sinemacula/laravel-sso/commit/9f718eb207f4b610e94bb358c9f1cd6410657c02))
* store an off rule for a tenant with no rule ([#48](https://github.com/sinemacula/laravel-sso/issues/48)) ([a8bd70a](https://github.com/sinemacula/laravel-sso/commit/a8bd70a50b7f70e5417de10c76a2b5804de7d2fb))


### Miscellaneous Chores

* release as 0.1.0 ([#121](https://github.com/sinemacula/laravel-sso/issues/121)) ([d069de2](https://github.com/sinemacula/laravel-sso/commit/d069de2aebc02131f2200e08071292027e583cf4))
