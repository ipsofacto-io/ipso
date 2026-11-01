# Changelog

## [0.4.0](https://github.com/ipsofacto-io/ipso/compare/v0.3.0...v0.4.0) (2026-11-01)


### Features

* **cli:** answer Claude Code hooks from local checks ([#51](https://github.com/ipsofacto-io/ipso/issues/51)) ([770d250](https://github.com/ipsofacto-io/ipso/commit/770d250c423ef1be14d2784685567d860c03332e))
* **cli:** answer Codex, Copilot, Cursor, and Kiro hooks ([#52](https://github.com/ipsofacto-io/ipso/issues/52)) ([2c3e979](https://github.com/ipsofacto-io/ipso/commit/2c3e9791857c2294edf0964eeeb7a5543529cff9))
* **cli:** check Pulumi, CloudFormation, CDK, and ARM output ([#47](https://github.com/ipsofacto-io/ipso/issues/47)) ([b5776b6](https://github.com/ipsofacto-io/ipso/commit/b5776b6694ab69e187d96e245763597784750273))
* **cli:** generate agent rules files from decisions ([#49](https://github.com/ipsofacto-io/ipso/issues/49)) ([553b9c9](https://github.com/ipsofacto-io/ipso/commit/553b9c9b1c5372d2753500f588cfa5aab043cc56))
* **cli:** render Helm charts and Kustomize directories offline ([#44](https://github.com/ipsofacto-io/ipso/issues/44)) ([d6e7dd3](https://github.com/ipsofacto-io/ipso/commit/d6e7dd31c1fb12c18ea78098fcccb28b2469a787))
* **cli:** serve decisions over a local MCP server ([#50](https://github.com/ipsofacto-io/ipso/issues/50)) ([c7ff8ad](https://github.com/ipsofacto-io/ipso/commit/c7ff8ad68d4cabdedc2afc41437524541e637644))
* expose plan evaluation to other modules ([#45](https://github.com/ipsofacto-io/ipso/issues/45)) ([5b24409](https://github.com/ipsofacto-io/ipso/commit/5b24409be7327ea8b226a8350f1dddbff5aca72b))

## [0.3.0](https://github.com/ipsofacto-io/ipso/compare/v0.2.0...v0.3.0) (2026-11-01)


### Features

* **cli:** baseline existing violations with fingerprints ([#40](https://github.com/ipsofacto-io/ipso/issues/40)) ([d82d92f](https://github.com/ipsofacto-io/ipso/commit/d82d92f623d8e59f92c01ccf381b78ddd77bcceb))
* **cli:** check premises on in-force decisions ([#37](https://github.com/ipsofacto-io/ipso/issues/37)) ([39e6847](https://github.com/ipsofacto-io/ipso/commit/39e68475d662f99b9bcb5c3d3b27a9adc9b8401b))
* **cli:** evaluate ESLint checks ([#36](https://github.com/ipsofacto-io/ipso/issues/36)) ([7a49ed8](https://github.com/ipsofacto-io/ipso/commit/7a49ed89ce2ec10e1fe07c348c21b97ef7c666ea))
* **cli:** evaluate Gatekeeper checks ([#35](https://github.com/ipsofacto-io/ipso/issues/35)) ([a3f7d94](https://github.com/ipsofacto-io/ipso/commit/a3f7d9459eaabcce1179f9951dc193f1c77d7d67))
* **cli:** evaluate import-linter checks ([#32](https://github.com/ipsofacto-io/ipso/issues/32)) ([f16745d](https://github.com/ipsofacto-io/ipso/commit/f16745d4ad828beb40fe6f3af450c4c10da8f0c8))
* **cli:** evaluate Kyverno checks ([#34](https://github.com/ipsofacto-io/ipso/issues/34)) ([9e56ff0](https://github.com/ipsofacto-io/ipso/commit/9e56ff0c814cb7a3eb15e79118b18d6a1425e564))
* **cli:** verify signed policy bundles ([#38](https://github.com/ipsofacto-io/ipso/issues/38)) ([b3c5056](https://github.com/ipsofacto-io/ipso/commit/b3c5056fad20e60c8678f19d1692079ce7db345a))
* **cli:** write SARIF output and link explain to decisions ([#39](https://github.com/ipsofacto-io/ipso/issues/39)) ([c564ba9](https://github.com/ipsofacto-io/ipso/commit/c564ba9edeebdc89af3d9b9d99cf4f144a15fd8a))
* expose EDR validation to other modules ([#42](https://github.com/ipsofacto-io/ipso/issues/42)) ([fb569ad](https://github.com/ipsofacto-io/ipso/commit/fb569adeee7047da4099ac85956873dd43b2871d))

## [0.2.0](https://github.com/ipsofacto-io/ipso/compare/v0.1.1...v0.2.0) (2026-10-27)


### ⚠ BREAKING CHANGES

* rename the CLI and module to ipso ([#29](https://github.com/ipsofacto-io/ipso/issues/29))

### Features

* **cli:** compile in-force checks into the local build directory ([2816ed1](https://github.com/ipsofacto-io/ipso/commit/2816ed1ab4a6988bdfd83aaa1365808a29979f12))
* **cli:** evaluate ArchUnit checks ([#28](https://github.com/ipsofacto-io/ipso/issues/28)) ([ad3317d](https://github.com/ipsofacto-io/ipso/commit/ad3317d02658f0c6bad57d71a6c9ea1fc10cc43b))
* **cli:** evaluate dependency-cruiser checks ([#26](https://github.com/ipsofacto-io/ipso/issues/26)) ([6cb03ba](https://github.com/ipsofacto-io/ipso/commit/6cb03ba5dd5d09fef59d2ce66211c3b833e17a9a))
* **cli:** evaluate Semgrep checks ([231777d](https://github.com/ipsofacto-io/ipso/commit/231777dc0d58528b34aa5b4138fcbc6f112e3350))
* **cli:** evaluate Terraform and OpenTofu plans ([#19](https://github.com/ipsofacto-io/ipso/issues/19)) ([c6b78c1](https://github.com/ipsofacto-io/ipso/commit/c6b78c1d7b76123c7593500921b4c1745166aaf3))
* **cli:** import MADR and Nygard ADRs as EDR files ([1f3118d](https://github.com/ipsofacto-io/ipso/commit/1f3118d9943eacba7a9a33b77cb52dc79731d268))
* **compiler:** compile ArchUnit and import-linter architecture rules ([#24](https://github.com/ipsofacto-io/ipso/issues/24)) ([65b814a](https://github.com/ipsofacto-io/ipso/commit/65b814a6f3519605fbdf53c1b8769d6fbf3b55e9))
* **compiler:** compile dependency-cruiser JSON rule files ([#20](https://github.com/ipsofacto-io/ipso/issues/20)) ([1a3e4ad](https://github.com/ipsofacto-io/ipso/commit/1a3e4ad83971767b987c5ccca075a36fd0b87cbe))
* **compiler:** compile Kyverno, Gatekeeper, and ESLint checks ([#25](https://github.com/ipsofacto-io/ipso/issues/25)) ([5bfddf4](https://github.com/ipsofacto-io/ipso/commit/5bfddf4aba0792dfd803da82526bd2e85a71e928))
* **compiler:** compile OPA policies and Terraform templates ([#18](https://github.com/ipsofacto-io/ipso/issues/18)) ([2928259](https://github.com/ipsofacto-io/ipso/commit/2928259b435a707ab0ecc3d083599e959d9fc0f2))
* **compiler:** compile Semgrep rules to canonical YAML ([#21](https://github.com/ipsofacto-io/ipso/issues/21)) ([9046a02](https://github.com/ipsofacto-io/ipso/commit/9046a02288f92c1e43e06a5e6687c685d1ede7e8))
* **compiler:** evaluate CI jobs and Checkov ids offline ([#22](https://github.com/ipsofacto-io/ipso/issues/22)) ([b244b7e](https://github.com/ipsofacto-io/ipso/commit/b244b7e210cbacb0cd69a8f7a244b150c9f441ae))
* rename the CLI and module to ipso ([#29](https://github.com/ipsofacto-io/ipso/issues/29)) ([db65f7a](https://github.com/ipsofacto-io/ipso/commit/db65f7a95a9feea71125099b006c1fa071c09905))


### Bug Fixes

* **cli:** cite IPSO-19 for the unimplemented import command ([89947b8](https://github.com/ipsofacto-io/ipso/commit/89947b81aec46ab3f5c96cff30a230e076074f01))

## 0.1.1 (2026-10-21)

### Features

* **ci:** publish Level 3 provenance, cosign signatures, and a CycloneDX SBOM

## 0.1.0 (2026-10-20)

### Features

* **cli:** add offline init, check, and explain ([0737378](https://github.com/ipsofacto-io/ipso/commit/07373789f8176bb190c4a1a3fd0f032a78190c5d))
