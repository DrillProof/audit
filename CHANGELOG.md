# Changelog

## [2.1.0](https://github.com/DrillProof/audit/compare/v2.0.0...v2.1.0) (2026-09-07)


### Features

* add S3 bucket and DynamoDB table recoverability checks ([d978c14](https://github.com/DrillProof/audit/commit/d978c1469db6909c0d917126c25c3619e8d3b002))
* Amazon EFS support ([e0ecfdc](https://github.com/DrillProof/audit/commit/e0ecfdc5afe9c9867fd203ab57ca9254209c2edc))
* **aws:** add read-only DynamoDB and bucket-posture API surfaces ([471c325](https://github.com/DrillProof/audit/commit/471c325d008bc1d7d1aaaa85d83a2be6339867a3))
* **aws:** discover DynamoDB tables with PITR status ([4b98130](https://github.com/DrillProof/audit/commit/4b9813051dbb90569bb0fcd14880901fadb2295b))
* **aws:** discover EFS filesystems, automatic backups and replication ([b897328](https://github.com/DrillProof/audit/commit/b8973281b6c098b5c4d8546adaeb4ad291cf176d))
* **aws:** discover S3 buckets once per account with protection posture ([d7bddc3](https://github.com/DrillProof/audit/commit/d7bddc30e33d932ce1e80a82498e8435b02ee2db))
* **checks:** accept PITR or backup plan as DynamoDB coverage ([7c4ee5f](https://github.com/DrillProof/audit/commit/7c4ee5f433522808087d3344632c3d45275e2bc0))
* **checks:** grade S3 bucket deletion protection across six tiers ([d23c9dc](https://github.com/DrillProof/audit/commit/d23c9dc271ba85cd968c5456b13624fa10f3b73d))
* **checks:** reinterpret coverage and redundancy for EFS ([8e51988](https://github.com/DrillProof/audit/commit/8e51988ef001ce9c701d5a3eb8300d8519bb6b16))
* **iam:** grant the four read-only EFS actions and add the EFS client ([84a0552](https://github.com/DrillProof/audit/commit/84a0552aba2e8557f83be13cbedb0a4d3e27ecd5))
* **iam:** grant the S3 and DynamoDB read actions the scanner calls ([81632b5](https://github.com/DrillProof/audit/commit/81632b55c0faa53b0c1186ee4cfcaba6aa564b96))
* **model:** add bucket and table resource types with protection state ([8dc62b0](https://github.com/DrillProof/audit/commit/8dc62b031f3e75ce407ad8b294c419191da685b2))
* **model:** add the EFS resource type and its backup posture ([e3e5c9d](https://github.com/DrillProof/audit/commit/e3e5c9d75c51955c6e4c84710e15b68e046b9aeb))
* **report:** document the S3 hierarchy and render N/A distinctly ([d38484a](https://github.com/DrillProof/audit/commit/d38484a4fdf0e67be7b7e9f379502bca67bfa567))
* **scan:** include buckets and tables, with an optional bucket allow-list ([d6fcd8f](https://github.com/DrillProof/audit/commit/d6fcd8fed71e9149cba72d35043221e23b5a8451))
* **score:** weight a One Zone filesystem with no backup as critical ([a7b041b](https://github.com/DrillProof/audit/commit/a7b041bb5b86119c1640070cba89849f580cd8c1))
* **score:** weight production buckets and tables as critical resources ([9039b78](https://github.com/DrillProof/audit/commit/9039b78ae0723148ad992ff87ea8f3c78a6c0e12))


### Fixes

* **ci:** make the customer-templates drift guard able to pass ([6ba16c1](https://github.com/DrillProof/audit/commit/6ba16c14a454f91d07ef942002a30b16156ca01f))
* EFS backup-status honesty — unreadable status is Unknown, not a fail ([6a0954a](https://github.com/DrillProof/audit/commit/6a0954ac973d11b5640aa267b15c5b4eeb1e6a77))

## [2.0.0](https://github.com/DrillProof/audit/compare/v1.2.1...v2.0.0) (2026-09-02)


### ⚠ BREAKING CHANGES

* Recoverability Scores rise for partially-protected estates. `score --fail-under N` gates set against v1 numbers may now pass where they previously failed — a gate that turned green deserves re-checking, not trust. Thresholds should be re-chosen against v2 numbers.

### Features

* score the estate as a weighted mean, not a sum of deductions ([08151d2](https://github.com/DrillProof/audit/commit/08151d20c17acdf99d83cda97247f98ee5b76bb8))

## [1.2.1](https://github.com/DrillProof/audit/compare/v1.2.0...v1.2.1) (2026-08-13)


### Fixes

* **release:** ship shell completions inside release archives ([e228d7f](https://github.com/DrillProof/audit/commit/e228d7f510475936c049e3c05e9168590bc40d3b))


### Performance

* **docker:** base image on distroless/static to drop QEMU emulation ([c22b227](https://github.com/DrillProof/audit/commit/c22b2277c08b71df2b31794582ae40ce4b9bd2d2))
* **docker:** base image on distroless/static to drop QEMU emulation ([9a18409](https://github.com/DrillProof/audit/commit/9a184098f23e39714ff52f20e0076cfa7a9e61ff))

## [1.2.0](https://github.com/DrillProof/audit/compare/v1.1.0...v1.2.0) (2026-08-13)


### Features

* ci updated with publishing ([a580fd0](https://github.com/DrillProof/audit/commit/a580fd0c140789826e9004dadf69f4aa5ffdb17e))
* cli initialized ([dc85079](https://github.com/DrillProof/audit/commit/dc85079f771d7e8da3dbda5a24b2abebaccb5a37))
* installer added for get.drillproof.com ([94010e3](https://github.com/DrillProof/audit/commit/94010e3367e3eb652bbe1f829ca264ecb1d2722c))
* **master:** release 1.0.0 ([0a6ddcd](https://github.com/DrillProof/audit/commit/0a6ddcd1b47a6823a78f34b3f35291a63d449a04))


### Fixes

* CI branch fixed ([be264e2](https://github.com/DrillProof/audit/commit/be264e29c1f667b437d20dd94b19c241f3d3438b))
* release updated ([dde4cbc](https://github.com/DrillProof/audit/commit/dde4cbc41afcaf6b0229acb40c5d29ae89b2e8f1))

## [1.1.0](https://github.com/DrillProof/audit/compare/drillproof-audit-v1.0.0...drillproof-audit-v1.1.0) (2026-08-02)


### Features

* ci updated with publishing ([a580fd0](https://github.com/DrillProof/audit/commit/a580fd0c140789826e9004dadf69f4aa5ffdb17e))
* cli initialized ([dc85079](https://github.com/DrillProof/audit/commit/dc85079f771d7e8da3dbda5a24b2abebaccb5a37))
* installer added for get.drillproof.com ([94010e3](https://github.com/DrillProof/audit/commit/94010e3367e3eb652bbe1f829ca264ecb1d2722c))
* **master:** release 1.0.0 ([0a6ddcd](https://github.com/DrillProof/audit/commit/0a6ddcd1b47a6823a78f34b3f35291a63d449a04))


### Fixes

* CI branch fixed ([be264e2](https://github.com/DrillProof/audit/commit/be264e29c1f667b437d20dd94b19c241f3d3438b))
