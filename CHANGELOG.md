# Changelog

<!--next-version-placeholder-->

## v0.3.0 (2022-03-16)
### Feature
* Refactor to use Poetry for build and semantic versioning ([`6afc751`](https://github.com/sonatype-nexus-community/iq-config-as-code/commit/6afc75167dcff5ac9134d051df321002a01e58ba))

## v0.2.0 (2022-03-16)
### Feature
* Work to add standardised Circle CI for Python project ([`ea8d65d`](https://github.com/sonatype-nexus-community/iq-config-as-code/commit/ea8d65dcb9c1f9ec97bd8c8b87a22a16262af99b))
* Export policy for orgs and apps ([`423c41f`](https://github.com/sonatype-nexus-community/iq-config-as-code/commit/423c41fb5dd0d20a79c4132878e8f006fb9bb93c))

### Fix
* Remove duplicate call to persist_policy ([`3cf7ea5`](https://github.com/sonatype-nexus-community/iq-config-as-code/commit/3cf7ea547b40ac407432a98b2f1c03f8bb36eb72))
* Correct organization policy import, disable for apps ([`768431e`](https://github.com/sonatype-nexus-community/iq-config-as-code/commit/768431e6d10579ec6cbd4ff3fe485ab484616ece))

### Documentation
* Add some docker documentation ([`e7bbd55`](https://github.com/sonatype-nexus-community/iq-config-as-code/commit/e7bbd55d51abc07a4b1113c123a81fce45749171))

## Historical Changelog
29th January 2021 - First release

12th February 2021 - Scrape existing IQ config to disk.

26th February 2021 - Scrape to user specified output directory

17th March 2021 - Override self-signed certificate verification

23rd March 2021 - Enable scrape of specific selected application(s) and/or organisation(s)

06th May 2021 - Add healthcheck capability

25th May 2021 - Enhanced healthcheck benchmarks environment configuration against a 'template' configuration aligned with recommended best practice.

13th July 2021 - Improved healthcheck reporting. Templates for on-boarding and healthcheck config aligned to Sonatype recommended best practice.

15th Oct 2021 - API limitation identified. Code to apply policy App Cat scrope 'hard-coded' in scrape script. Persisted data applied to best practice.

5th Nov 2021 - Aforementioned API limitation remediated within product. policyTag data parsed dynamically from json payload.

15th Nov 2021 - Add policyTags to healthcheck analysis.