<!--
SPDX-FileCopyrightText: 2025 Swiss Confederation

SPDX-License-Identifier: MIT
-->

![github-banner](https://github.com/swiyu-admin-ch/swiyu-admin-ch.github.io/blob/main/assets/images/github-banner.jpg)

# Generic Application Test

The Generic Application Test is a test system designed to run end-to-end (E2E) tests against the generic SWIYU [Issuer](https://github.com/swiyu-admin-ch/swiyu-issuer) and [Verifier](https://github.com/swiyu-admin-ch/swiyu-) components.

Its primary goal is to validate the generic behavior of these components in isolation, without relying on a full trust infrastructure or real wallets. The system focuses on testing the generic issuance and verification flows, independently of any specific ecosystem or deployment.

This project starts the Issuer and Verifier services inside containers and interacts with them through HTTP calls using a fake (mocked) wallet. All other trust-related services are mocked to keep the test environment simple, deterministic, and focused.


## Table of Contents

- [License](#license)

## License

This project is licensed under the terms of the MIT license. See the [LICENSE](/LICENSE) file for details.