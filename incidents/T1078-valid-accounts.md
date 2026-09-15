# T1078 — Valid Accounts

1. **Detection:** `UNUSUAL-VALID-ACCOUNT-001` consumes a successful login explicitly enriched as unusual.
2. **Validation:** Confirm the `suspicious-login` validation result is PASS.
3. **Triage:** Review account, source, service, authentication timeline, and enrichment quality.
4. **Containment:** In the lab, disable only a designated test account if the scenario calls for it.
5. **Eradication:** Remove unintended test configuration and rotate no real credentials.
6. **Recovery:** Restore the test account configuration and verify normal telemetry.
7. **Lessons Learned:** Improve baseline and geo/device enrichment before retesting.
