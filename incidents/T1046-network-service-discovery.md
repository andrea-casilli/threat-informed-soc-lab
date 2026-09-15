# T1046 — Network Service Discovery

1. **Detection:** `NETWORK-SERVICE-DISCOVERY-001` observes ten distinct destination ports from one source.
2. **Validation:** Execute the `port-scan` simulation through validation; it writes events only and opens no network connections.
3. **Triage:** Validate source, port cardinality, interval, asset-owner context, and approved assessment windows.
4. **Containment:** For an authorized lab, disconnect the simulated endpoint if testing a response workflow.
5. **Eradication:** Remove only unintended lab automation; this MVP contains no scanner.
6. **Recovery:** Re-enable the isolated lab path and confirm telemetry ingestion.
7. **Lessons Learned:** Add asset inventory context and exclusions, then rerun validation.
