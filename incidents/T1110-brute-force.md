# T1110 — Brute Force

1. **Detection:** `SSH-BRUTE-FORCE-001` observes five failed SSH logins from one source in five minutes.
2. **Validation:** Run `python -m soc_lab validate`; T1110 must PASS.
3. **Triage:** Check source, target, username, time range, and whether the local simulator generated the events.
4. **Containment:** In a lab, isolate the test VM network interface only when authorized; do not block external addresses from this project.
5. **Eradication:** Correct the simulated source or configuration; no malware or account action is present.
6. **Recovery:** Restore the lab baseline and confirm normal local access.
7. **Lessons Learned:** Tune threshold and allow-list logic using controlled false-positive cases, then retest.
