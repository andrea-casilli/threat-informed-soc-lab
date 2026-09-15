# Threat Model

The lab models four common ATT&CK behaviors at the telemetry layer: repeated authentication failures, multiple service connection attempts, an unusual successful login, and Unix shell execution. The adversary is simulated entirely by deterministic Python objects. No credentials are tried, no process is launched, and no connection is made.

Assets are the local JSONL logs, reports, and source code. Primary risks are unsafe expansion of simulations and accidental inclusion of secrets. Controls include inert event generation, private RFC1918/documentation-style lab addresses, `.gitignore`, `.env.example`, and CI secret scanning.
