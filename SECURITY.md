# Security Policy

## Scope and safe use

This project is exclusively for local, authorized laboratories. Its simulations generate data records only: they do not scan, authenticate to, exploit, or alter any host or network. Never point extensions at systems you do not own or lack written authorization to test.

Do not commit credentials, private keys, tokens, certificates, personal data, or sensitive public IP addresses. Use environment variables or a secret manager for integrations and copy `.env.example` instead of committing `.env`.

## Reporting a vulnerability

Do not open a public issue containing sensitive details. Contact the repository maintainer privately with a concise reproduction, impact, and suggested mitigation. Allow reasonable time for a fix before disclosure.
