# Manual evidence checklist
- Show encrypted payloads (no plaintext)
- BAD_CERT on invalid/self/expired cert
- SIG_FAIL on tamper (flip bit in ct)
- REPLAY on reused seqno
- Transcript + signed SessionReceipt
