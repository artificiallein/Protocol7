# Metadata exposure (Phase 1 draft)

End-to-end content encryption cannot make ordinary email anonymous. Even a future fully encrypted P7/1 envelope leaves the following visible to the provider or an observer of the corresponding mail account:

| Data | Visibility and mitigation |
| --- | --- |
| `From`, `To`, routing headers, email account | Visible; provider learns correspondence. Identity keys remain separate from addresses. |
| Time, sending frequency, ordering | Visible; neutral subjects do not hide traffic patterns. |
| Message and attachment size | Visible after encoding; future padding could reduce precision at a cost. |
| Sender IP and mail server path | Visible to sending provider and potentially in headers; no anonymity claim. |
| MIME type and subject | Fixed application envelope type and neutral `Protocol 7 Message`; presence of P7 traffic is visible. |
| Delivery status | SMTP acceptance is observable, recipient reading is not inferred. |
| P7/1 public envelope | Sender public identity, fingerprint, signature, random message ID and suite are visible and linkable. |

Inner message text, filename, original MIME type, reply references and conversation ID are serialized inside the sealed envelope. Any cleartext routing or envelope fields are documented in [PROTOCOL.md](PROTOCOL.md). Local notifications and logs also require separate privacy review. No current phase transmits email.
