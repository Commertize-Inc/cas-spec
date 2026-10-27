# Security policy

Please report suspected vulnerabilities privately by email to **support@commertize.com** with the subject line "Security report: cas-spec". Do not open a public issue for a security problem.

Include what you found, how to reproduce it, and the affected file, package and version. We aim to acknowledge reports promptly and keep reporters informed while we investigate. We are glad to credit you in the release notes if you wish. This policy creates no contractual obligation and offers no bounty.

In scope: the specification text, the reference verifier and the conformance vectors in this repository. A path where the verifier reports `VALID` when the spec says it must not is a vulnerability. Out of scope: Commertize's hosted services (report those to the same address, but they are not covered by this repository's releases), deployed credential contracts, and the provider you connect.

The verifier never signs, never holds a key and never sends a transaction. If you find a path where it does, please report it.

Please act in good faith: do not access data that is not yours, do not degrade service for others, and give us reasonable time to fix an issue before disclosing it.
