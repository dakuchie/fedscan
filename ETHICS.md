# Ethics and disclosure protocol

1. **Public code only.** We analyse source files in public GitHub repositories. We never use any credential, token or account belonging to someone else.
2. **No exploitation.** We never request OIDC tokens against third-party roles, pools or credentials, and we never call `AssumeRoleWithWebIdentity`, STS token exchange or Entra token exchange against them. Confirming exploitability on live systems would be unauthorised access, whatever the intent. The paper reports *potential* exposure only.
3. **Ethics review.** Get a determination from the institution's IRB or ethics board before collecting data. Record the protocol number in `manuscript/main.tex` (Section 5.4).
4. **Who gets notified.** The owner of every production binding rated critical or high is notified. Channels, in order of preference:
   1. GitHub private vulnerability reporting
   2. The `SECURITY.md` contact
   3. `security.txt`
   4. The maintainer's public email address

   Use the template in Appendix A of the manuscript. Log every notification in `data/disclosure.csv` with these columns: `repo, binding_id, channel, notified_at, acknowledged_at, fixed_at, outcome`.
5. **Embargo.** Wait at least 90 days from notification before any public mention. The paper never identifies an affected party.
6. **Vendors.** Share aggregate findings with AWS, Google, Microsoft and GitHub through their security contacts before submission.
7. **Data release.** Pseudonymise repository identifiers with HMAC-SHA256 using a secret key (`PSEUDONYM_KEY`), and never publish that key. Do not release file paths or resource names.
