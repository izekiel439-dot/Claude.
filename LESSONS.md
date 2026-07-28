# Lessons learned

Generalized notes from incidents where an assistant session got something wrong or
learned something worth remembering. No incident-specific details (IPs, file paths,
timestamps, machine names) are recorded here on purpose — only the reusable lesson.

## Don't let a single AV/EDR verdict stand in for actual investigation

A malware classification from an antivirus or EDR product is a strong signal, not a
verdict. Before treating a detection as confirmed and taking irreversible action
(deleting a file, stripping an exclusion, killing a persistence mechanism), check:

- **Provenance.** Where did this file actually come from? If it's something the user
  or a prior trusted session authored, that changes the prior substantially compared
  to something silently dropped by an installer.
- **Behavior, not just label.** Read the file. Does it actually do the thing the
  label implies (obfuscated payloads, outbound calls to unexplained hosts, credential
  exfiltration), or does it just resemble one structurally (e.g. a legitimate security
  auditing tool that enumerates the same things a hacktool would, for the opposite
  reason)?
- **Whether the block persists past a local exclusion.** If a path exclusion is added
  and the block still fires, that's evidence of a cloud/signature-based verdict, not a
  purely local heuristic — treat that as a stronger, not weaker, signal, and don't
  escalate to disabling broader protections just to force execution.

When these checks disagree with the initial verdict, say so plainly and let the user
decide the risk tradeoff — don't quietly reverse course or quietly hold the line
without surfacing the tension.

## Prefer reversible steps over deleting when provenance is unclear

Moving a suspicious file aside (rename, quarantine to a holding folder) preserves the
option to restore it later. Deleting it outright forecloses that option. Default to
the reversible action first, especially when the file's origin hasn't been fully
traced yet.

## Re-verify after a fix, don't assume it worked

Adding an exclusion, removing a registry key, or killing a process is only a
hypothesis about what will fix the problem. Re-run the actual check afterward
(re-attempt execution, re-query the registry, re-check for the live connection)
instead of reporting success based on the remediation step alone.

## Keep destructive/irreversible actions gated behind explicit confirmation

Registry edits, file deletion, disabling security controls, and anything requiring
elevation should be confirmed with the user first, one decision at a time, rather
than bundled into a single "yes go ahead" for a whole cleanup plan. Users can and
do want to stop partway through once they see an intermediate result.
