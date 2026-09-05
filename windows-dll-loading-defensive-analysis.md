# Auditing Windows DLL Loading Tests in a Controlled Environment: Three Bugs, Repair Principles, and Defensive Observability

> **Scope and intended use**
>
> This article discusses stability and defensive observability only in self-owned, isolated Windows virtual machines and test binaries. The underlying techniques can be abused, so this document does not provide reusable injection chains, evasion methods, or instructions for operating on arbitrary processes. Any security testing should have explicit authorization from the asset owner, with the target scope, time window, and results recorded.

This is a source-code audit of a Windows DLL loading test utility and its companion test DLL. Of the three findings, the first two originate in the test DLL's lifecycle design; the third is a synchronization issue between the tool's process-list cache and its user interface. Their value is not in making process injection more reliable. Instead, they illustrate two engineering lessons: DLL initialization must respect loader constraints, and defensive detection should account for both loader-visible behavior and inter-process telemetry.

Topics covered include the Windows PE loader, DllMain, the loader lock, inter-process access, thread-creation telemetry, and authorization and audit requirements for security testing.

---

## 1. Start with an accurate loader model

When a DLL is loaded through the normal loader path, Windows records the module in loader-maintained structures and sends process and thread notifications according to its lifecycle. Custom mapping implementations instead perform their own mapping and initialization. Whether they call an entry point, handle TLS, or clean up correctly depends on the implementation, so they must not be treated as equivalent to a normal system load.

| Observation | Normal loader path | Custom mapping implementation |
|---|---|---|
| Module registration | Maintained by the system loader | Usually absent from normal module lists |
| Process-attach callback | Invoked by the system load flow | Occurs only if explicitly implemented |
| Thread notifications | May occur by default; can be disabled by the DLL | Normally not automatically delivered by Windows |
| Unload and cleanup | Follows system loader semantics | Defined by the implementation and may be incomplete |
| Defensive visibility | Can be correlated with module-load and inter-process events | Cannot rely only on module-load events |

The failures in the original test DLL arose from treating thread notifications and DllMain as ordinary application callbacks. Microsoft states that DllMain runs while the loader lock is held, should do only minimal initialization, and should not call User32, GDI, LoadLibrary, process-creation, or thread-waiting routines. [DLL best practices](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-best-practices)

### Defensive observation: one event is not a verdict

Process-injection-related behavior can occur in debuggers, accessibility software, game anti-cheat products, EDR tools, and malware. An alert should be evaluated with context: environment, code signing, parent-child relationships, target criticality, and explicit authorization. The presence of a single API trace is not, by itself, evidence of malicious activity.

In an authorized lab, the same test scenario can be mapped to the following telemetry to validate detection logic and measure false positives and false negatives:

- Sysmon Event ID 10 records one process opening another process. It is useful when correlated with the target, requested access, and later events, but it can be noisy.
- Sysmon Event ID 8 records cross-process thread creation. It is often a strong signal, but it does not cover every code-injection or process-manipulation technique.
- Sysmon Event ID 7 records image loads. It is more useful for DLLs loaded through the normal loader path, but it cannot replace correlation with other telemetry.
- Sysmon Event ID 25 is intended for specific process-image-tampering scenarios and should be interpreted within its documented coverage.

See [Microsoft's Sysmon event reference](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events) for event semantics and limitations. Production deployments should establish a baseline first, then use scoped correlation rules and human review.

---

## 2. Bug 1: The test DLL window appeared briefly and then closed

**Symptom.** In a controlled suspended-start test, the test DLL's dialog appeared and then closed almost immediately. The behavior initially resembled a load-timing problem, but it was caused by two combined DLL defects.

### Defect A: Unintended fall-through in message handling

The dialog-initialization branch lacked an explicit return or break, so execution fell into a command handler that closed the window. This is a standard window-procedure control-flow defect rather than a security mechanism, yet it can look very similar to a loading failure.

**Repair principles:**

1. Give every message branch an explicit return or break; do not rely on implicit fall-through.
2. Separate window creation, display, shutdown, and error handling into independently testable functions.
3. Add structured logging for initialization, shutdown, and thread exit, including timestamps and thread IDs. Do not rely only on message boxes for diagnosis.

### Defect B: Performing UI operations during thread-detach notification

The test DLL handled thread attach, thread detach, and process detach in the same branch, where it displayed message boxes and closed a dialog. When a thread ends, Windows can deliver a DLL notification in a loader-lock context. Touching UI from that callback couples lifecycle handling to the windowing subsystem and can cause instability or deadlock.

**Repair principles:**

1. Keep DllMain to simple state changes such as storing an instance handle; do not create UI, display dialogs, or wait for threads.
2. If the DLL does not require per-thread callbacks, consider disabling thread notifications during process attach. First confirm that the DLL does not depend on static-CRT behavior and check the API result.
3. Move initialization and cleanup to explicit exported functions or a controller called by the host outside DllMain.
4. Do not treat PostMessage as an exception that makes User32 safe in DllMain. The robust design is for DllMain not to own UI lifecycle at all.

### Controlled reproduction timeline

The original failure can be summarized as follows:

1. A test thread finishes loading the DLL.
2. The test DLL creates a dialog and stores its window handle.
3. The test thread ends, triggering a thread-detach notification.
4. The notification handler touches the window in an unsuitable loader context.
5. The window closes early, or the process deadlocks on some paths.

Expressing the issue as a timeline is more useful than calling it an intermittent crash: it points directly to thread notifications, the loader lock, and the UI boundary rather than incorrectly blaming a security product or Windows version.

---

## 3. Bug 2: Closing the test window made the UI unresponsive

**Symptom.** In an experiment attached to a self-owned test process, closing the test window caused the process UI to stop responding.

**Root cause.** DllMain is invoked while the loader lock is held. If the callback synchronously invokes UI code or another action that may load components, wait for a thread, or acquire a different lock, it can create a lock-order inversion. One party holds the loader lock while waiting for UI or a worker thread; the other holds the corresponding resource while waiting for the loader lock. The result is a process-wide deadlock.

**Recommended repairs:**

- Reduce DllMain to minimal initialization, especially avoiding thread synchronization and window management.
- Release resources in the host's normal message loop or an explicit shutdown API, not in DllMain.
- Give worker threads a clear stop protocol: request a stop, let the worker complete its current task and report its state, then reclaim resources from a non-DllMain path in the host.
- During testing, use Application Verifier, debugger thread views, and lock diagnostics to confirm there is no wait chain.

Microsoft's [DllMain documentation](https://learn.microsoft.com/en-us/windows/win32/dlls/dllmain) likewise notes that entry-point calls are serialized and should not be used to communicate with other threads or processes.

---

## 4. Bug 3: A newly started test process did not appear in the tool UI

**Symptom.** The UI could obtain the target window's PID, but the status bar and later validation consulted only an outdated process cache. As a result, a newly started self-owned test process was displayed as not selected.

**Root cause.** A cache was incorrectly treated as the sole source of truth. A process list always has a timing gap: when a window is selected, the background enumeration snapshot may not have refreshed, and UI components may not uniformly repopulate their state after refresh.

### Keep stability repairs separate from security boundaries

From a software-quality perspective, the UI can re-enumerate when the cache misses, display a verification-in-progress state, and update its status when a fresh snapshot arrives. This avoids discarding a PID that the user just selected.

In a security test utility, however, **discovering a process does not mean that high-risk actions are authorized against it**. Before execution, the tool should independently verify:

- the target belongs to the pre-registered lab assets and allowlist;
- the process path, signature, session, and start time match the test plan;
- the action remains within the authorization window; and
- the operator, experiment identifier, target identity, and result are written to an audit log.

In other words, fixing the cache improves UI consistency. It must not turn real-time discovery after a cache miss into a path for operating on any newly discovered process.

---

## 5. Defensive validation checklist

| Validation goal | Passing condition | Common mistake |
|---|---|---|
| DLL lifecycle | DllMain handles only minimal state; no UI or waits | Treating one non-reproduction as a concurrency test |
| Test boundary | Only self-owned VMs, test binaries, and registered targets | Identifying a target only by window title or PID |
| Log quality | Record operator, target, authorization ID, time, and outcome | Putting sensitive paths, tokens, or memory content in logs |
| Detection rules | Test against baseline, lab tests, and known-benign software | Blocking directly on one Event ID |
| Response process | Isolate, preserve evidence, verify authorization, then escalate | Classifying a research test as an intrusion without review |

Each test should produce an immutable experiment record: the test plan, VM snapshot identifier, allowlisted executable hashes, telemetry samples, detection result, rollback evidence, and any exception notes. This demonstrates defensive-research rigor far better than showing what a tool can do.

---

## 6. Conclusion

The attribution for the three bugs is straightforward:

1. A control-flow error in dialog initialization caused the window to close incorrectly.
2. UI handling in thread or process detach callbacks violated DLL lifecycle constraints under the loader lock.
3. The process cache and UI state fell out of sync, preventing a newly started controlled test process from being displayed correctly.

The repair objective should be a robust, auditable test environment, not expanded capability against arbitrary targets. Incorporating loader constraints, target authorization, telemetry correlation, and human review into the design turns Windows low-level testing into reproducible, explainable research that can improve defensive capability.

## References

- [Microsoft: Dynamic-Link Library Best Practices](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-best-practices)
- [Microsoft: DllMain entry point](https://learn.microsoft.com/en-us/windows/win32/dlls/dllmain)
- [Microsoft: Sysmon events](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events)
