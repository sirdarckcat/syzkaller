# Concurrency and State/Logic Errors

If the fault involves inconsistent state, unexpected execution (soft lockup, deadlock), or complex timing errors, perform the following checks:


<table>
  <tr>
   <td><strong>Sub-Category</strong>
   </td>
   <td><strong>Check Sequence</strong>
   </td>
   <td><strong>Source Examples</strong>
   </td>
  </tr>
  <tr>
   <td><strong>Concurrency/Locking Bug</strong>
   </td>
   <td>Did concurrent threads attempt to modify shared lists or state non-atomically? Check for double list removal without membership check, premature lock release creating a race window for shared state teardown, or accessing fields after a potentially freeing put without proper lock holding or atomic operations.
   </td>
   <td>CVE-2024-57948, CVE-2025-38323, CVE-2025-38289.
   </td>
  </tr>
  <tr>
   <td><strong>Improper Loop/Iterator Control</strong>
   </td>
   <td>Did the loop modify the list it was iterating over without proper handling (e.g., using <code>break</code> instead of <code>goto</code> or <code>*_safe</code> iteration), resulting in livelock/soft lockup? Or did the iterator state advance inappropriately after a lock drop?
   </td>
   <td>CVE-2024-57991, CVE-2024-58058, CVE-2025-38276.
   </td>
  </tr>
  <tr>
   <td><strong>Initialization/State Validation</strong>
   </td>
   <td>Was a required initialization step or state check missed before core API use? E.g., forgetting <code>platform_set_drvdata</code>, calling a function that requires <code>netdev_ops</code> before assignment, or performing cleanup on a channel before it was marked <code>enabled</code>.
   </td>
   <td>CVE-2025-38318, CVE-2025-38487.
   </td>
  </tr>
</table>