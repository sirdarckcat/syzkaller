# Lifetime/Concurrency Violations (UAF, Double Free)

The IPoF in these cases is the instruction that accesses memory that has already been implicitly or explicitly freed, or the operation that corrupts a synchronization primitive.


<table>
  <tr>
   <td><strong>CVE Identifier</strong>
   </td>
   <td><strong>Failing Operation</strong>
   </td>
   <td><strong>Failing Variable/State</strong>
   </td>
   <td><strong>Context/Trigger</strong>
   </td>
  </tr>
  <tr>
   <td><strong>CVE-2024-57948</strong>
   </td>
   <td>Function call <code>list_del_rcu(&sdata->list)</code>.
   </td>
   <td><code>sdata->list</code> was already unlinked.
   </td>
   <td>Race condition leading to <strong>double list unlink</strong> during concurrent interface and hardware removal.
   </td>
  </tr>
  <tr>
   <td><strong>CVE-2024-57995</strong>
   </td>
   <td>Dereferencing <code>arvif->is_created</code>.
   </td>
   <td><code>arvif</code> is a <strong>stale/freed pointer</strong>.
   </td>
   <td>Ordering bug: the check was performed after a teardown path (<code>ath12k_mac_unassign_link_vif</code>) potentially freed <code>arvif</code>, but before it was reassigned.
   </td>
  </tr>
  <tr>
   <td><strong>CVE-2024-58004</strong>
   </td>
   <td>List insertion via <code>plist_add</code>.
   </td>
   <td><code>isys->pm_qos</code> is a <strong>dangling/stale list node</strong>.
   </td>
   <td>Error path neglect: <code>cpu_latency_qos_remove_request()</code> was skipped during probe cleanup, leaving the PM QoS list pointing to freed memory.
   </td>
  </tr>
  <tr>
   <td><strong>CVE-2025-38349</strong>
   </td>
   <td>Accessing the mutex structure inside <code>mutex_unlock(&ep->mtx)</code>.
   </td>
   <td><code>ep</code> (the <code>struct eventpoll</code> containing <code>ep->mtx</code>) is <strong>freed</strong>.
   </td>
   <td>Incorrect locking order: the reference count decrement (which triggered the free) occurred <em>while</em> holding the mutex, allowing a race to free the object before the unlocking thread finished accessing the mutex structure.
   </td>
  </tr>
</table>