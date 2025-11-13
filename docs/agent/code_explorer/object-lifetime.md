# Object Lifetime and Initialization Asymmetry

If the fault is a **Use-After-Free (UAF)**, a **Double Free**, or a crash resulting from accessing uninitialized/stale data, perform the following checks:


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
   <td><strong>Temporal UAF (Ordering)</strong>
   </td>
   <td>Was <code>P</code> freed (or unassigned/unlinked) immediately before the Fault Line, and was the subsequent access intended to read a necessary state field before the pointer was re-validated/reassigned? Or was a state field captured <em>before</em> the structure was freed, but the final decision using that state relies on accessing the freed object (e.g., accessing SKB control block after <code>dev_kfree_skb_any(skb)</code>)?
   </td>
   <td>CVE-2024-57995, CVE-2025-38292.
   </td>
  </tr>
  <tr>
   <td><strong>Dangling Global State</strong>
   </td>
   <td>Did the Teardown Path fail to remove a reference to <code>P</code> from a global list (<code>pm_qos</code> plist, <code>dev_lec[]</code> array, <code>ftrace_mod_maps</code>) before freeing <code>P</code>'s memory? Check if a cleanup routine returned early due to a module-global state (e.g., <code>ftrace_disabled</code>).
   </td>
   <td>CVE-2024-58004, CVE-2025-38346, CVE-2025-38323.
   </td>
  </tr>
  <tr>
   <td><strong>Asymmetric Init/Fini</strong>
   </td>
   <td>Did an error path execute a cleanup function (e.g., <code>uvc_status_unregister</code>, <code>xe_svm_fini</code>, <code>rproc_type_release</code>) before the corresponding initialization (<code>uvc_status_init</code>, <code>xe_svm_init</code>, <code>ida_alloc</code>) had successfully run, causing the finalizer to operate on uninitialized fields (NULL dereference or deadlock)?
   </td>
   <td>CVE-2024-58059, CVE-2025-38309.
   </td>
  </tr>
  <tr>
   <td><strong>Resource Leak/Missing Cleanup</strong>
   </td>
   <td>Did the error path skip a required paired cleanup call (e.g., skipping <code>finish_mount_kattr()</code> after resources were acquired) or fail to free an old buffer before assigning a new one (memory leak)?
   </td>
   <td>CVE-2025-38247, CVE-2025-38258.
   </td>
  </tr>
  <tr>
   <td><strong>Double Free / Ownership Violation</strong>
   </td>
   <td>Did the error path free two pointers (<code>mc_bus</code>, <code>mc_dev</code>) that may alias the same underlying allocation or did a helper function free memory that the caller was responsible for freeing?
   </td>
   <td>CVE-2025-38313, CVE-2025-38341.
   </td>
  </tr>
</table>