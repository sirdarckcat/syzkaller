# NULL Pointer Dereference (NPD) / Invalid Pointer Use

This occurs when a pointer is used without adequate validation, often immediately crashing the kernel. The IPoF is the line of code executing the dereference itself.

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
   <td><strong>CVE-2024-57944</strong>
   </td>
   <td>Dereferencing <code>indio_dev->name</code>.
   </td>
   <td><code>indio_dev->name</code> is <strong>NULL</strong> (due to allocation failure).
   </td>
   <td>Subsequent use of the pointer after unchecked allocation (<code>devm_kasprintf</code>) fails in <code>ads1298_init()</code>.
   </td>
  </tr>
  <tr>
   <td><strong>CVE-2024-57978</strong>
   </td>
   <td>Function call <code>pm_runtime_suspended()</code>.
   </td>
   <td><code>jpeg->pd_dev[i]</code> is an <strong>ERR_PTR</strong> (invalid pointer value).
   </td>
   <td>Passing an <code>ERR_PTR</code> to a function expecting a valid structure pointer in <code>mxc_jpeg_detach_pm_domains()</code>.
   </td>
  </tr>
  <tr>
   <td><strong>CVE-2024-57981</strong>
   </td>
   <td>Dereferencing <code>xhci->current_cmd</code> inside <code>xhci_mod_cmd_timer()</code>.
   </td>
   <td><code>xhci->current_cmd</code> is <strong>NULL</strong>.
   </td>
   <td>Timer setup proceeds unconditionally when ring pointers are unequal but no active command (<code>cur_cmd</code> is NULL).
   </td>
  </tr>
  <tr>
   <td><strong>CVE-2024-58081</strong>
   </td>
   <td>Function call <code>strlen()</code>.
   </td>
   <td>Device name pointer returned by <code>dev_name()</code> is <strong>NULL</strong>.
   </td>
   <td>Debugfs setup accesses the device name before it was properly initialized by <code>pm_genpd_init()</code>.
   </td>
  </tr>
  <tr>
   <td><strong>CVE-2025-38251</strong>
   </td>
   <td>Accessing <code>skb->truesize</code>.
   </td>
   <td><code>skb</code> pointer is <strong>NULL</strong>.
   </td>
   <td>Execution order bug: the code dereferenced <code>skb</code> in an early-return path (<code>!clip_devs</code>) before checking if <code>skb</code> itself was NULL.
   </td>
  </tr>
  <tr>
   <td><strong>CVE-2025-38316</strong>
   </td>
   <td>Dereferencing <code>phy->dev</code>.
   </td>
   <td><code>phy</code> pointer is <strong>NULL</strong>.
   </td>
   <td>Ordering flaw: <code>struct mt7996_dev *dev = phy->dev;</code> was executed <em>before</em> <code>if (!phy) return;</code> in <code>mt7996_set_monitor()</code>.
   </td>
  </tr>
  <tr>
   <td><strong>CVE-2025-39755</strong>
   </td>
   <td>Function call <code>strcmp(driver->name, ...)</code>.
   </td>
   <td><code>driver->name</code> is <strong>NULL</strong>.
   </td>
   <td>Driver initialization failed to set the top-level <code>.name</code> field in the structure definition.
   </td>
  </tr>
</table>