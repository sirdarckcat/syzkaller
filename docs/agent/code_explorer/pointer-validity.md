# Pointer Validity and Error Handling

If the fault is a **NULL Pointer Dereference (NPD)**, **Invalid Pointer Dereference (ERR_PTR)**, or crash due to an uninitialized variable, perform the following checks:


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
   <td><strong>Missing Allocation Check</strong>
   </td>
   <td>Did the Vulnerability Line involve a memory allocation function (<code>devm_kasprintf</code>, <code>devm_kzalloc</code>, <code>kunit_kzalloc</code>) or a data retrieval function (<code>smu_atom_get_data_table</code>) immediately followed by use without an <code>if (!ptr)</code> check?
   </td>
   <td>CVE-2024-57944, CVE-2024-57988, CVE-2025-38281.
   </td>
  </tr>
  <tr>
   <td><strong>API Misuse (NULL vs ERR_PTR)</strong>
   </td>
   <td>Did the Vulnerability Line involve checking a pointer (<code>P</code>) returned by an API? If <code>P</code> was expected to return <code>NULL</code> on failure (<code>devm_kzalloc</code>, <code>of_find_device_by_node</code>), did the code mistakenly use <code>IS_ERR(P)</code>?
   </td>
   <td>CVE-2024-58065, CVE-2024-57978, CVE-2024-58082.
   </td>
  </tr>
  <tr>
   <td><strong>Error Pointer Dereference</strong>
   </td>
   <td>If <code>P</code> was an error pointer (<code>ERR_PTR</code>), did the code fail to execute an unconditional exit (e.g., <code>goto out;</code>) after error detection, causing fall-through logic to dereference <code>P</code>?
   </td>
   <td>CVE-2024-57978, CVE-2025-38269.
   </td>
  </tr>
  <tr>
   <td><strong>Invalid Pointer/Index (Logic)</strong>
   </td>
   <td>Did the code rely on an incorrect logic assumption? E.g., Dereferencing an optional <code>NULL</code> pointer parameter (<code>len</code>) used for internal calculation, or assuming a pending command implies a non-NULL pointer (<code>cur_cmd</code>).
   </td>
   <td>CVE-2025-38304, CVE-2024-57981.
   </td>
  </tr>
</table>
