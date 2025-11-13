# Memory Bounds and Input Integrity

If the fault is an **Out-of-Bounds (OOB) Access** (read or write), **Stack/Heap Overflow**, or **Integer Overflow** leading to undersized allocation, perform the following checks:


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
   <td><strong>Index/Array Bounds Check</strong>
   </td>
   <td>Was an index derived from user space/firmware/logic used without checking its full range (<code>[0, ARRAY_SIZE-1]</code>)? Check for off-by-one errors (e.g., using <code>></code> instead of <code>>=</code> against <code>ARRAY_SIZE</code>) or missing non-negative check for returned IDs/indices.
   </td>
   <td>CVE-2024-57990, CVE-2024-57983, CVE-2025-38286.
   </td>
  </tr>
  <tr>
   <td><strong>Size Calculation Error (OOB Write)</strong>
   </td>
   <td>Did the kernel allocate memory based on an incorrect calculation (e.g., using element <em>count</em> instead of <em>count * sizeof(element)</em>) or fail to account for mandatory overhead (e.g., reserved ID byte)?
   </td>
   <td>CVE-2024-57997, CVE-2025-38495.
   </td>
  </tr>
  <tr>
   <td><strong>Input Length Validation</strong>
   </td>
   <td>Did the function read/write based on an input size (<code>len</code>, <code>data_size</code>, <code>prop->length</code>) without verifying it respects the <em>minimum required structure size</em> or the <em>maximum fixed destination size</em>?
   </td>
   <td>CVE-2025-38315, CVE-2025-38249, CVE-2025-38497.
   </td>
  </tr>
  <tr>
   <td><strong>Integer Overflow in Size/Index</strong>
   </td>
   <td>Did arithmetic involving user-controlled lengths (<code>gl->tot_len</code>, <code>nr_apqns</code>, <code>cvt.f_refresh</code>) overflow native integers, leading to an undersized allocation or division by zero?
   </td>
   <td>CVE-2024-57973, CVE-2025-38312, CVE-2025-38257.
   </td>
  </tr>
</table>