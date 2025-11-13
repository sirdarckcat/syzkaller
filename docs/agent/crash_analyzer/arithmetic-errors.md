# Logic/Arithmetic Errors

The IPoF results from an illegal arithmetic operation derived from invalid state or user input.


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
   <td><strong>CVE-2025-38297</strong>
   </td>
   <td>Arithmetic division.
   </td>
   <td>Divisor <code>table[i].performance</code> is <strong>zero</strong>.
   </td>
   <td><code>em_compute_costs()</code> ran for non-CPU devices where the performance state was uninitialized (zero).
   </td>
  </tr>
  <tr>
   <td><strong>CVE-2025-38312</strong>
   </td>
   <td>Arithmetic division inside <code>fb_cvt_hperiod()</code>.
   </td>
   <td>Divisor <code>cvt.f_refresh</code> is <strong>zero</strong>.
   </td>
   <td>Integer overflow caused by doubling a large user-supplied value (<code>mode->refresh</code>) for interlaced modes, making the value wrap to zero.
   </td>
  </tr>
  <tr>
   <td><strong>CVE-2024-57973</strong>
   </td>
   <td>Allocation call <code>alloc_skb(wrapped_size)</code>.
   </td>
   <td>Calculated size wraps to a <strong>too-small value</strong>.
   </td>
   <td>Integer overflow during addition of allocation size terms (<code>gl->tot_len + sizeof(...)</code>) on 32-bit systems.
   </td>
  </tr>
</table>