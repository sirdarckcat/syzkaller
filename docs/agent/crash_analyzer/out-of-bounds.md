# Array/Buffer Out-of-Bounds (OOB) Access

The IPoF is the array access itself, using an index that violates the memory boundary.


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
   <td><strong>CVE-2024-57990</strong>
   </td>
   <td>Array index access <code>phy->clc[clc->idx]</code>.
   </td>
   <td>Index <code>clc->idx</code> equals <code>ARRAY_SIZE(phy->clc)</code> (off-by-one error).
   </td>
   <td>The bounds check used <code>></code> instead of <code>>=</code> against the array size in <code>mt7925_load_clc()</code>.
   </td>
  </tr>
  <tr>
   <td><strong>CVE-2024-57997</strong>
   </td>
   <td>Indexed access <code>wcn->chan_survey[i]</code>.
   </td>
   <td>The allocated size was <code>n_channels</code> bytes, but access treated it as <code>n_channels * sizeof(struct wcn36xx_chan_survey)</code>.
   </td>
   <td>Heap buffer under-allocation due to missing element size multiplication in <code>devm_kmalloc()</code>.
   </td>
  </tr>
  <tr>
   <td><strong>CVE-2025-38486</strong>
   </td>
   <td>Array writes to <code>ctrl->pconfig[i]</code>.
   </td>
   <td>Index <code>i</code> exceeded the array bounds, or <code>i</code> accessed the reserved/unused index 0.
   </td>
   <td>Writes were performed without bounds checking based on an incorrectly derived TX slot count in <code>qcom_swrm_set_channel_map</code>.
   </td>
  </tr>
  <tr>
   <td><strong>CVE-2025-38497</strong>
   </td>
   <td>Array index access <code>page[l - 1]</code>.
   </td>
   <td>Index value of <strong>-1</strong> (when input length <code>len</code> is 0).
   </td>
   <td>Missing check for <code>len > 0</code> before attempting to strip a trailing newline in <code>webusb_landingPage_store()</code>/<code>os_desc_qw_sign_store()</code>.
   </td>
  </tr>
  <tr>
   <td><strong>CVE-2025-39735</strong>
   </td>
   <td>Memory read/dump via <code>print_hex_dump()</code>.
   </td>
   <td>Read length (<code>size</code>) was calculated as a huge value (due to integer overflow from <code>EALIST_SIZE > INT_MAX</code>).
   </td>
   <td>Integer overflow produced a negative length that wrapped to a very large <code>size_t</code> value, driving unbounded reads past the slab boundary.
   </td>
  </tr>
</table>