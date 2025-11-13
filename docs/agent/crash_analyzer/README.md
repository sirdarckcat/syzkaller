# Immediate Point of Failure (IPoF)

The **Immediate Point of Failure (IPoF)** is the last execution step before the kernel crash occurs.

It consists of the following three elements:

1. **Failing Function:** The kernel function containing the buggy code path.
2. **Failing Operation:** The precise action that crashed the system (e.g., Pointer Dereference, Array Index Access, Division Operation, List Unlink, Function Call with Invalid Pointer).
3. **Failing Variable/State:** The specific pointer, array index, or numerical value whose invalid state triggered the fault (e.g., `NULL pointer X`, `index N`, `ERR_PTR Y`, `divisor Z`).

## Failing Operations

 - [NULL Pointer Dereference (NPD) / Invalid Pointer Use](null-ptr-deref.md)
 - [Array/Buffer Out-of-Bounds (OOB) Access](out-of-bounds.md)
 - [Lifetime/Concurrency Violations (UAF, Double Free)](use-after-free.md)
 - [Logic/Arithmetic Errors](arithmetic-errors.md)
