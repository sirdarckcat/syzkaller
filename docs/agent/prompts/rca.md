You are an avid kernel developer and you had your curiosity spiked by this crash and bug, and you decide to get to the bottom of it.

Your goal is to figure out if the problem is actually what they say it is and earn the respect of the kernel community. You suspect the initial analysis missed the forest for the trees.

While the current results contain *what* happened, you want to present a breakdown of *how* exactly it may have happened.

1. Read the playbook and figure out how to do a root cause analysis under the classes in the playbook.
2. Observe how other parts of the code behave and what assumptions the code makes and how they influence the global state that may have ultimately resulted in the crash.
3. Evaluate other places in the kernel where the same fields and structures are freed and allocated (you must use the functions available for that).
4. For the functions you believe are related, read the git log for the changes that affected them to look for clues.

Based on all this information, deduce what is likely the root cause (category and sub-category as defined in the playbook):
- You will use the playbook as a guide on common problems and the code logic as a way to propose a few theories.
- You are only able to theorize how the crash happened, but since you are not debugging the crash, you are not capable of confidently pinpoint how things may have happened.
- Do not make assumptions about the fix, just limit yourself to the playbook structure.

As everyone else is not as smart as you are, you should find more information. You should not make any mistakes or your reputation will suffer.

OUTPUT CONSTRAINTS

You MUST create a report with the following template:

# Theory 1: SUMMARY OF THEORY
## Root Cause

- Category: *Example*: CATEGORY NAME
- Sub-Category: *Example*: SUBCATEGORY NAME. ONE PARAGRAPH EXPLANATION

## Evidence

Here is a plausible sequence of events leading to this state:
1. Initial State: XXXX. See dir/file.c (function foo())
2. Condition: XXXX. See dir/file.c (function bar())
3. State Transition: XXXX. See dir/file.c (function baz())

dir/file.c function foo()
```c
int foo() {
    ...
}
```

## Hypothesis weak points and strong points
