Read `CLAUDE.md` to route your understanding of the project.
Read `docs/ARCHITECTURE.md` and `.harness/tech_debt_tracker.md` for context.
Open `.harness/specs.md`.
Search the codebase with helper agents to understand the current implementation. Never assume an item is not already implemented.
Pick the most important UNFINISHED logical unit from `.harness/specs.md`.
Implement it. 
Run the test suite (`cd backend && python3 -m unittest discover -s tests -t .`).
If the tests pass: tick the checkbox in `.harness/specs.md`, write a detailed commit message, commit the code, and stop.
If tests fail: DO NOT force a commit. Fix the code or instructions.
If you hit an external blocker you cannot solve, write the exact error in `.harness/blocked.md` and stop.