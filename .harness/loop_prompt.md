Read `claude.md` to route your understanding of the project.
Read `docs/ARCHITECTURE.md` and `.harness/tech_debt_tracker.md` for context.
Open `.harness/specs.md`.
Search the codebase with helper agents to understand the current implementation. Pay special attention to `backend/app/main.py`, `backend/app/injection.py`, and `backend/tests/test_auth.py`.
Pick the most important UNFINISHED logical unit from `.harness/specs.md`.
Implement it.
Run the test suite (`cd backend && python3 -m unittest discover -s tests -t .`).
If the tests pass: tick the checkbox in `.harness/specs.md`, write a detailed commit message, commit the code, and stop.
If you hit an external blocker you cannot solve, write the exact error in `.harness/blocked.md` and stop.