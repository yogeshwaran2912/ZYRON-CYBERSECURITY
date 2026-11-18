# AI Code Review Guidelines – ZYRON Framework

> **Instructions for ChatGPT / Claude:**  
> When reviewing ZYRON codebase files, evaluate against this checklist and provide structured feedback.

---

## 1. Review Checklist

### A. Security & Scope Enforcement
- [ ] Does any active network lookup check `ScopeManager.verify_scope_or_raise()` beforehand?
- [ ] Does the code prevent directory traversal (e.g. `../` checks in filename inputs)?
- [ ] Are all SQL statements properly parameterized (`cursor.execute("... WHERE id = ?", (id,))`)?
- [ ] Does the code respect dry-run mode?
- [ ] Is sensitive client/target evidence protected locally without automatic external uploads?

### B. Python Quality & Standards (PEP 8)
- [ ] Type hints used on function signatures and return types?
- [ ] Proper exception handling with specific custom exceptions (`ZyronException`, `ValidationError`, `ScopeViolationError`)?
- [ ] No bare `except:` clauses?
- [ ] Useful docstrings and inline comments explaining complex cybersecurity concepts?

### C. Resource Efficiency (8 GB RAM Budget)
- [ ] Are database connections properly closed (using context managers)?
- [ ] Are file handles closed properly?
- [ ] Does the code avoid spinning up infinite background threads or memory leaks?

---

## 2. Review Output Format
When conducting manual AI code reviews, format responses as follows:
1. **Summary:** Brief assessment of the module/file reviewed.
2. **Security & Scope Compliance:** Pass / Fail with explanations.
3. **Identified Issues / Refactor Suggestions:** Clear code snippets showing the suggested fix.
4. **Pedagogical Explanation:** Simple explanation of the security theory behind the recommendation.
