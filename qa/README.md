# Automated regression tests

`qa_suite.py` is a Playwright suite with 274 checks. It covers the operational portal only. The HR Agent is out of scope.

This folder is not part of the website, so you don't need to upload it to GitHub.

## Run it
1. Serve the site folder locally:
   `python3 -m http.server 8800`
2. In another terminal, run:
   `python3 qa/qa_suite.py http://localhost:8800/ <admin password> <staff password>`

You need Python 3 and Playwright: `pip install playwright`, then `playwright install chromium`.

## Notes
- The suite writes QA records only into throwaway browser profiles. Your live page and your own browser are never changed.
- The password-change tests run against downloaded copies saved as `qa-export1.html` and `qa-export2.html` in the served folder. Delete those two files afterwards.
