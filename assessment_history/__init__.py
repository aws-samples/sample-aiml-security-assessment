"""Compare AI/ML security assessment runs over time.

``compare`` pairs the findings of two runs of one account and labels each one
(Resolved, Still open, Regressed, New, No longer reported, No longer
assessed, Not failing). ``models`` holds the shared record shapes and
``normalize`` the values in finding details that change on every run.

See docs/ASSESSMENT_HISTORY.md for the rules.
"""
