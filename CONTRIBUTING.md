# Contributing

Sherlock OSA is evidence-first. A pull request is ready only when it contains:

1. a narrow problem statement and acceptance criteria;
2. tests that fail before and pass after the change;
3. no weakening of mission scope, signature, engine or evidence gates;
4. a threat-model update for a new network, tool or secret boundary;
5. a licence review before adding any dependency or copied asset.

Run `python3 scripts/verify.py` before opening a pull request. New execution
adapters must default to `UNBACKED` until an end-to-end test proves the declared
effect and a separate verifier proves its postcondition.
