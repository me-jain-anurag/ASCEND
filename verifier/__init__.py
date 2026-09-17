# verifier/ — ASCEND execution verifier (component A3).
#
# Executes privilege-escalation techniques against the isolated Docker lab and
# records truthful pass/fail outcomes. Those outcomes are ASCEND's ground truth:
# the labels the exploitability scorer trains on, and the verified_exploitable
# flag stamped on every vector in the environment graph.
#
# Entry point:  python -m verifier batch|verify|check
# Dependencies: docker, pyyaml (see requirements.txt)
