"""ASCEND lab generator — turn a scenario blueprint into a buildable lab.

See docs/10 section 4. The generator is an *input producer*: it emits the same
seed scripts and docker-compose layout the hand-written lab/ uses, so the
collector / enumerator / verifier / chokepoint code does not change.
"""
