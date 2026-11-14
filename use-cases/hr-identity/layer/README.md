# hr-identity Lambda layer

The Lambda in `../lambda/` imports `pg8000` to connect to the HR database
with an RDS IAM token. `pg8000` is a pure-Python driver, so the layer has
no architecture-specific wheel to track.

The layer's `python/` directory is populated **at CDK synth time** by the
helper in `../stack.py` (`_install_pg8000_into_layer`), which runs a pinned
`pip install --target python/ pg8000==1.31.5` with the deployer's own
Python. Idempotent: a `.pg8000-pin` sentinel skips the install when the
    10|pin has not moved.

This replaces the earlier manual step that asked the operator to run a
pip-install before `cdk deploy`. Forgetting that step produced a deploy
that looked healthy but failed every sign-in with
`ModuleNotFoundError: pg8000` in the pre-token trigger logs.

`python/` is the directory Lambda adds to `sys.path` for a Python layer
(AWS Lambda layer paths). The asset hash CDK computes changes when
`python/` fills up, which forces a layer-version bump on the next
    20|`cdk deploy` — no manual version tracking.

The installed site-packages and the sentinel are ignored by git (see
`python/.gitignore`); only this README and the empty-directory marker
are committed.
