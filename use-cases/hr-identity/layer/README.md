# hr-identity Lambda layer

The Lambda in `../lambda/` imports `pg8000` to connect to the HR database
with an RDS IAM token. `pg8000` is a pure-Python driver, so the layer has
no architecture-specific wheel to track.

CDK stages this directory as the layer's asset at synth time. The layer is
empty by default so this repository can be cloned and synthesized offline
without network calls. Before `cdk deploy`, install pg8000 into
`python/` so Lambda loads it on cold start:

```bash
python3 -m pip install \
  --no-cache-dir \
  --target use-cases/hr-identity/layer/python \
  --requirement use-cases/hr-identity/lambda/requirements.txt
```

`python/` is the directory Lambda adds to `sys.path` for a Python layer
(AWS Lambda layer paths). The asset hash CDK computes changes when
`python/` fills up, which forces a layer-version bump on the next
`cdk deploy` — no manual version tracking.

The installed site-packages are ignored by git (see `python/.gitignore`);
only this README and the empty-directory marker are committed.
