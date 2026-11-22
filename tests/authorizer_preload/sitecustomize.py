"""Installed on PYTHONPATH only for verification subprocesses.

Python imports sitecustomize at startup. The verification scripts then talk
to the stand-in control plane instead of AWS.
"""

from authorizer_world import install_from_env

install_from_env()
