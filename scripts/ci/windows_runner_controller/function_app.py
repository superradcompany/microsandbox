"""Private Azure timer entry point; no HTTP trigger or PR checkout."""

import json
import logging
import os
import time

import azure.functions as func
from azure.identity import ManagedIdentityCredential

from clients import AppToken, Azure, BlobLeases, GitHub
from controller import Controller, reap_expired_resources
from models import Config

app = func.FunctionApp()
# Azure's HTTP policy logs resource URLs at INFO. Keep that noise and private
# infrastructure identifiers out of routine application diagnostics.
logging.getLogger("azure").setLevel(logging.WARNING)
credential = ManagedIdentityCredential()
app_token = AppToken()


@app.timer_trigger(schedule='*/15 * * * * *', arg_name='timer', run_on_startup=False, use_monitor=True)
def reconcile(timer: func.TimerRequest):
    cfg = Config(**json.loads(os.environ['WINDOWS_CI_CONFIG']))
    azure = Azure(credential)
    # Azure's monitored timer runs one instance at a time across host scale-out.
    # Expiry runs before opening lease storage or requesting a GitHub token.
    try:
        reap_expired_resources(cfg, azure, time.time())
    except Exception as error:
        logging.error('Expiry reconciliation failed (%s)', type(error).__name__)
    try:
        Controller(cfg, azure, GitHub(cfg, app_token), BlobLeases()).tick()
    except Exception as error:
        logging.error('Runner reconciliation deferred (%s)', type(error).__name__)
