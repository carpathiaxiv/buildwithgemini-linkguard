# ruff: noqa
# Copyright 2026 Google LLC

from google.adk.agents import Agent
from google.adk.apps import App
from google.adk.models import Gemini
from google.genai import types

from .tools import inspect_and_capture_url, store_scan_result, lookup_scan_history
from .a2ui_utils import a2ui_callback
from .instruction_prompt import INSTRUCTION

MODEL = "gemini-3.6-flash"

instruction = INSTRUCTION

root_agent = Agent(
    name="linkguard_agent",
    model=Gemini(
        model=MODEL,
        retry_options=types.HttpRetryOptions(attempts=3),
    ),
    instruction=instruction,
    tools=[inspect_and_capture_url, store_scan_result, lookup_scan_history],
    after_model_callback=a2ui_callback,
)

app = App(
    root_agent=root_agent,
    name="app",
)
