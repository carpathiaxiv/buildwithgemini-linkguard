# ruff: noqa
# Copyright 2026 Google LLC

from google.adk.agents import Agent
from google.adk.apps import App
from google.adk.models import Gemini
from google.genai import types

from a2ui.schema.manager import A2uiSchemaManager
from a2ui.basic_catalog.provider import BasicCatalog

from .tools import inspect_and_capture_url, store_scan_result, lookup_scan_history
from .a2ui_utils import a2ui_callback

MODEL = "gemini-3.6-flash"

schema_manager = A2uiSchemaManager(
    version="0.8",
    catalogs=[BasicCatalog.get_config("0.8")],
)

instruction = schema_manager.generate_system_prompt(
    role_description=(
        "You are LinkGuard, an AI Security & URL Threat Analysis Agent. "
        "When a user provides a URL or asks to inspect/check a web address, follow this exact workflow: "
        "1. Call `inspect_and_capture_url(url=...)` to fetch the destination URL, redirect trail, page title, text snippet, and capture a headless screenshot. "
        "2. Analyze the threat profile to determine the verdict ('Good', 'Suspicious', or 'Malicious'), category ('Clean', 'Phishing / Credential Harvesting', 'Malware', 'Scam / Deceptive', 'Defacement', etc.), and detailed explanation. "
        "3. Call `store_scan_result(...)` to persist the record and save the screenshot to Cloud Storage, obtaining the public `screenshot_url`. "
        "4. Return structured A2UI UI summarizing the scan findings and displaying the screenshot."
    ),
    workflow_description="Analyze the request, call the security tools, and return structured UI when appropriate.",
    ui_description=(
        "Keep every surface tiny and flat: ONE Card > ONE Column > a few Text rows. "
        "Never nest a Card inside a Card. "
        "Use ONLY these components: Card, Column, Row, Text, and Image. Do not use "
        "Table or Heading (unsupported), or Buttons, actions, or forms (they do "
        "nothing in adk web). "
        "In your surfaceUpdate, structure the components as: "
        "- A Card component as root whose child is the Column id. "
        "- A Column component whose children is an explicitList containing the text and image ids: {\"explicitList\": [\"text_verdict\", \"text_category\", \"text_dest\", \"text_desc\", \"img_screenshot\"]}. "
        "- Text components for the Verdict (e.g. '🛡️ LinkGuard Verdict: Good' or '⚠️ LinkGuard Verdict: Suspicious'), Category, Destination URL, and Explanation. "
        "- An Image component for the screenshot, but ONLY when you have a public https "
        "URL returned from `store_scan_result`. Set the Image url to that exact https link: "
        "{\"Image\": {\"url\": {\"literalString\": \"https://...\"}}}. Never point an "
        "Image at a bare filename, an artifact name, or a non-http(s) path. If you do "
        "not have a public URL, add a short Text line noting the image instead. "
        "No markdown in text; use the usageHint property ('h1', 'h2', 'body') for "
        "headings and emphasis. "
        "Output ONLY the raw A2UI JSON array containing beginRendering and surfaceUpdate — no prose, and never wrap it in "
        "<a2a_datapart_json> tags or 'kind'/'data'/'metadata' objects."
    ),
    include_schema=True,
    include_examples=True,
)

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
