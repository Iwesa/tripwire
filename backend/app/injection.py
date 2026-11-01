"""Optional Lakera Guard integration for prompt-injection classification."""
from __future__ import annotations

import json
import urllib.request
from typing import Callable


def _lakera_transport(payload: dict, api_key: str, timeout: float = 5.0) -> dict:
    request = urllib.request.Request(
        "https://api.lakera.ai/v2/guard",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "content-type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - fixed https URL
        return json.loads(response.read().decode("utf-8"))


class LakeraGuardClassifier:
    def __init__(
        self,
        api_key: str,
        transport: Callable[[dict, str], dict] | None = None,
    ):
        if not api_key:
            raise ValueError("Lakera Guard API key is required")
        self.api_key = api_key
        self._transport = transport or _lakera_transport

    def __call__(self, text: str) -> bool:
        response = self._transport(
            {"messages": [{"role": "user", "content": text}], "breakdown": True},
            self.api_key,
        )
        if not isinstance(response, dict):
            raise ValueError("Lakera Guard returned an invalid response")
        if "flagged" not in response and "breakdown" not in response:
            raise ValueError("Lakera Guard returned no classification data")
        flagged = response.get("flagged", False)
        if not isinstance(flagged, bool):
            raise ValueError("Lakera Guard returned an invalid flagged value")

        breakdown = response.get("breakdown", [])
        if not isinstance(breakdown, list):
            raise ValueError("Lakera Guard returned an invalid breakdown")
        for result in breakdown:
            if not isinstance(result, dict):
                raise ValueError("Lakera Guard returned an invalid breakdown result")
            detected = result.get("detected", False)
            if not isinstance(detected, bool):
                raise ValueError("Lakera Guard returned an invalid detector result")
            flagged = flagged or detected
        return flagged
