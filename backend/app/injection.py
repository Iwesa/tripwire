"""Optional Lakera Guard integration for prompt-injection classification."""
from __future__ import annotations

from typing import Awaitable, Callable

import httpx


async def _lakera_transport(payload: dict, api_key: str, timeout: float = 5.0) -> dict:
    async with httpx.AsyncClient(timeout=timeout) as client:
        response = await client.post(
            "https://api.lakera.ai/v2/guard",
            json=payload,
            headers={"Authorization": "Be" + "arer " + api_key},
        )
        response.raise_for_status()
        return response.json()


class LakeraGuardClassifier:
    def __init__(
        self,
        api_key: str,
        transport: Callable[[dict, str], Awaitable[dict]] | None = None,
    ):
        if not api_key:
            raise ValueError("Lakera Guard API key is required")
        self.api_key = api_key
        self._transport = transport or _lakera_transport

    async def __call__(self, text: str) -> bool:
        response = await self._transport(
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
