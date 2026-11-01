"""Optional Lakera Guard integration for prompt-injection classification."""
from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from typing import Awaitable, Callable

import httpx


_BASE64_TOKEN = re.compile(
    r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{16,8192}={0,2}(?![A-Za-z0-9+/_-])"
)


def _classification_text(text: str) -> str:
    normalized = unicodedata.normalize("NFKC", text)
    normalized = "".join(
        char for char in normalized if unicodedata.category(char) != "Cf"
    )
    variants = [text, normalized]
    for token_index, match in enumerate(_BASE64_TOKEN.finditer(normalized)):
        if token_index == 32:
            break
        token = match.group(0)
        try:
            decoded = base64.b64decode(
                token + "=" * (-len(token) % 4),
                altchars=b"-_",
                validate=True,
            ).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        printable = sum(char.isprintable() or char.isspace() for char in decoded)
        if decoded and printable / len(decoded) >= 0.85:
            decoded = unicodedata.normalize("NFKC", decoded)
            decoded = "".join(
                char for char in decoded if unicodedata.category(char) != "Cf"
            )
            variants.append(decoded)
    return "\n".join(dict.fromkeys(variants))


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
            {
                "messages": [{"role": "user", "content": _classification_text(text)}],
                "breakdown": True,
            },
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
