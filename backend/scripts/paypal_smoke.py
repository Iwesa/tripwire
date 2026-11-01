"""Day-1 smoke test: proves your sandbox credentials + Payouts work BEFORE you build on them.

    cd backend && PAYPAL_CLIENT_ID=... PAYPAL_CLIENT_SECRET=... \
        python scripts/paypal_smoke.py <sandbox-personal-account-email>

Sends a $1.00 sandbox payout. If Payouts is not enabled on your sandbox business app you will see
a PayPal error body here - fix it now, not on Nov 10. (Unverified from authoring environment.)
"""
import os
import sys
import asyncio
from decimal import Decimal

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from app.models import ToolCall  # noqa: E402
from app.paypal import PayPalClient, PayPalError  # noqa: E402

if len(sys.argv) != 2:
    sys.exit(__doc__)
client = PayPalClient(os.environ["PAYPAL_CLIENT_ID"], os.environ["PAYPAL_CLIENT_SECRET"])

async def execute_and_close():
    try:
        return await client.execute(ToolCall(
            "smoke", "create_payout", Decimal("1.00"), "USD", sys.argv[1],
            agent_note="tripwire smoke test",
        ))
    finally:
        await client.aclose()


try:
    out = asyncio.run(execute_and_close())
    print("OK payout batch:", out.get("batch_header", {}).get("payout_batch_id"), out.get("batch_header", {}).get("batch_status"))
except PayPalError as e:
    sys.exit(f"FAILED: {e}")
