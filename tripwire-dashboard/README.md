# Tripwire dashboard

    npm install && npm run dev        # http://localhost:5173

Start the API with `TRIPWIRE_CORS=http://localhost:5173` (the default) and enter the API address and
`TRIPWIRE_ADMIN_TOKEN`. The token stays in memory and is never stored. Polls every 3-4 seconds.
Activity and Audit read `/audit`; Approvals use `/approvals`; Agents use `/mandates`, `/state/{id}`, `/mandates/{id}/revoke`.
