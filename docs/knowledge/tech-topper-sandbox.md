# tech-topper-sandbox — Uphold Topper widget sandbox (authed BOLA testing)

Reusable sandbox facts for the Uphold/Topper (Intigriti `upholdcom`) authed-BOLA lane.
Source: public docs **github.com/uphold/topper-docs** (`docs/environments.md`, `docs/flows/crypto-onramp.mdx`).
Host-specific live state (widget_id, signer, sessions) → memory `project_uphold_topper_bola` + hunt_cursor, NOT here.

## Environments
- Sandbox app: `https://app.sandbox.topperpay.com/` · REST: `https://api.sandbox.topperpay.com/`
- Prod app: `https://app.topperpay.com/` · REST: `https://api.topperpay.com/`
- Sessions start via a signed **bootstrap token**: `app.sandbox.topperpay.com/?bt=<JWS>` (ES256, header
  `kid`=key_id, payload `sub`=widget_id). Sandbox widget_id/key_id do NOT work in prod (separate signing key).

## Bypasses for fast test-account setup (sandbox only)
- **Email auth + phone verification codes** → type `000000` to bypass.
- **ID verification (KYC)** → skip the real ID upload by either: a whitelisted email domain, OR add `+kyc`
  to the email username (`user+kyc@domain.com`, `user+kyc+abc@domain.com`). KYC UI still shows (prod-like).

## Test cards (force payment outcomes) — entered in the BROWSER widget, NOT the token
Any expiry date and CVV are accepted for these.

| Card number      | Outcome                 | Type   | Country | Brand      |
|------------------|-------------------------|--------|---------|------------|
| 5318773012490080 | **success**             | debit  | US      | MasterCard |
| 4748972091871094 | amount_invalid          | debit  | US      | Visa       |
| 4818924250131070 | card_unauthorized       | debit  | GB      | Visa       |
| 4414745735532923 | card_declined_by_bank   | credit | US      | Visa       |
| 4086439018748730 | card_expired            | credit | US      | Visa       |
| 4532942248840268 | card_unsupported        | credit | AD      | Visa       |
| 4916426384864999 | request_data_invalid    | credit | US      | Visa       |
| 4929216735379028 | insufficient_funds      | credit | MT      | Visa       |
| 4916526184701927 | velocity                | credit | AE      | Visa       |

GOTCHA that wasted a session (2026-06-17): generic gateway test cards (`4242 4242 4242 4242`,
checkout.com `4543 4740 0224 9996`) are NOT on this table → "card couldn't be linked". Use `5318773012490080`.
In `crypto_offramp` only **debit** cards matching the user's residence country are accepted.

## Crypto asset / settlement
- Sandbox has limited testnet funds. **Use `XRP` for testing** — other assets (incl. ETH) can get stuck
  "indefinitely trying to create the blockchain transaction" (doc line). For a **BOLA proof you don't need
  settlement** — the order RECORD exists once card payment is captured, which is enough for `orderById(id)`
  / `account(id)` to return it. XRP only matters if you need the order to fully settle on-chain.

## Bootstrap-token payload knobs (crypto-onramp)
- `source` {amount, asset:"USD", paymentMethod{network:"card"|"apple-pay"|"google-pay"|"paypal"|"venmo"|"pix"|"sepa"}}
- `target` {address, asset, network, label, allowedAssets[]}
- `simulation` {country:"US"} — sets the simulated country pre-auth (ignored once user authenticated → real country).
- `partner` {continueUrl, displayName, fee{percentage}, validation{device{ip,user-agent}}} — device validation
  must MATCH the user's actual IP/UA or session-init fails (can be plain or sha256-hashed).

## PayPal/Venmo test accounts (US only) — do NOT alter creds / enable MFA / "remember device"
- PayPal: `testpaypal@topper.com` / `PaypalP@y12345` (US)
- Venmo: `pwv-test-user2` or `pwv-test-user3` / `VenmoP@y12345` (US)

## Anti-fraud / repeater note (reusable across Uphold)
Oscilar anti-fraud SDK hooks `window.fetch` (scripted fetch → "Failed to fetch") but NOT `XMLHttpRequest`:
capture a real authed request, replay via sync XHR with captured headers + swapped (OWNED) id → 200. No Burp.
