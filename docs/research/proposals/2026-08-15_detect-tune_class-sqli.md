# PROPOSAL (proposal) for docs/knowledge/class-sqli.md — detect-tune 2026-08-15
_Review and apply manually; not auto-merged into the KB._

## WAF-evasion addendum: retry the differential inside a JSON body (added 2026-08-15)
Research (BWAFSQLi, ACM TOSEM, tested against AWS/Cloudflare/F5/Imperva/Palo Alto WAFs) confirms
JSON-encoded injection payloads bypass signature rules tuned for URL/form-param injection. Practical
effect on our `'` vs `''` differential primitive: a clean/no-diff result on a JSON-API endpoint sitting
behind a WAF is NOT sufficient to call the endpoint safe — WAF rules commonly don't inspect JSON body
field values the same way. Before marking a JSON-API param `sqli:killed`, retry the differential with
the payload placed as a JSON body field value (not just query string) to rule out a WAF-masked false
negative.
Source: https://dl.acm.org/doi/10.1145/3788286
