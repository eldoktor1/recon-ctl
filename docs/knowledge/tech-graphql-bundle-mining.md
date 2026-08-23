# Mining GraphQL operations out of a SPA bundle

Reusable technique. Recovered two filed SEEK findings (`reinstate`, `updateUserDetails`) and the whole
job-posting surface. Written up after repeatedly ALMOST missing operations because of a lazy search.

## The rule: enumerate everything first, filter second

Do NOT search for the operation you expect (`/[Dd]raft/`, `/reinstate/`). Enumerate EVERY operation
name in the bundle, print the list, then pick. On SEEK, searching for mutations whose *name* contained
"draft" returned NOTHING while `UpdateDraftJob` and `CreateDraftJob` were sitting right there, because
they were stored in a different form than the regex assumed.

## Bundles hold GraphQL in TWO forms. Always search BOTH.

1. **Readable gql template literals**

   ```
   mutation SetHirerAccountUsersJobAccessV2($input: SetHirerAccountUsersJobAccessV2Input!) {
     setHirerAccountUsersJobAccessV2(input: $input) { success }
   }
   ```
   Regex: `/mutation\s+([A-Za-z0-9_]+)/g`

2. **Pre-parsed AST objects** (what Apollo/graphql-tag produce at build time)

   ```
   operation:"mutation",name:{kind:"Name",value:"UpdateDraftJob"}
   ```
   Regex: `/operation:[`"']mutation[`"'],name:\{kind:[`"']Name[`"'],value:[`"']([A-Za-z0-9_]+)[`"']/g`

   The FIELD name is a separate token from the OPERATION name and often differs in case or wording.
   `ReinstateUserStatus` (operation) vs `reinstate` (field) is why an entire earlier probe sweep looked
   uniformly hardened: every probe sent the operation name as the field and got a masked error.

## Quote style varies within one codebase

Minifiers emit backticks, double quotes and single quotes in different chunks. Match all three:
`[`"']`. A grab that hardcoded backticks returned null for four operations that were present in
double quotes.

## Scan every chunk, and do not clobber the one you keep

An app ships several bundles. On SEEK's job-posting-ui the operations were split across
`main-*.js` (1MB) and `470-*.js` (11MB). A loop that assigned each fetched bundle to the same
`window.__x` left only the LAST one in memory while the accumulator held results from both, which made
a later follow-up search come back empty against the wrong bundle.

## Recovering the input SHAPE once you have the name

Take a ~1000 char window from the operation-name match and pull the ordered `value:"..."` tokens. That
yields, in order: operation name, variable name, INPUT TYPE name, root field name, payload type, and
the first selected fields. Example output for one window:

    UpdateDraftJob, input, UpdateDraftJobInput, updateDraftJob, input, input,
    UpdateDraftJobPayload, draftId

Then confirm against the live API with the coercion oracle: declare a variable of that exact input type
with `{}` and read the BAD_USER_INPUT errors, which enumerate every required field and its type while
executing nothing.

## The trap that makes probing useless

A masked `GRAPHQL_VALIDATION_FAILED / "Invalid request"` is returned for a wrong FIELD name AND for a
wrong TYPE name. So probing candidate field names while guessing an input type you invented (e.g.
`$input: JSON`) masks on every attempt and DISCRIMINATES NOTHING. Five such probes were recorded on
SEEK and proved exactly zero. Get the type name from the bundle first; never infer absence from a
masked error.

## Checklist

- [ ] list every `script[src]` on the authenticated page for the app's own origin
- [ ] fetch each, note length, keep them separately
- [ ] enumerate readable mutation/query names AND AST operation names, unfiltered
- [ ] diff that list against what the UI exposes - the gap is the interesting surface
- [ ] for each target, grab the window and read operation / input type / field / payload
- [ ] confirm the shape with a `{}` coercion probe before sending anything real
