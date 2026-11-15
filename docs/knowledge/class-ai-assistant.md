# AI assistants embedded in a product — attack surface

Written 2026-09-16 off the Chime walk, where `Query.jade` turned out to be an AI assistant living
inside a banking app. The class is live and paying in 2026, and it is not yet saturated.

## Why it is worth the evening

An embedded assistant is two vulnerabilities stacked in one feature:

1. **An ordinary object-reference surface.** Conversations and messages have ids, and the resolvers
   that fetch them are as likely to miss an ownership check as any other resolver.
2. **A second-order execution boundary.** If the assistant holds tool access — reading balances,
   moving money, opening tickets — then text you get into its context is text it may ACT on. Writing
   into someone else's conversation is therefore not merely tampering; it is a prompt-injection path
   that borrows the victim's session and privileges.

Industry reporting through 2026 has converged on the same point: the interesting failures are agent
frameworks with real capability, up to and including tricking an agent into moving funds to the wrong
account. Systematic testing of these endpoints is still rare, which is exactly the dup-avoidance the
MOTTO asks for.

## The shape to look for in a schema

```
Query.<assistant>       conversation(conversation_id: ID)      <- READ by reference
                        conversations(first, after, ...)       <- does it scope to the session?
Mutation.<assistant>    create_conversation(initial_message)
                        post_message(conversation_id, ...)     <- WRITE by reference: the good half
                        submit_feedback(message_id: ID!, ...)  <- a THIRD id namespace, often looser
Message                 { id, role, content: JSON!, ... }      <- role is often client-supplied
```

Three separate id namespaces (conversation, message, feedback) usually mean three separate
authorisation checks, and they are rarely all present.

`content: JSON!` is worth its own look. A free-form JSON body typed only as `JSON` is unvalidated by
the schema, so whatever structure the model consumes is reachable — including, sometimes, a `role`
the caller sets, which is a direct system-prompt override.

## How to test it

- **Two owned accounts**, or one account with two conversations for a sibling differential. Create a
  conversation on each side, then cross the ids both ways. Both directions, always.
- **The impossible-id control first.** A random uuid distinguishes a real lookup from a bucketed
  constant before you read anything into a rejection.
- **Read then write.** Reading a stranger's chat is the familiar half and it may already be reported.
  The write half is where the novel finding is.
- **Chain honestly.** Injection alone is a Medium. Injection that demonstrably causes the assistant to
  take an action on the victim's account is the critical, and it needs the action shown, not asserted.

## Hard lines specific to this class

- Never post into a conversation you do not own, and never a guessed id. Two accounts you control, or
  nothing — the same rule as any IDOR, and it matters more here because the target is a live chat.
- Never read a stranger's conversation to "confirm" the bug. A sibling differential on your own two
  accounts proves it without touching anyone's data.
- Prompt-inject only your own assistant session. Demonstrating that the model follows injected
  instructions does not require a victim.

## Related

`class-idor.md` for the sibling-differential method and the bucketing-vs-lookup control.
`class-graphql.md` for locating these namespaces in an introspection dump.
