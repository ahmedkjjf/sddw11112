# Security Specification - Neural Security Decoder

## Data Invariants
1. A user can only read and write their own profile data.
2. Deobfuscation logs must be owned by the user who created them.
3. Users cannot modify their own `credits` or `isPremium` status (must be handled by server/admin later, but for now we block client updates to these critical fields).
4. All IDs must be valid strings.
5. Logs are immutable once created.

## The "Dirty Dozen" Payloads (Denial Tests)
1. **Identity Spoofing**: Attempt to create a user profile with a different UID than `auth.uid`.
2. **Resource Poisoning**: Create a log with a 2MB `originalSnippet`.
3. **Privilege Escalation**: Update `isPremium` to `true` while being a normal user.
4. **Credit Injection**: Update `credits` to 999999.
5. **PII Leak**: Read another user's profile in the `/users/` collection.
6. **Log Hijacking**: Read another user's deobfuscation logs.
7. **Malformed ID**: Use recursive or overly long document IDs.
8. **Invalid Timestamp**: Provide a fake client-side `createdAt` date.
9. **Field Injection**: Add a `role: "admin"` field to a user profile.
10. **State Shortcut**: Bypass terminal state logic (not applicable here yet, but good to keep in mind).
11. **System Field Modification**: Change the `modelUsed` after a log is created.
12. **Anonymous Write**: Attempt to write data without being authenticated.

## Implementation Strategy
- Use `isValidUser` and `isValidLog` helpers.
- Use `affectedKeys().hasOnly()` to restrict updates to non-critical fields.
- Use `exists()` or `get()` checks for relational consistency if needed.
