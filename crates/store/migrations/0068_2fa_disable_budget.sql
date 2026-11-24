-- Disabling the second factor is a session-authenticated action that spends a code, and
-- nothing in this router rate-limits /auth/*: a stolen session plus a loop could guess a
-- six-digit TOTP code and turn the factor off. The sign-in challenge budget in
-- 0065_two_factor_attempts.sql cannot cover this, because a signed-in caller has no
-- challenge row; the budget has to be keyed by the account being changed.
--
-- Policy: five consecutive wrong codes lock disabling for fifteen minutes. A successful
-- disable deletes the row, so a later re-enable starts from zero. A correct code inside a
-- window whose counter is already running is not allowed to clear it, otherwise an
-- attacker holding one valid code could interleave it with wrong ones and get unlimited
-- attempts. The counter is read under `SELECT ... FOR UPDATE` so two concurrent guesses
-- cannot both observe the same count.
CREATE TABLE account_2fa_disable_attempt (
    account_id      text PRIMARY KEY REFERENCES account (id) ON DELETE CASCADE,
    failed_attempts integer NOT NULL DEFAULT 0,
    -- Start of the current run of consecutive misses. A run older than the lock window
    -- has decayed, so a user who mistypes once a day never accumulates a lock.
    first_attempt_at timestamptz NOT NULL DEFAULT now(),
    -- NULL while the budget is available; a timestamp in the past is a lapsed lock and is
    -- treated the same as NULL (the next attempt starts a fresh run).
    locked_until    timestamptz
);
