-- A challenge that may be answered forever is a guessing oracle: with ±1 step accepted,
-- three of a million six-digit codes are valid in any moment, so the five-minute window
-- needs a budget. The counter lives on the challenge rather than the account because the
-- lockout should last exactly as long as the thing being guessed: when the budget is spent
-- the row is deleted, and the attacker must produce the password again to get a new one.
-- An account-wide lockout would instead let anyone who knows an email address deny the
-- real owner a login for a fixed period, trading a guessing bound for a cheap DoS.
ALTER TABLE auth_2fa_challenge ADD COLUMN attempts integer NOT NULL DEFAULT 0;
