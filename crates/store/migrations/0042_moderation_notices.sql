-- A silence, a suspension, a refused registration and their reversal all change what a
-- person may do. Until now the only record of the decision was the moderator's audit row,
-- which the person cannot read: they signed in, found their posts no longer federating,
-- and had no sentence explaining it and no pointer at the appeal form (0039).
--
-- A `moderation` notification carries the decision to the account it is about. The
-- columns hold the same facts the audit row holds — the action, the moderator's text, the
-- rule when a rule decided — so a person reading one and a moderator reading the other see
-- one story. `note` keeps the single-sentence rendering a client without a moderation UI
-- can show, the shape 0039 gave a decided appeal.
ALTER TABLE notification DROP CONSTRAINT notification_kind_valid;
ALTER TABLE notification ADD CONSTRAINT notification_kind_valid
    CHECK (kind IN ('follow', 'favourite', 'reblog', 'mention', 'poll', 'status',
                    'appeal', 'moderation'));

-- The action in the audit log's vocabulary (`account_silence`, `account_unsuspend`), not a
-- second spelling of it: the console and the person's page must not disagree about what
-- happened. `warn` is the one action here that changes nothing about the account.
ALTER TABLE notification ADD COLUMN moderation_action text
    CONSTRAINT notification_moderation_action_check
    CHECK (moderation_action IS NULL
           OR moderation_action IN ('warn', 'silence', 'suspend', 'reject', 'approve',
                                    'enable', 'unsilence', 'unsuspend'));

-- The moderator's reason, verbatim. Its own column rather than prose inside `note` because
-- the client has to render it as the reason, and denormalising it into the sentence would
-- make "the same text as the audit row" a claim nobody can check.
ALTER TABLE notification ADD COLUMN moderation_reason text;

-- The name of the rule that decided, when a rule rather than a person did. A name, not an
-- id: a rule can be deleted, and the person is owed the words they were caught by.
ALTER TABLE notification ADD COLUMN moderation_rule text;

-- When the restriction ends, if it has an end. NULL is "until a moderator lifts it",
-- which is every restriction this server can apply today; the column exists so a timed
-- one can be told about without changing this table again.
ALTER TABLE notification ADD COLUMN moderation_expires_at timestamptz;

-- A moderation row without an action would be a sentence with no decision behind it.
ALTER TABLE notification ADD CONSTRAINT notification_moderation_shape
    CHECK (kind <> 'moderation' OR moderation_action IS NOT NULL);
