-- Remote content that had nowhere to go: custom emoji tags, and the tallies of a poll
-- that was voted on somewhere else.
--
-- A peer's `Emoji` tag is not a hashtag and not a media attachment, so an ingested note
-- kept only the raw `:shortcode:` in its HTML. The row here is what lets a client swap it
-- for the image the peer sent.
CREATE TABLE status_emoji (
    status_id text NOT NULL REFERENCES status (id) ON DELETE CASCADE,
    shortcode text NOT NULL,
    url text NOT NULL,
    position integer NOT NULL DEFAULT 0,
    PRIMARY KEY (status_id, shortcode)
);

-- A federated poll's votes happened on the peer's instance, not here: writing them into
-- `poll_vote` would invent local accounts and make a refresh count them twice. The peer's
-- numbers are a snapshot that an `Update` replaces wholesale.
CREATE TABLE poll_tally (
    poll_id text NOT NULL REFERENCES poll (id) ON DELETE CASCADE,
    option_index integer NOT NULL CHECK (option_index >= 0),
    votes bigint NOT NULL CHECK (votes >= 0),
    PRIMARY KEY (poll_id, option_index)
);

-- The peer's `votersCount` is not the sum of the options on a multiple-choice poll, so it
-- is kept instead of derived from the tallies.
ALTER TABLE poll ADD COLUMN voters_count bigint NOT NULL DEFAULT 0;
