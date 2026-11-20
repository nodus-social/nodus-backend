-- The revisions of a post. A row is written only when an edit actually changes what the
-- post says: a peer that repeats an Update saying the same thing is not a new revision,
-- and listing it as one would teach a reader to distrust the history.
--
-- The row keeps the version that was written, not the version it replaced, so the newest
-- row is the current text and the table is the whole history by itself.
CREATE TABLE status_edit (
    id           bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    status_id    text        NOT NULL REFERENCES status (id) ON DELETE CASCADE,
    content      text        NOT NULL,
    spoiler_text text        NOT NULL DEFAULT '',
    sensitive    boolean     NOT NULL DEFAULT false,
    created_at   timestamptz NOT NULL DEFAULT now()
);

-- Reading a history asks for one post's revisions, newest first.
CREATE INDEX status_edit_status_idx ON status_edit (status_id, created_at DESC, id DESC);
