ALTER TABLE account
    ADD COLUMN lossless_images_default boolean NOT NULL DEFAULT false,
    ADD COLUMN lossless_videos_default boolean NOT NULL DEFAULT false;
