ALTER TABLE account
    ADD COLUMN lossless_images_allowed boolean NOT NULL DEFAULT true,
    ADD COLUMN lossless_videos_allowed boolean NOT NULL DEFAULT true;
