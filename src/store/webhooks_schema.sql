--
-- Webhook storage SQL schema
--
CREATE TABLE IF NOT EXISTS "webhooks"
(
  -- Repository ID
  "repo_id" TEXT NOT NULL,
  -- Webhook URL
  "url" TEXT NOT NULL,
  -- Possible secret required to be sent along with the webhook
  "secret" TEXT,
  -- Webhook content type
  "content_type" TEXT NOT NULL DEFAULT 'application/json',
  --- Webhook creation time
  "created_at" INTEGER NOT NULL,
  --
  PRIMARY KEY (repo_id, url)
) STRICT;
