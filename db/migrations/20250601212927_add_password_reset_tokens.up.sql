CREATE TABLE password_reset_tokens (
	id SERIAL,
	user_id INT4 CONSTRAINT password_reset_tokens_user_id_ref REFERENCES users (id) ON DELETE CASCADE,
	token VARCHAR(64) NOT NULL UNIQUE,
	created_at INT4 NOT NULL,
	expires_at INT4 NOT NULL,
	used_at INT4,
	last_updated INT4 NOT NULL,
	deleted INT2 DEFAULT '0',
	PRIMARY KEY (id)
);

CREATE INDEX password_reset_tokens_user_id_idx ON password_reset_tokens(user_id);
CREATE INDEX password_reset_tokens_token_idx ON password_reset_tokens(token);
CREATE INDEX password_reset_tokens_expires_at_idx ON password_reset_tokens(expires_at);
CREATE INDEX password_reset_tokens_created_at_idx ON password_reset_tokens(created_at);
