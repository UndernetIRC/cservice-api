CREATE TABLE languages (
	id SERIAL,
	code VARCHAR( 16 ) UNIQUE,
	name VARCHAR( 16 ),
	last_updated INT4 NOT NULL,
	deleted INT2 DEFAULT '0',
	PRIMARY KEY(id)
);

CREATE TABLE translations (
	language_id INT4 CONSTRAINT translations_language_id_ref REFERENCES languages ( id ),
	response_id INT4 NOT NULL DEFAULT '0',
	text TEXT,
	last_updated INT4 NOT NULL,
	deleted INT2 DEFAULT '0',

	PRIMARY KEY (language_id, response_id)
);

CREATE TABLE help (
	topic VARCHAR(20) NOT NULL,
	language_id INT4 CONSTRAINT help_language_id_ref REFERENCES languages ( id ),
	contents TEXT
);

CREATE INDEX help_topic_idx ON help (topic);
CREATE INDEX help_language_id_idx ON help (language_id);

CREATE TABLE channels (
	id SERIAL,
	name TEXT NOT NULL UNIQUE,
	flags INT4 NOT NULL DEFAULT '0',
	mass_deop_pro INT2 NOT NULL DEFAULT 3,
	flood_pro INT4 NOT NULL DEFAULT '0',
	url VARCHAR (128),
	description VARCHAR (300),
	comment VARCHAR (300),
	keywords VARCHAR(300),
	registered_ts INT4,
	channel_ts INT4 NOT NULL,
	channel_mode VARCHAR(26),
	userflags INT2 DEFAULT '0',
	limit_offset INT4 DEFAULT '3',
	limit_period INT4 DEFAULT '20',
	limit_grace INT4 DEFAULT '1',
	limit_max INT4 DEFAULT '0',
	no_take INT4 DEFAULT '0',
	last_updated INT4 NOT NULL,
	deleted INT2 DEFAULT '0',
	max_bans INT4 DEFAULT '0',
	welcome VARCHAR(300) DEFAULT '',
	PRIMARY KEY (id)
);

CREATE UNIQUE INDEX channels_name_idx ON channels(LOWER(name));

CREATE TABLE bans (
	id SERIAL,
	channel_id INT4 CONSTRAINT bans_channel_id_ref REFERENCES channels (id),
	banmask VARCHAR (128) NOT NULL,
	set_by VARCHAR (128),
	set_ts INT4,
	level INT2,
	expires INT4,
	reason VARCHAR (300),
	last_updated INT4 NOT NULL,
	deleted INT2 DEFAULT '0',
	PRIMARY KEY (banmask,channel_id)
);

CREATE INDEX bans_expires_idx ON bans(expires);
CREATE INDEX bans_channelkey_idx ON bans(channel_id);

CREATE TABLE users (
	id SERIAL,
	user_name TEXT NOT NULL,
	password VARCHAR (40) NOT NULL,
	email TEXT,
	url  VARCHAR(128),
	question_id INT2,
	verificationdata VARCHAR(30),
	language_id INT4 CONSTRAINT language_channel_id_ref REFERENCES languages (id),
	public_key TEXT,
	post_forms int4 DEFAULT 0 NOT NULL,
	flags INT2 NOT NULL DEFAULT '0',
	last_updated_by VARCHAR (128),
	last_updated INT4 NOT NULL,
	deleted INT2 DEFAULT '0',
	tz_setting VARCHAR(255) DEFAULT '',
	signup_cookie VARCHAR(255) DEFAULT '',
	signup_ts INT4,
	signup_ip VARCHAR(15),
	maxlogins INT4 DEFAULT 1,
	totp_key  VARCHAR(60) DEFAULT '',
	PRIMARY KEY ( id )
) ;

CREATE INDEX users_username_idx ON users( lower(user_name) );
CREATE INDEX users_email_idx ON users( lower(email) );
CREATE INDEX users_signup_ts_idx ON users( signup_ts );
CREATE INDEX users_signup_ip_idx ON users( signup_ip );

CREATE TABLE users_lastseen (
	user_id INT4 CONSTRAINT lastseen_users_id_ref REFERENCES users ( id ),
	last_seen INT4,
	last_hostmask VARCHAR( 256 ),
	last_ip VARCHAR( 256 ),
	last_updated INT4 NOT NULL,
	PRIMARY KEY (user_id)
);

CREATE TABLE user_sec_history (
	user_id INT4 NOT NULL,
	user_name TEXT NOT NULL,
	command TEXT NOT NULL,
	ip VARCHAR( 256 ) NOT NULL,
	hostmask VARCHAR( 256 ) NOT NULL,
	timestamp INT4 NOT NULL
);

CREATE TABLE levels (
	channel_id INT4 CONSTRAINT levels_channel_id_ref REFERENCES channels ( id ),
	user_id INT4 CONSTRAINT levels_users_id_ref REFERENCES users ( id ),
	access INT4 NOT NULL DEFAULT '0',
	flags INT2 NOT NULL DEFAULT '0',
	suspend_expires INT4 DEFAULT '0',
	suspend_level INT4 DEFAULT '0',
	suspend_by VARCHAR( 128 ),
	suspend_reason VARCHAR( 300 ),
	added INT4,
	added_By VARCHAR( 128 ),
	last_Modif INT4,
	last_Modif_By VARCHAR( 128 ),
	last_Updated INT4 NOT NULL,
	deleted INT2 DEFAULT '0',
	PRIMARY KEY( channel_id, user_id )
);

CREATE INDEX levels_access_idx ON levels( access ) ;
CREATE INDEX levels_userid_idx ON levels( user_id ) ;
CREATE INDEX levels_suspendexpires_idx ON levels( suspend_expires ) WHERE suspend_expires <> 0;

CREATE TABLE channellog (
	ts INT4,
	channelID INT4 CONSTRAINT channel_log_ref REFERENCES channels ( id ),
	event INT2 DEFAULT '0',
	message TEXT,
	last_updated INT4 NOT NULL,
	deleted INT2 DEFAULT '0'
);

CREATE INDEX channellog_channelID_idx ON channellog(channelID);
CREATE INDEX channellog_event_idx ON channellog(event);

CREATE TABLE userlog (
	ts INT4,
	user_id INT4 CONSTRAINT user_log_ref REFERENCES users ( id ),
	event INT4 DEFAULT '0',
	message TEXT,
	last_updated INT4 NOT NULL
);

CREATE INDEX userlog_channelID_idx ON userlog(user_id);
CREATE INDEX userlog_event_idx ON userlog(event);

CREATE TABLE supporters (
	channel_id INT4 CONSTRAINT channel_supporters_ref REFERENCES channels ( id ),
	user_id INT4 CONSTRAINT users_supporters_ref REFERENCES users( id ),
	support CHAR DEFAULT '?',
	noticed CHAR NOT NULL DEFAULT 'N',
	reason TEXT,
	join_count INT4 DEFAULT '0',
	last_updated INT4 NOT NULL,
	deleted INT2 DEFAULT '0',
	PRIMARY KEY(channel_id,user_id)
);

CREATE INDEX supporters_support_idx ON supporters(support);
create index supporters_user_id_idx ON supporters(user_id);

CREATE TABLE pending (
	channel_id INT4 CONSTRAINT pending_channel_ref REFERENCES channels (id),
	manager_id INT4 CONSTRAINT pending_manager_ref REFERENCES users (id),
	created_ts INT4 NOT NULL,
	check_start_ts INT4 NOT NULL,
	status INT4 DEFAULT '0',
	join_count INT4 DEFAULT '0',
	unique_join_count INT4 DEFAULT '0',
	decision_ts INT4,
	decision TEXT,
	managername VARCHAR (80),
	reg_acknowledged CHAR DEFAULT 'N',
	comments TEXT,
	last_updated INT4 NOT NULL,
	description TEXT,
	reviewed CHAR NOT NULL DEFAULT 'N',
	first_init CHAR NOT NULL DEFAULT 'N',
	reviewed_by_id INT4 CONSTRAINT pending_review_ref REFERENCES users (id),
	PRIMARY KEY(channel_id)
);

CREATE INDEX pending_status_idx ON pending(status);
CREATE INDEX pending_manager_id_idx ON pending(manager_id);

CREATE TABLE pending_traffic (
	channel_id INT4 CONSTRAINT pending_traffic_channel_ref REFERENCES channels (id),
	ip_number inet,
	join_count INT4,
	PRIMARY KEY(channel_id, ip_number)
);

CREATE INDEX pending_traffic_channel_id_idx ON pending_traffic(channel_id);


CREATE TABLE pending_chanfix_scores (
	channel_id INT4 CONSTRAINT pending_chanfix_scores_channel_ref REFERENCES channels (id),
	user_id TEXT NOT NULL DEFAULT '0',
	rank INT4 NOT NULL DEFAULT '0',
	score INT4 NOT NULL DEFAULT '0',
	account VARCHAR(20) NOT NULL,
	first_opped VARCHAR(10),
	last_opped VARCHAR(20),
	last_updated INT4 NOT NULL DEFAULT date_part('epoch', CURRENT_TIMESTAMP)::int,
	first CHAR NOT NULL DEFAULT 'Y'
);

CREATE INDEX pending_chanfix_scores_channel_id_idx ON pending_chanfix_scores(channel_id);


CREATE TABLE domain (
	id SERIAL,
	domain varchar(1024) NOT NULL UNIQUE,
	flags INT2 NOT NULL DEFAULT '1',
	last_updated INT4 NOT NULL,
	deleted INT2 DEFAULT '0',

	PRIMARY KEY(id)
);

CREATE INDEX domain_domain_idx ON domain(domain);

CREATE TABLE deletion_transactions (
	tableID INT4,
	key1 INT4,
	key2 INT4,
	key3 INT4,
	last_updated INT4 NOT NULL
);

CREATE TABLE noreg (
	id SERIAL,
	user_name TEXT,
	email TEXT,
	channel_name TEXT,
	type INT4 NOT NULL,
	never_reg INT4 NOT NULL DEFAULT '0',
	for_review INT4 NOT NULL DEFAULT '0',
	expire_time INT4,
	created_ts INT4,
 	set_by TEXT,
	reason TEXT
);

CREATE INDEX noreg_user_name_idx ON noreg (lower(user_name));
CREATE INDEX noreg_email_idx ON noreg (lower(email));
CREATE INDEX noreg_channel_name_idx ON noreg (lower(channel_name));
CREATE INDEX noreg_expire_time_idx ON noreg (expire_time);

CREATE TABLE notes (
	message_id SERIAL,
	user_id INT4 CONSTRAINT users_notes_ref REFERENCES users( id ),
	from_user_id INT4 CONSTRAINT users_notes_ref2 REFERENCES users( id ),
	message VARCHAR( 300 ),
	last_updated INT4 NOT NULL,
	PRIMARY KEY(message_id, user_id)
);

CREATE TABLE notices (
	message_id SERIAL,
	user_id INT4 CONSTRAINT users_notes_ref REFERENCES users( id ),
	message VARCHAR( 300 ),
	last_updated INT4 NOT NULL,
	PRIMARY KEY(message_id, user_id)
);

CREATE FUNCTION update_users() RETURNS TRIGGER AS '
BEGIN
	NOTIFY users_u;
	RETURN NEW;
END;
' LANGUAGE 'plpgsql';

CREATE FUNCTION update_channels() RETURNS TRIGGER AS '
BEGIN
	NOTIFY channels_u;
	RETURN NEW;
END;
' LANGUAGE 'plpgsql';

CREATE FUNCTION update_levels() RETURNS TRIGGER AS '
BEGIN
	NOTIFY levels_u;
	RETURN NEW;
END;
' LANGUAGE 'plpgsql';

CREATE FUNCTION update_bans() RETURNS TRIGGER AS '
BEGIN
	NOTIFY bans_u;
	RETURN NEW;
END;
' LANGUAGE 'plpgsql';

CREATE TRIGGER t_update_users AFTER UPDATE ON users FOR EACH ROW EXECUTE PROCEDURE update_users();
CREATE TRIGGER t_update_bans AFTER UPDATE ON bans FOR EACH ROW EXECUTE PROCEDURE update_bans();
CREATE TRIGGER t_update_channels AFTER UPDATE ON channels FOR EACH ROW EXECUTE PROCEDURE update_channels();
CREATE TRIGGER t_update_levels AFTER UPDATE ON levels FOR EACH ROW EXECUTE PROCEDURE update_levels();

CREATE FUNCTION new_user() RETURNS TRIGGER AS '
-- creates the users associated last_seen record
BEGIN
	INSERT INTO users_lastseen (user_id, last_seen, last_updated) VALUES(NEW.id, extract(epoch FROM now())::int, extract(epoch FROM now())::int);
	RETURN NEW;
END;
' LANGUAGE 'plpgsql';

CREATE TRIGGER t_new_user AFTER INSERT ON users FOR EACH ROW EXECUTE PROCEDURE new_user();

CREATE FUNCTION delete_user() RETURNS TRIGGER AS '
BEGIN
	INSERT INTO deletion_transactions (tableID, key1, key2, key3, last_updated)
	VALUES(1, OLD.id, 0, 0, extract(epoch FROM now())::int);
	RETURN OLD;
END;
' LANGUAGE 'plpgsql';

CREATE TRIGGER t_delete_user AFTER DELETE ON users FOR EACH ROW EXECUTE PROCEDURE delete_user();

CREATE FUNCTION delete_channel() RETURNS TRIGGER AS '
BEGIN
	INSERT INTO deletion_transactions (tableID, key1, key2, key3, last_updated)
	VALUES(2, OLD.id, 0, 0, extract(epoch FROM now())::int);
	RETURN OLD;
END;
' LANGUAGE 'plpgsql';

CREATE TRIGGER t_delete_channel AFTER DELETE ON channels FOR EACH ROW EXECUTE PROCEDURE delete_channel();

CREATE FUNCTION delete_level() RETURNS TRIGGER AS '
BEGIN
	INSERT INTO deletion_transactions (tableID, key1, key2, key3, last_updated)
	VALUES(3, OLD.channel_id, OLD.user_id, 0, extract(epoch FROM now())::int);
	RETURN OLD;
END;
' LANGUAGE 'plpgsql';

CREATE TRIGGER t_delete_level AFTER DELETE ON levels FOR EACH ROW EXECUTE PROCEDURE delete_level();

CREATE FUNCTION delete_ban() RETURNS TRIGGER AS '
BEGIN
	INSERT INTO deletion_transactions (tableID, key1, key2, key3, last_updated)
	VALUES(4, OLD.id, 0, 0, extract(epoch FROM now())::int);
	RETURN OLD;
END;
' LANGUAGE 'plpgsql';

CREATE TRIGGER t_delete_ban AFTER DELETE ON bans FOR EACH ROW EXECUTE PROCEDURE delete_ban();

CREATE TABLE variables (
	var_name VARCHAR(30),
	contents text,
	hint text,
	last_updated INT4,
	PRIMARY KEY(var_name)
);

CREATE TABLE adminlog (
	id SERIAL,
	user_id INT4 NOT NULL,
	cmd VARCHAR(100),
	args VARCHAR(255),
	timestamp INT4 NOT NULL,
	issue_by VARCHAR(255),
	PRIMARY KEY(id)
);

CREATE INDEX adminlog_c_idx ON adminlog(cmd,timestamp);
CREATE INDEX adminlog_u_idx ON adminlog(user_id,timestamp);
CREATE INDEX adminlog_a_idx ON adminlog(args);
CREATE INDEX adminlog_i_idx ON adminlog(issue_by);


CREATE TABLE ip_restrict (
	id		SERIAL,
	user_id		int4 NOT NULL,
	added		int4 NOT NULL,
	added_by	int4 NOT NULL,
	type		int4 NOT NULL DEFAULT 0,
	value		inet NOT NULL,
	last_updated	int4 NOT NULL DEFAULT date_part('epoch', CURRENT_TIMESTAMP)::int,
	last_used	int4 NOT NULL DEFAULT 0,
	expiry		int4 NOT NULL,
	description	VARCHAR(255)
);

CREATE INDEX ip_restrict_idx ON ip_restrict(user_id,type);

CREATE TABLE webnotices (
	id 	SERIAL,
	created_ts 	int4 NOT NULL,
	contents 	VARCHAR(255) NOT NULL,
	PRIMARY KEY(id)
);

CREATE TABLE glines (
        Id SERIAL,
        Host VARCHAR(128) UNIQUE NOT NULL,
        AddedBy VARCHAR(128) NOT NULL,
        AddedOn INT4 NOT NULL,
        ExpiresAt INT4 NOT NULL,
        LastUpdated INT4 NOT NULL DEFAULT date_part('epoch', CURRENT_TIMESTAMP)::int,
        Reason VARCHAR(255)
);


CREATE TABLE whitelist (
        Id SERIAL,
        IP inet UNIQUE NOT NULL,
        AddedBy VARCHAR(128) NOT NULL,
        AddedOn INT4 NOT NULL,
        ExpiresAt INT4 NOT NULL,
        Reason VARCHAR(255)
);
