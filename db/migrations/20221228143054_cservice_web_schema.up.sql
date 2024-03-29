CREATE TABLE acl (
	acl_id SERIAL,
	user_id INT4 NOT NULL,
	isstaff INT2 NOT NULL,
	flags INT4 DEFAULT '0' NOT NULL,
	xtra INT4 NOT NULL,
	last_updated INT4 NOT NULL,
	last_updated_by INT4 NOT NULL,
	suspend_expire INT4 DEFAULT '0' NOT NULL,
	suspend_by INT4 DEFAULT '0' NOT NULL,
	deleted INT2 DEFAULT '0' NOT NULL
);

CREATE TABLE fraud_lists (
	id SERIAL,
	name VARCHAR(255) NOT NULL
);

CREATE TABLE fraud_list_data (
	list_id INT4 NOT NULL,
	user_id INT4 REFERENCES users(id) NOT NULL
);

CREATE TABLE pending_pwreset (
        cookie VARCHAR(128) NOT NULL,
        user_id INT4 NOT NULL,
        question_id INT2 NOT NULL,
        verificationdata VARCHAR(30) NOT NULL,
        expiration INT4 NOT NULL
);

CREATE INDEX pending_pwreset_cookie_idx ON pending_pwreset(cookie);
CREATE INDEX pending_pwreset_user_id_idx ON pending_pwreset(user_id);
CREATE INDEX pending_pwreset_expiration_idx ON pending_pwreset(expiration);

CREATE TABLE locks (
	section INT2,
	since INT4,
	by INT4
);

CREATE TABLE counts (
	count_type INT2,
	count_count INT4
);

CREATE TABLE statistics (
	users_id	INT4 NOT NULL,
	stats_type	INT4 NOT NULL,
	stats_value_int	INT4 DEFAULT 0 NOT NULL,
	stats_value_chr	VARCHAR(255) DEFAULT '' NOT NULL,
	last_updated	INT4 NOT NULL
);

CREATE INDEX statistics_users_id_idx ON statistics(users_id);

CREATE TABLE pending_mgrchange (
	id SERIAL,
	channel_id INT4 NOT NULL,
	manager_id INT4 NOT NULL,
	new_manager_id INT4 NOT NULL,
	change_type INT2,
	opt_duration INT4,
	reason TEXT,
	expiration INT4 DEFAULT 0,
	crc VARCHAR(128),
	confirmed INT2 DEFAULT 0,
	from_host VARCHAR(15) DEFAULT '0.0.0.0'
);

CREATE INDEX pending_mgrchange_id_idx ON pending_mgrchange(id);
CREATE INDEX pending_mgrchange_channel_id_idx ON pending_mgrchange(channel_id);
CREATE INDEX pending_mgrchange_manager_id_idx ON pending_mgrchange(manager_id);
CREATE INDEX pending_mgrchange_new_manager_id_idx ON pending_mgrchange(new_manager_id);
CREATE INDEX pending_mgrchange_change_type_idx ON pending_mgrchange(change_type);
CREATE INDEX pending_mgrchange_opt_duration_idx ON pending_mgrchange(opt_duration);
CREATE INDEX pending_mgrchange_expiration_idx ON pending_mgrchange(expiration);
CREATE INDEX pending_mgrchange_crc_idx ON pending_mgrchange(crc);
CREATE INDEX pending_mgrchange_confirmed_idx ON pending_mgrchange(confirmed);

CREATE TABLE pendingusers (
	user_name VARCHAR(12),
	cookie VARCHAR(32),
	email VARCHAR(255),
	expire INT4,
	question_id INT2,
	verificationdata VARCHAR(30),
	poster_ip VARCHAR(15) DEFAULT '',
	language INT4 NOT NULL
);

CREATE INDEX pendingusers_cookie_idx ON pendingusers(cookie);

CREATE TABLE pending_emailchanges (
	cookie VARCHAR(128) NOT NULL,
	user_id INT4 NOT NULL,
	old_email VARCHAR(255) NOT NULL,
	new_email VARCHAR(255) NOT NULL,
	expiration INT4 NOT NULL,
	phase INT4 NOT NULL
);

CREATE INDEX pending_emailchanges_cookie_idx ON pending_emailchanges(cookie);
CREATE INDEX pending_emailchanges_user_id_idx ON pending_emailchanges(user_id);
CREATE INDEX pending_emailchanges_expiration_idx ON pending_emailchanges(expiration);

CREATE TABLE pending_passwordchanges (
	cookie VARCHAR(128) NOT NULL,
	user_id INT4 NOT NULL,
	old_crypt VARCHAR(40) NOT NULL,
	new_crypt VARCHAR(40) NOT NULL,
	new_clrpass VARCHAR(255) NOT NULL,
	created_ts INT4 NOT NULL
);

CREATE TABLE lastrequests (
	ip VARCHAR(15) DEFAULT '0.0.0.0',
	last_request_ts INT4
);

CREATE INDEX lastrequests_ip_idx ON lastrequests(ip);

CREATE TABLE objections (
	channel_id int4 REFERENCES channels(id) NOT NULL,
	user_id int4 REFERENCES users(id) NOT NULL,
	comment text NOT NULL,
	created_ts int4 NOT NULL,
	admin_only varchar(1) DEFAULT 'N'
);

CREATE TABLE timezones (
	tz_index SERIAL,
	tz_name VARCHAR(128) NOT NULL,
	tz_countrycode VARCHAR(5) NOT NULL,
	tz_acronym VARCHAR(10) NOT NULL,
	deleted INT2 DEFAULT '0',
	last_updated INT4 NOT NULL
);

CREATE TABLE complaints (
	id SERIAL,
	from_id int4 NOT NULL,
	from_email varchar (255) NOT NULL,
	inrec_email varchar (255) NOT NULL,
	complaint_type int4 NOT NULL,
	complaint_text text NOT NULL,
	complaint_logs text NOT NULL,
	complaint_channel1_id int4 NOT NULL,
	complaint_channel1_name text NOT NULL,
	complaint_channel2_id int4 NOT NULL,
	complaint_channel2_name text NOT NULL,
	complaint_users_id int4 NOT NULL,
	status int4 NOT NULL,
	nicelevel int4 NOT NULL,
	reviewed_by_id int4 NOT NULL,
	reviewed_ts int4 NOT NULL,
	created_ts int4 NOT NULL,
	created_ip varchar (15) DEFAULT '0.0.0.0' NOT NULL,
	created_crc varchar (128) NOT NULL,
	crc_expiration int4 NOT NULL,
	ticket_number varchar(32) NOT NULL,
	current_owner int4 NOT NULL,
	PRIMARY KEY (id)
);

CREATE TABLE complaints_threads (
	id SERIAL,
	complaint_ref int4 NOT NULL CONSTRAINT complaints_threads_ref REFERENCES complaints (id),
	reply_by int4 NOT NULL,
	reply_ts int4 NOT NULL,
	reply_text text NOT NULL,
	actions_text text NOT NULL,
	in_reply_to int4 NOT NULL,
	PRIMARY KEY (id)
);


CREATE TABLE complaint_types (
	id SERIAL,
	complaint_label varchar(255) NOT NULL,
	PRIMARY KEY (id)
);

DELETE FROM complaint_types;
INSERT INTO complaint_types (id, complaint_label) VALUES (1, 'My username is suspended');
INSERT INTO complaint_types (id, complaint_label) VALUES (2, 'Members of a registered channel are spamming my channel');
INSERT INTO complaint_types (id, complaint_label) VALUES (3, 'I object to this channel application but I want to do so anonymously');
INSERT INTO complaint_types (id, complaint_label) VALUES (4, 'My channel was purged and I want you to reconsider');
INSERT INTO complaint_types (id, complaint_label) VALUES (5, 'My channel was purged and I want to know why');
INSERT INTO complaint_types (id, complaint_label) VALUES (99, 'Other complaint');

CREATE TABLE complaints_reference (
	complaints_ref int4 NOT NULL CONSTRAINT complaints_reference_ref REFERENCES complaints (id),
	referenced_by int4 NOT NULL,
	referenced_to int4 NOT NULL,
	reference_ts int4 NOT NULL,
	is_new int4 DEFAULT '1' NOT NULL
);

CREATE INDEX complaints_ref_ref ON complaints_reference(complaints_ref,referenced_to);

CREATE TABLE default_msgs (
	id	SERIAL,
	type	int4 NOT NULL,
	label	varchar(255) NOT NULL,
	content	text NOT NULL
);

CREATE INDEX default_msgs_idx ON default_msgs(type);
