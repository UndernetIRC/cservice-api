// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.18.0

package models

import (
	"net/netip"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/undernetirc/cservice-api/db/types/flags"
	"github.com/undernetirc/cservice-api/db/types/password"
)

type Acl struct {
	AclID         pgtype.Int4 `json:"acl_id"`
	UserID        int32       `json:"user_id"`
	Isstaff       int16       `json:"isstaff"`
	Flags         flags.ACL   `json:"flags"`
	Xtra          int32       `json:"xtra"`
	LastUpdated   int32       `json:"last_updated"`
	LastUpdatedBy int32       `json:"last_updated_by"`
	SuspendExpire int32       `json:"suspend_expire"`
	SuspendBy     int32       `json:"suspend_by"`
	Deleted       int16       `json:"deleted"`
}

type Adminlog struct {
	ID        int32       `json:"id"`
	UserID    int32       `json:"user_id"`
	Cmd       pgtype.Text `json:"cmd"`
	Args      pgtype.Text `json:"args"`
	Timestamp int32       `json:"timestamp"`
	IssueBy   pgtype.Text `json:"issue_by"`
}

type Ban struct {
	ID          pgtype.Int4 `json:"id"`
	ChannelID   int32       `json:"channel_id"`
	Banmask     string      `json:"banmask"`
	SetBy       pgtype.Text `json:"set_by"`
	SetTs       pgtype.Int4 `json:"set_ts"`
	Level       pgtype.Int2 `json:"level"`
	Expires     pgtype.Int4 `json:"expires"`
	Reason      pgtype.Text `json:"reason"`
	LastUpdated int32       `json:"last_updated"`
	Deleted     pgtype.Int2 `json:"deleted"`
}

type Channel struct {
	ID           int32       `json:"id"`
	Name         string      `json:"name"`
	Flags        int32       `json:"flags"`
	MassDeopPro  int16       `json:"mass_deop_pro"`
	FloodPro     int32       `json:"flood_pro"`
	Url          pgtype.Text `json:"url"`
	Description  pgtype.Text `json:"description"`
	Comment      pgtype.Text `json:"comment"`
	Keywords     pgtype.Text `json:"keywords"`
	RegisteredTs pgtype.Int4 `json:"registered_ts"`
	ChannelTs    int32       `json:"channel_ts"`
	ChannelMode  pgtype.Text `json:"channel_mode"`
	Userflags    pgtype.Int2 `json:"userflags"`
	LimitOffset  pgtype.Int4 `json:"limit_offset"`
	LimitPeriod  pgtype.Int4 `json:"limit_period"`
	LimitGrace   pgtype.Int4 `json:"limit_grace"`
	LimitMax     pgtype.Int4 `json:"limit_max"`
	NoTake       pgtype.Int4 `json:"no_take"`
	LastUpdated  int32       `json:"last_updated"`
	Deleted      pgtype.Int2 `json:"deleted"`
	MaxBans      pgtype.Int4 `json:"max_bans"`
	Welcome      pgtype.Text `json:"welcome"`
}

type Channellog struct {
	Ts          pgtype.Int4 `json:"ts"`
	Channelid   pgtype.Int4 `json:"channelid"`
	Event       pgtype.Int2 `json:"event"`
	Message     pgtype.Text `json:"message"`
	LastUpdated int32       `json:"last_updated"`
	Deleted     pgtype.Int2 `json:"deleted"`
}

type Complaint struct {
	ID                    int32  `json:"id"`
	FromID                int32  `json:"from_id"`
	FromEmail             string `json:"from_email"`
	InrecEmail            string `json:"inrec_email"`
	ComplaintType         int32  `json:"complaint_type"`
	ComplaintText         string `json:"complaint_text"`
	ComplaintLogs         string `json:"complaint_logs"`
	ComplaintChannel1ID   int32  `json:"complaint_channel1_id"`
	ComplaintChannel1Name string `json:"complaint_channel1_name"`
	ComplaintChannel2ID   int32  `json:"complaint_channel2_id"`
	ComplaintChannel2Name string `json:"complaint_channel2_name"`
	ComplaintUsersID      int32  `json:"complaint_users_id"`
	Status                int32  `json:"status"`
	Nicelevel             int32  `json:"nicelevel"`
	ReviewedByID          int32  `json:"reviewed_by_id"`
	ReviewedTs            int32  `json:"reviewed_ts"`
	CreatedTs             int32  `json:"created_ts"`
	CreatedIp             string `json:"created_ip"`
	CreatedCrc            string `json:"created_crc"`
	CrcExpiration         int32  `json:"crc_expiration"`
	TicketNumber          string `json:"ticket_number"`
	CurrentOwner          int32  `json:"current_owner"`
}

type ComplaintType struct {
	ID             int32  `json:"id"`
	ComplaintLabel string `json:"complaint_label"`
}

type ComplaintsReference struct {
	ComplaintsRef int32 `json:"complaints_ref"`
	ReferencedBy  int32 `json:"referenced_by"`
	ReferencedTo  int32 `json:"referenced_to"`
	ReferenceTs   int32 `json:"reference_ts"`
	IsNew         int32 `json:"is_new"`
}

type ComplaintsThread struct {
	ID           int32  `json:"id"`
	ComplaintRef int32  `json:"complaint_ref"`
	ReplyBy      int32  `json:"reply_by"`
	ReplyTs      int32  `json:"reply_ts"`
	ReplyText    string `json:"reply_text"`
	ActionsText  string `json:"actions_text"`
	InReplyTo    int32  `json:"in_reply_to"`
}

type Count struct {
	CountType  pgtype.Int2 `json:"count_type"`
	CountCount pgtype.Int4 `json:"count_count"`
}

type DefaultMsg struct {
	ID      pgtype.Int4 `json:"id"`
	Type    int32       `json:"type"`
	Label   string      `json:"label"`
	Content string      `json:"content"`
}

type DeletionTransaction struct {
	Tableid     pgtype.Int4 `json:"tableid"`
	Key1        pgtype.Int4 `json:"key1"`
	Key2        pgtype.Int4 `json:"key2"`
	Key3        pgtype.Int4 `json:"key3"`
	LastUpdated int32       `json:"last_updated"`
}

type Domain struct {
	ID          int32       `json:"id"`
	Domain      string      `json:"domain"`
	Flags       int16       `json:"flags"`
	LastUpdated int32       `json:"last_updated"`
	Deleted     pgtype.Int2 `json:"deleted"`
}

type FraudList struct {
	ID   pgtype.Int4 `json:"id"`
	Name string      `json:"name"`
}

type FraudListDatum struct {
	ListID int32 `json:"list_id"`
	UserID int32 `json:"user_id"`
}

type Gline struct {
	ID          pgtype.Int4 `json:"id"`
	Host        string      `json:"host"`
	Addedby     string      `json:"addedby"`
	Addedon     int32       `json:"addedon"`
	Expiresat   int32       `json:"expiresat"`
	Lastupdated int32       `json:"lastupdated"`
	Reason      pgtype.Text `json:"reason"`
}

type Help struct {
	Topic      string      `json:"topic"`
	LanguageID pgtype.Int4 `json:"language_id"`
	Contents   pgtype.Text `json:"contents"`
}

type IpRestrict struct {
	ID          pgtype.Int4 `json:"id"`
	UserID      int32       `json:"user_id"`
	Added       int32       `json:"added"`
	AddedBy     int32       `json:"added_by"`
	Type        int32       `json:"type"`
	Value       netip.Addr  `json:"value"`
	LastUpdated int32       `json:"last_updated"`
	LastUsed    int32       `json:"last_used"`
	Expiry      int32       `json:"expiry"`
	Description pgtype.Text `json:"description"`
}

type Language struct {
	ID          int32       `json:"id"`
	Code        pgtype.Text `json:"code"`
	Name        pgtype.Text `json:"name"`
	LastUpdated int32       `json:"last_updated"`
	Deleted     pgtype.Int2 `json:"deleted"`
}

type Lastrequest struct {
	Ip            pgtype.Text `json:"ip"`
	LastRequestTs pgtype.Int4 `json:"last_request_ts"`
}

type Level struct {
	ChannelID      int32       `json:"channel_id"`
	UserID         int32       `json:"user_id"`
	Access         int32       `json:"access"`
	Flags          int16       `json:"flags"`
	SuspendExpires pgtype.Int4 `json:"suspend_expires"`
	SuspendLevel   pgtype.Int4 `json:"suspend_level"`
	SuspendBy      pgtype.Text `json:"suspend_by"`
	SuspendReason  pgtype.Text `json:"suspend_reason"`
	Added          pgtype.Int4 `json:"added"`
	AddedBy        pgtype.Text `json:"added_by"`
	LastModif      pgtype.Int4 `json:"last_modif"`
	LastModifBy    pgtype.Text `json:"last_modif_by"`
	LastUpdated    int32       `json:"last_updated"`
	Deleted        pgtype.Int2 `json:"deleted"`
}

type Lock struct {
	Section pgtype.Int2 `json:"section"`
	Since   pgtype.Int4 `json:"since"`
	By      pgtype.Int4 `json:"by"`
}

type Noreg struct {
	ID          pgtype.Int4 `json:"id"`
	UserName    pgtype.Text `json:"user_name"`
	Email       pgtype.Text `json:"email"`
	ChannelName pgtype.Text `json:"channel_name"`
	Type        int32       `json:"type"`
	NeverReg    int32       `json:"never_reg"`
	ForReview   int32       `json:"for_review"`
	ExpireTime  pgtype.Int4 `json:"expire_time"`
	CreatedTs   pgtype.Int4 `json:"created_ts"`
	SetBy       pgtype.Text `json:"set_by"`
	Reason      pgtype.Text `json:"reason"`
}

type Note struct {
	MessageID   int32       `json:"message_id"`
	UserID      int32       `json:"user_id"`
	FromUserID  pgtype.Int4 `json:"from_user_id"`
	Message     pgtype.Text `json:"message"`
	LastUpdated int32       `json:"last_updated"`
}

type Notice struct {
	MessageID   int32       `json:"message_id"`
	UserID      int32       `json:"user_id"`
	Message     pgtype.Text `json:"message"`
	LastUpdated int32       `json:"last_updated"`
}

type Objection struct {
	ChannelID int32       `json:"channel_id"`
	UserID    int32       `json:"user_id"`
	Comment   string      `json:"comment"`
	CreatedTs int32       `json:"created_ts"`
	AdminOnly pgtype.Text `json:"admin_only"`
}

type Pending struct {
	ChannelID       int32       `json:"channel_id"`
	ManagerID       pgtype.Int4 `json:"manager_id"`
	CreatedTs       int32       `json:"created_ts"`
	CheckStartTs    int32       `json:"check_start_ts"`
	Status          pgtype.Int4 `json:"status"`
	JoinCount       pgtype.Int4 `json:"join_count"`
	UniqueJoinCount pgtype.Int4 `json:"unique_join_count"`
	DecisionTs      pgtype.Int4 `json:"decision_ts"`
	Decision        pgtype.Text `json:"decision"`
	Managername     pgtype.Text `json:"managername"`
	RegAcknowledged pgtype.Text `json:"reg_acknowledged"`
	Comments        pgtype.Text `json:"comments"`
	LastUpdated     int32       `json:"last_updated"`
	Description     pgtype.Text `json:"description"`
	Reviewed        string      `json:"reviewed"`
	FirstInit       string      `json:"first_init"`
	ReviewedByID    pgtype.Int4 `json:"reviewed_by_id"`
}

type PendingChanfixScore struct {
	ChannelID   pgtype.Int4 `json:"channel_id"`
	UserID      string      `json:"user_id"`
	Rank        int32       `json:"rank"`
	Score       int32       `json:"score"`
	Account     string      `json:"account"`
	FirstOpped  pgtype.Text `json:"first_opped"`
	LastOpped   pgtype.Text `json:"last_opped"`
	LastUpdated int32       `json:"last_updated"`
	First       string      `json:"first"`
}

type PendingEmailchange struct {
	Cookie     string `json:"cookie"`
	UserID     int32  `json:"user_id"`
	OldEmail   string `json:"old_email"`
	NewEmail   string `json:"new_email"`
	Expiration int32  `json:"expiration"`
	Phase      int32  `json:"phase"`
}

type PendingMgrchange struct {
	ID           pgtype.Int4 `json:"id"`
	ChannelID    int32       `json:"channel_id"`
	ManagerID    int32       `json:"manager_id"`
	NewManagerID int32       `json:"new_manager_id"`
	ChangeType   pgtype.Int2 `json:"change_type"`
	OptDuration  pgtype.Int4 `json:"opt_duration"`
	Reason       pgtype.Text `json:"reason"`
	Expiration   pgtype.Int4 `json:"expiration"`
	Crc          pgtype.Text `json:"crc"`
	Confirmed    pgtype.Int2 `json:"confirmed"`
	FromHost     pgtype.Text `json:"from_host"`
}

type PendingPasswordchange struct {
	Cookie     string `json:"cookie"`
	UserID     int32  `json:"user_id"`
	OldCrypt   string `json:"old_crypt"`
	NewCrypt   string `json:"new_crypt"`
	NewClrpass string `json:"new_clrpass"`
	CreatedTs  int32  `json:"created_ts"`
}

type PendingPwreset struct {
	Cookie           string `json:"cookie"`
	UserID           int32  `json:"user_id"`
	QuestionID       int16  `json:"question_id"`
	Verificationdata string `json:"verificationdata"`
	Expiration       int32  `json:"expiration"`
}

type PendingTraffic struct {
	ChannelID int32       `json:"channel_id"`
	IpNumber  netip.Addr  `json:"ip_number"`
	JoinCount pgtype.Int4 `json:"join_count"`
}

type Pendinguser struct {
	UserName         pgtype.Text       `json:"user_name"`
	Cookie           pgtype.Text       `json:"cookie"`
	Email            pgtype.Text       `json:"email"`
	Expire           pgtype.Int4       `json:"expire"`
	QuestionID       pgtype.Int2       `json:"question_id"`
	Verificationdata pgtype.Text       `json:"verificationdata"`
	PosterIp         pgtype.Text       `json:"poster_ip"`
	Language         int32             `json:"language"`
	Password         password.Password `json:"password"`
}

type Role struct {
	ID          int32            `json:"id"`
	Name        string           `json:"name"`
	Description string           `json:"description"`
	CreatedAt   pgtype.Timestamp `json:"created_at"`
	UpdatedAt   pgtype.Timestamp `json:"updated_at"`
	CreatedBy   string           `json:"created_by"`
	UpdatedBy   string           `json:"updated_by"`
}

type Statistic struct {
	UsersID       int32  `json:"users_id"`
	StatsType     int32  `json:"stats_type"`
	StatsValueInt int32  `json:"stats_value_int"`
	StatsValueChr string `json:"stats_value_chr"`
	LastUpdated   int32  `json:"last_updated"`
}

type Supporter struct {
	ChannelID   int32       `json:"channel_id"`
	UserID      int32       `json:"user_id"`
	Support     pgtype.Text `json:"support"`
	Noticed     string      `json:"noticed"`
	Reason      pgtype.Text `json:"reason"`
	JoinCount   pgtype.Int4 `json:"join_count"`
	LastUpdated int32       `json:"last_updated"`
	Deleted     pgtype.Int2 `json:"deleted"`
}

type Timezone struct {
	TzIndex       pgtype.Int4 `json:"tz_index"`
	TzName        string      `json:"tz_name"`
	TzCountrycode string      `json:"tz_countrycode"`
	TzAcronym     string      `json:"tz_acronym"`
	Deleted       pgtype.Int2 `json:"deleted"`
	LastUpdated   int32       `json:"last_updated"`
}

type Translation struct {
	LanguageID  int32       `json:"language_id"`
	ResponseID  int32       `json:"response_id"`
	Text        pgtype.Text `json:"text"`
	LastUpdated int32       `json:"last_updated"`
	Deleted     pgtype.Int2 `json:"deleted"`
}

type User struct {
	ID               int32             `json:"id"`
	UserName         string            `json:"user_name"`
	Password         password.Password `json:"password"`
	Email            pgtype.Text       `json:"email"`
	Url              pgtype.Text       `json:"url"`
	QuestionID       pgtype.Int2       `json:"question_id"`
	Verificationdata pgtype.Text       `json:"verificationdata"`
	LanguageID       pgtype.Int4       `json:"language_id"`
	PublicKey        pgtype.Text       `json:"public_key"`
	PostForms        int32             `json:"post_forms"`
	Flags            flags.User        `json:"flags"`
	LastUpdatedBy    pgtype.Text       `json:"last_updated_by"`
	LastUpdated      int32             `json:"last_updated"`
	Deleted          pgtype.Int2       `json:"deleted"`
	TzSetting        pgtype.Text       `json:"tz_setting"`
	SignupCookie     pgtype.Text       `json:"signup_cookie"`
	SignupTs         pgtype.Int4       `json:"signup_ts"`
	SignupIp         pgtype.Text       `json:"signup_ip"`
	Maxlogins        pgtype.Int4       `json:"maxlogins"`
	TotpKey          pgtype.Text       `json:"totp_key"`
}

type UserRole struct {
	UserID    int32            `json:"user_id"`
	RoleID    int32            `json:"role_id"`
	CreatedAt pgtype.Timestamp `json:"created_at"`
	UpdatedAt pgtype.Timestamp `json:"updated_at"`
	CreatedBy string           `json:"created_by"`
	UpdatedBy string           `json:"updated_by"`
}

type UserSecHistory struct {
	UserID    int32  `json:"user_id"`
	UserName  string `json:"user_name"`
	Command   string `json:"command"`
	Ip        string `json:"ip"`
	Hostmask  string `json:"hostmask"`
	Timestamp int32  `json:"timestamp"`
}

type Userlog struct {
	Ts          pgtype.Int4 `json:"ts"`
	UserID      pgtype.Int4 `json:"user_id"`
	Event       pgtype.Int4 `json:"event"`
	Message     pgtype.Text `json:"message"`
	LastUpdated int32       `json:"last_updated"`
}

type UsersLastseen struct {
	UserID       int32       `json:"user_id"`
	LastSeen     pgtype.Int4 `json:"last_seen"`
	LastHostmask pgtype.Text `json:"last_hostmask"`
	LastIp       pgtype.Text `json:"last_ip"`
	LastUpdated  int32       `json:"last_updated"`
}

type Variable struct {
	VarName     string      `json:"var_name"`
	Contents    pgtype.Text `json:"contents"`
	Hint        pgtype.Text `json:"hint"`
	LastUpdated pgtype.Int4 `json:"last_updated"`
}

type Webnotice struct {
	ID        int32  `json:"id"`
	CreatedTs int32  `json:"created_ts"`
	Contents  string `json:"contents"`
}

type Whitelist struct {
	ID        pgtype.Int4 `json:"id"`
	Ip        netip.Addr  `json:"ip"`
	Addedby   string      `json:"addedby"`
	Addedon   int32       `json:"addedon"`
	Expiresat int32       `json:"expiresat"`
	Reason    pgtype.Text `json:"reason"`
}
