// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.16.0

package models

import (
	"github.com/jackc/pgtype"
	"github.com/undernetirc/cservice-api/db/types/flags"
)

type Acl struct {
	AclID         *int32    `json:"acl_id"`
	UserID        int32     `json:"user_id"`
	Isstaff       int16     `json:"isstaff"`
	Flags         flags.ACL `json:"flags"`
	Xtra          int32     `json:"xtra"`
	LastUpdated   int32     `json:"last_updated"`
	LastUpdatedBy int32     `json:"last_updated_by"`
	SuspendExpire int32     `json:"suspend_expire"`
	SuspendBy     int32     `json:"suspend_by"`
	Deleted       int16     `json:"deleted"`
}

type Adminlog struct {
	ID        int32   `json:"id"`
	UserID    int32   `json:"user_id"`
	Cmd       *string `json:"cmd"`
	Args      *string `json:"args"`
	Timestamp int32   `json:"timestamp"`
	IssueBy   *string `json:"issue_by"`
}

type Ban struct {
	ID          *int32  `json:"id"`
	ChannelID   int32   `json:"channel_id"`
	Banmask     string  `json:"banmask"`
	SetBy       *string `json:"set_by"`
	SetTs       *int32  `json:"set_ts"`
	Level       *int16  `json:"level"`
	Expires     *int32  `json:"expires"`
	Reason      *string `json:"reason"`
	LastUpdated int32   `json:"last_updated"`
	Deleted     *int16  `json:"deleted"`
}

type Channel struct {
	ID           int32   `json:"id"`
	Name         string  `json:"name"`
	Flags        int32   `json:"flags"`
	MassDeopPro  int16   `json:"mass_deop_pro"`
	FloodPro     int32   `json:"flood_pro"`
	Url          *string `json:"url"`
	Description  *string `json:"description"`
	Comment      *string `json:"comment"`
	Keywords     *string `json:"keywords"`
	RegisteredTs *int32  `json:"registered_ts"`
	ChannelTs    int32   `json:"channel_ts"`
	ChannelMode  *string `json:"channel_mode"`
	Userflags    *int16  `json:"userflags"`
	LimitOffset  *int32  `json:"limit_offset"`
	LimitPeriod  *int32  `json:"limit_period"`
	LimitGrace   *int32  `json:"limit_grace"`
	LimitMax     *int32  `json:"limit_max"`
	NoTake       *int32  `json:"no_take"`
	LastUpdated  int32   `json:"last_updated"`
	Deleted      *int16  `json:"deleted"`
	MaxBans      *int32  `json:"max_bans"`
	Welcome      *string `json:"welcome"`
}

type Channellog struct {
	Ts          *int32  `json:"ts"`
	Channelid   *int32  `json:"channelid"`
	Event       *int16  `json:"event"`
	Message     *string `json:"message"`
	LastUpdated int32   `json:"last_updated"`
	Deleted     *int16  `json:"deleted"`
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
	CountType  *int16 `json:"count_type"`
	CountCount *int32 `json:"count_count"`
}

type DefaultMsg struct {
	ID      *int32 `json:"id"`
	Type    int32  `json:"type"`
	Label   string `json:"label"`
	Content string `json:"content"`
}

type DeletionTransaction struct {
	Tableid     *int32 `json:"tableid"`
	Key1        *int32 `json:"key1"`
	Key2        *int32 `json:"key2"`
	Key3        *int32 `json:"key3"`
	LastUpdated int32  `json:"last_updated"`
}

type Domain struct {
	ID          int32  `json:"id"`
	Domain      string `json:"domain"`
	Flags       int16  `json:"flags"`
	LastUpdated int32  `json:"last_updated"`
	Deleted     *int16 `json:"deleted"`
}

type FraudList struct {
	ID   *int32 `json:"id"`
	Name string `json:"name"`
}

type FraudListDatum struct {
	ListID int32 `json:"list_id"`
	UserID int32 `json:"user_id"`
}

type Gline struct {
	ID          *int32  `json:"id"`
	Host        string  `json:"host"`
	Addedby     string  `json:"addedby"`
	Addedon     int32   `json:"addedon"`
	Expiresat   int32   `json:"expiresat"`
	Lastupdated int32   `json:"lastupdated"`
	Reason      *string `json:"reason"`
}

type Help struct {
	Topic      string  `json:"topic"`
	LanguageID *int32  `json:"language_id"`
	Contents   *string `json:"contents"`
}

type IpRestrict struct {
	ID          *int32      `json:"id"`
	UserID      int32       `json:"user_id"`
	Added       int32       `json:"added"`
	AddedBy     int32       `json:"added_by"`
	Type        int32       `json:"type"`
	Value       pgtype.Inet `json:"value"`
	LastUpdated int32       `json:"last_updated"`
	LastUsed    int32       `json:"last_used"`
	Expiry      int32       `json:"expiry"`
	Description *string     `json:"description"`
}

type Language struct {
	ID          int32   `json:"id"`
	Code        *string `json:"code"`
	Name        *string `json:"name"`
	LastUpdated int32   `json:"last_updated"`
	Deleted     *int16  `json:"deleted"`
}

type Lastrequest struct {
	Ip            *string `json:"ip"`
	LastRequestTs *int32  `json:"last_request_ts"`
}

type Level struct {
	ChannelID      int32   `json:"channel_id"`
	UserID         int32   `json:"user_id"`
	Access         int32   `json:"access"`
	Flags          int16   `json:"flags"`
	SuspendExpires *int32  `json:"suspend_expires"`
	SuspendLevel   *int32  `json:"suspend_level"`
	SuspendBy      *string `json:"suspend_by"`
	SuspendReason  *string `json:"suspend_reason"`
	Added          *int32  `json:"added"`
	AddedBy        *string `json:"added_by"`
	LastModif      *int32  `json:"last_modif"`
	LastModifBy    *string `json:"last_modif_by"`
	LastUpdated    int32   `json:"last_updated"`
	Deleted        *int16  `json:"deleted"`
}

type Lock struct {
	Section *int16 `json:"section"`
	Since   *int32 `json:"since"`
	By      *int32 `json:"by"`
}

type Noreg struct {
	ID          *int32  `json:"id"`
	UserName    *string `json:"user_name"`
	Email       *string `json:"email"`
	ChannelName *string `json:"channel_name"`
	Type        int32   `json:"type"`
	NeverReg    int32   `json:"never_reg"`
	ForReview   int32   `json:"for_review"`
	ExpireTime  *int32  `json:"expire_time"`
	CreatedTs   *int32  `json:"created_ts"`
	SetBy       *string `json:"set_by"`
	Reason      *string `json:"reason"`
}

type Note struct {
	MessageID   int32   `json:"message_id"`
	UserID      int32   `json:"user_id"`
	FromUserID  *int32  `json:"from_user_id"`
	Message     *string `json:"message"`
	LastUpdated int32   `json:"last_updated"`
}

type Notice struct {
	MessageID   int32   `json:"message_id"`
	UserID      int32   `json:"user_id"`
	Message     *string `json:"message"`
	LastUpdated int32   `json:"last_updated"`
}

type Objection struct {
	ChannelID int32   `json:"channel_id"`
	UserID    int32   `json:"user_id"`
	Comment   string  `json:"comment"`
	CreatedTs int32   `json:"created_ts"`
	AdminOnly *string `json:"admin_only"`
}

type Pending struct {
	ChannelID       int32   `json:"channel_id"`
	ManagerID       *int32  `json:"manager_id"`
	CreatedTs       int32   `json:"created_ts"`
	CheckStartTs    int32   `json:"check_start_ts"`
	Status          *int32  `json:"status"`
	JoinCount       *int32  `json:"join_count"`
	UniqueJoinCount *int32  `json:"unique_join_count"`
	DecisionTs      *int32  `json:"decision_ts"`
	Decision        *string `json:"decision"`
	Managername     *string `json:"managername"`
	RegAcknowledged *string `json:"reg_acknowledged"`
	Comments        *string `json:"comments"`
	LastUpdated     int32   `json:"last_updated"`
	Description     *string `json:"description"`
	Reviewed        string  `json:"reviewed"`
	FirstInit       string  `json:"first_init"`
	ReviewedByID    *int32  `json:"reviewed_by_id"`
}

type PendingChanfixScore struct {
	ChannelID   *int32  `json:"channel_id"`
	UserID      string  `json:"user_id"`
	Rank        int32   `json:"rank"`
	Score       int32   `json:"score"`
	Account     string  `json:"account"`
	FirstOpped  *string `json:"first_opped"`
	LastOpped   *string `json:"last_opped"`
	LastUpdated int32   `json:"last_updated"`
	First       string  `json:"first"`
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
	ID           *int32  `json:"id"`
	ChannelID    int32   `json:"channel_id"`
	ManagerID    int32   `json:"manager_id"`
	NewManagerID int32   `json:"new_manager_id"`
	ChangeType   *int16  `json:"change_type"`
	OptDuration  *int32  `json:"opt_duration"`
	Reason       *string `json:"reason"`
	Expiration   *int32  `json:"expiration"`
	Crc          *string `json:"crc"`
	Confirmed    *int16  `json:"confirmed"`
	FromHost     *string `json:"from_host"`
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
	IpNumber  pgtype.Inet `json:"ip_number"`
	JoinCount *int32      `json:"join_count"`
}

type Pendinguser struct {
	UserName         *string `json:"user_name"`
	Cookie           *string `json:"cookie"`
	Email            *string `json:"email"`
	Expire           *int32  `json:"expire"`
	QuestionID       *int16  `json:"question_id"`
	Verificationdata *string `json:"verificationdata"`
	PosterIp         *string `json:"poster_ip"`
	Language         int32   `json:"language"`
}

type Statistic struct {
	UsersID       int32  `json:"users_id"`
	StatsType     int32  `json:"stats_type"`
	StatsValueInt int32  `json:"stats_value_int"`
	StatsValueChr string `json:"stats_value_chr"`
	LastUpdated   int32  `json:"last_updated"`
}

type Supporter struct {
	ChannelID   int32   `json:"channel_id"`
	UserID      int32   `json:"user_id"`
	Support     *string `json:"support"`
	Noticed     string  `json:"noticed"`
	Reason      *string `json:"reason"`
	JoinCount   *int32  `json:"join_count"`
	LastUpdated int32   `json:"last_updated"`
	Deleted     *int16  `json:"deleted"`
}

type Timezone struct {
	TzIndex       *int32 `json:"tz_index"`
	TzName        string `json:"tz_name"`
	TzCountrycode string `json:"tz_countrycode"`
	TzAcronym     string `json:"tz_acronym"`
	Deleted       *int16 `json:"deleted"`
	LastUpdated   int32  `json:"last_updated"`
}

type Translation struct {
	LanguageID  int32   `json:"language_id"`
	ResponseID  int32   `json:"response_id"`
	Text        *string `json:"text"`
	LastUpdated int32   `json:"last_updated"`
	Deleted     *int16  `json:"deleted"`
}

type User struct {
	ID               int32      `json:"id"`
	UserName         string     `json:"user_name"`
	Password         string     `json:"password"`
	Email            *string    `json:"email"`
	Url              *string    `json:"url"`
	QuestionID       *int16     `json:"question_id"`
	Verificationdata *string    `json:"verificationdata"`
	LanguageID       *int32     `json:"language_id"`
	PublicKey        *string    `json:"public_key"`
	PostForms        int32      `json:"post_forms"`
	Flags            flags.User `json:"flags"`
	LastUpdatedBy    *string    `json:"last_updated_by"`
	LastUpdated      int32      `json:"last_updated"`
	Deleted          *int16     `json:"deleted"`
	TzSetting        *string    `json:"tz_setting"`
	SignupCookie     *string    `json:"signup_cookie"`
	SignupTs         *int32     `json:"signup_ts"`
	SignupIp         *string    `json:"signup_ip"`
	Maxlogins        *int32     `json:"maxlogins"`
	TotpKey          *string    `json:"totp_key"`
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
	Ts          *int32  `json:"ts"`
	UserID      *int32  `json:"user_id"`
	Event       *int32  `json:"event"`
	Message     *string `json:"message"`
	LastUpdated int32   `json:"last_updated"`
}

type UsersLastseen struct {
	UserID       int32   `json:"user_id"`
	LastSeen     *int32  `json:"last_seen"`
	LastHostmask *string `json:"last_hostmask"`
	LastIp       *string `json:"last_ip"`
	LastUpdated  int32   `json:"last_updated"`
}

type Variable struct {
	VarName     string  `json:"var_name"`
	Contents    *string `json:"contents"`
	Hint        *string `json:"hint"`
	LastUpdated *int32  `json:"last_updated"`
}

type Webnotice struct {
	ID        int32  `json:"id"`
	CreatedTs int32  `json:"created_ts"`
	Contents  string `json:"contents"`
}

type Whitelist struct {
	ID        *int32      `json:"id"`
	Ip        pgtype.Inet `json:"ip"`
	Addedby   string      `json:"addedby"`
	Addedon   int32       `json:"addedon"`
	Expiresat int32       `json:"expiresat"`
	Reason    *string     `json:"reason"`
}
