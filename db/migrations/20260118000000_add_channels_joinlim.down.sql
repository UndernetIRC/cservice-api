-- Rollback JOINLIM feature

-- Remove translations
DELETE FROM translations WHERE response_id >= 210 AND response_id <= 219 AND language_id = 1;

-- Remove help topics
DELETE FROM help WHERE topic = 'SET JOINLIM' AND language_id = 1;
DELETE FROM help WHERE topic = 'SET JOINMAX' AND language_id = 1;
DELETE FROM help WHERE topic = 'SET JOINMODE' AND language_id = 1;
DELETE FROM help WHERE topic = 'SET JOINPERIOD' AND language_id = 1;

-- Remove columns from channels table
ALTER TABLE channels DROP COLUMN IF EXISTS limit_joinmax;
ALTER TABLE channels DROP COLUMN IF EXISTS limit_joinsecs;
ALTER TABLE channels DROP COLUMN IF EXISTS limit_joinperiod;
ALTER TABLE channels DROP COLUMN IF EXISTS limit_joinmode;
