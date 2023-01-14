DELETE FROM levels WHERE channel_id = 2 AND user_id = 1;
DELETE FROM levels WHERE channel_id = 1 AND user_id = 1;
DELETE FROM users_lastseen WHERE user_id = 1;
DELETE FROM users WHERE user_name = 'Admin';
DELETE FROM channels WHERE name = '#coder-com';
DELETE FROM channels WHERE name = '*';
