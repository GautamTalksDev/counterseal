The server code deployed at leash.gautamkhosla.com before the merge (main at the time of the merge, map 2026-10-09.1).
server/test/migration.test.js runs it to write live-shaped rows into a database with migrations 0001 to 0003, then
applies 0004 and checks that the merged code keeps every account, passkey, session, token, hold, push subscription
and audit chain working. Do not edit.
