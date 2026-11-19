-- Passcodes are no longer stored in clear: new links keep only the Argon2id hash.
-- pass_code stays for links issued before this migration; it is replaced by a hash the first time the link is
-- opened with the right passcode.
-- failed_attempts is the lifetime count of wrong passcodes for the link (HL7 SMART Health Links asks for a limit).

alter table qr_code add column pass_code_hash varchar(255);
alter table qr_code add column failed_attempts integer not null default 0;
