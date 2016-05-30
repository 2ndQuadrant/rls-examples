/* table_vault--1.0.sql */

-- table containing a single row with the signing key
CREATE TABLE key_vault (
    key_pass TEXT   -- key passphrase hashed using crypt()
);

-- no public access to the table (the key must remain secret)
REVOKE ALL ON key_vault FROM PUBLIC;

-- table matching current sessions
CREATE TABLE sessions (
    id         UUID PRIMARY KEY,
    user_name  NAME NOT NULL,
    created    TIMESTAMP NOT NULL DEFAULT now()
);

-- no public access (not even reads)
REVOKE ALL ON sessions FROM PUBLIC;

-- used to store username into the session table, returns random UUID
-- XXX: we can't restrict access, so it's protected by passphrase (stored in key_vault)
CREATE OR REPLACE FUNCTION set_username (p_username TEXT, p_passphrase TEXT) RETURNS uuid AS $$
DECLARE
    v_id        UUID;
BEGIN

    -- UUID generator provided by pgcrypto
    v_id := gen_random_uuid();

    -- verify the passphrase
    PERFORM 1 FROM @extschema@.key_vault
             WHERE key_pass = crypt(p_passphrase, key_pass);

    -- either there's no key in the table, or the passphrase does not match
    IF NOT FOUND THEN
        RAISE EXCEPTION 'matching key not found';
    END IF;

    -- store the context into the sessions table
    INSERT INTO @extschema@.sessions VALUES (v_id, p_username);

    -- store the ID in a session variable
    PERFORM set_config('signed_vault.session_id', CAST (v_id AS TEXT), false);

    -- but also return the value (because of convenience)
    RETURN v_id;

END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- everyone can run the function, that's why we have the secret passphrase
GRANT ALL ON FUNCTION set_username(text, text) TO PUBLIC;

-- used to get username from the sessions table using the UUID identifier
CREATE OR REPLACE FUNCTION get_username () RETURNS text AS $$
DECLARE
    v_id        UUID;
    v_created   TIMESTAMP;
    v_username  TEXT;
BEGIN

    -- read the value from session variable
    v_id := current_setting('signed_vault.session_id');

    SELECT user_name, created INTO v_username, v_created
      FROM @extschema@.sessions WHERE id = v_id;

    -- no matching session ID found
    IF NOT FOUND THEN
        RAISE EXCEPTION 'invalid session ID';
    END IF;

    -- also check that the value is not expired (24 hours)
    IF now() > v_created + INTERVAL '1 day' THEN
        RAISE EXCEPTION 'session expired';
    END IF;

    -- signature seems OK, return the username
    RETURN v_username;

END;
$$ LANGUAGE plpgsql SECURITY DEFINER STABLE;

-- everyone can run the function (that's why we have the signature)
GRANT ALL ON FUNCTION get_username() TO PUBLIC;

-- grant generic access to the schema
GRANT USAGE ON SCHEMA @extschema@ TO PUBLIC;
