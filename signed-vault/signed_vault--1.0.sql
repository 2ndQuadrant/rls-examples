/* signed_vault--1.0.sql */

-- table containing a single row with the signing key
CREATE TABLE key_vault (
    key_data TEXT,  -- key used to sign session variables
    key_pass TEXT   -- key passphrase hashed using crypt()
);

-- no public access to the table (the key must remain secret)
REVOKE ALL ON key_vault FROM PUBLIC;

-- used to store signed username into the context
-- XXX: we can't restrict access, so it's protected by passphrase (stored in key_vault)
CREATE OR REPLACE FUNCTION set_username (p_username TEXT, p_passphrase TEXT) RETURNS text AS $$
DECLARE
    v_timestamp INT;
    v_signature TEXT;
    v_key       BYTEA;
    v_value     TEXT;
BEGIN

    -- get timestamp and key used for the signature
    v_timestamp := EXTRACT(epoch FROM now());

    SELECT key_data INTO v_key FROM @extschema@.key_vault
                              WHERE key_pass = crypt(p_passphrase, key_pass);

    -- either there's no key in the table, or the passphrase does not match
    IF NOT FOUND THEN
        RAISE EXCEPTION 'matching key not found';
    END IF;

    -- construct the value and compute the signature (key + username + timestamp)
    -- XXX: may also include other information (e.g. pid)
    v_value := p_username || ':' || v_timestamp;
    v_signature := crypt(v_value || ':' || v_key, gen_salt('bf'));

    -- value + signature (without the key)
    v_value := v_value || ':' || v_signature;

    -- store it in a session variable
    PERFORM set_config('signed_vault.username', v_value, false);

    -- but also return the value (because of convenience)
    RETURN v_value;

END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- everyone can run the function, that's why we have the secret passphrase
GRANT ALL ON FUNCTION set_username(text, text) TO PUBLIC;

-- used to verify signature on the value
CREATE OR REPLACE FUNCTION get_username () RETURNS text AS $$
DECLARE
    v_timestamp INT;
    v_username  TEXT;
    v_signature TEXT;
    v_key       BYTEA;
    v_parts     TEXT[];
    v_value     TEXT;
BEGIN

    -- get key used for the signature (no passphrase needed for verification)
    SELECT key_data INTO v_key FROM @extschema@.key_vault;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'no signing key found';
    END IF;

    -- read the value from session variable
    v_value := current_setting('signed_vault.username');

    -- split the value into parts (username, timestamp, signature)
    v_parts := regexp_matches(v_value, '(.*):(.*):(.*)');

    v_username  := v_parts[1];
    v_timestamp := v_parts[2];
    v_signature := v_parts[3];

    -- verify the signature
    IF crypt(v_username || ':' || v_timestamp || ':' || v_key, v_signature) != v_signature THEN
        RAISE EXCEPTION 'signature invalid';
    END IF;

    -- also check that the value is not expired (24 hours)
    IF EXTRACT(epoch FROM now()) > v_timestamp + 86400 THEN
        RAISE EXCEPTION 'signature expired';
    END IF;

    -- signature seems OK, return the username
    RETURN v_username;

END;
$$ LANGUAGE plpgsql SECURITY DEFINER STABLE;

-- everyone can run the function (that's why we have the signature)
GRANT ALL ON FUNCTION get_username() TO PUBLIC;

-- grant generic access to the schema
GRANT USAGE ON SCHEMA @extschema@ TO PUBLIC;
