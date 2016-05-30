table_vault
===========

A simple example of a vault storing data in a regular table. The passphrase
protecting the vault is stored in table key_vault. The API consists of two
functions:

 * set_username(user_name, passphrase)
 * get_username()


Example usage
-------------

1. install `pgcrypto` extension (provides crypto for the signing etc.)

    CREATE EXTENSION pgcrypto;

2. install `table_vault` extension (after `make install`)

    CREATE EXTENSION table_vault;

3. generate random signing key and set a passphrase

    INSERT INTO table_vault.key_vault
    VALUES (crypt('mypassphrase', gen_salt('bf')));

4. set the context

    SELECT table_vault.set_username('tomas', 'mypassphrase');

5. get the username from signed context

    SELECT table_vault.get_username();
