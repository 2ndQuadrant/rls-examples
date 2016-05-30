signed_vault
============

A simple example of a vault storing data in signed session variables. The key
used for signing (and passphrase protecting it) is stored in table key_vault.
The API consists of two functions

 * set_username(user_name, passphrase)
 * get_username()


Example usage
-------------

1. install `pgcrypto` extension (provides crypto for the signing etc.)

    CREATE EXTENSION pgcrypto;

2. install `signed_vault` extension (after `make install`)

    CREATE EXTENSION signed_vault;

3. generate random signing key and set a passphrase

    INSERT INTO signed_vault.key_vault
    VALUES (gen_random_bytes(32), crypt('mypassphrase', gen_salt('bf')));

4. set the context

    SELECT signed_vault.set_username('tomas', 'mypassphrase');

5. get the username from signed context

    SELECT signed_vault.get_username();
