\set ON_ERROR_STOP on

\if :{?bridge_password}
\else
\echo 'bridge_password is required; run psql with -v bridge_password=...'
\quit
\endif

BEGIN;

SELECT 'CREATE ROLE cpa_log_reader LOGIN'
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cpa_log_reader')
\gexec

ALTER ROLE cpa_log_reader
    WITH NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS
    PASSWORD :'bridge_password';
ALTER ROLE cpa_log_reader SET default_transaction_read_only = on;
ALTER ROLE cpa_log_reader SET statement_timeout = '5s';
ALTER ROLE cpa_log_reader SET lock_timeout = '1s';
ALTER ROLE cpa_log_reader SET idle_in_transaction_session_timeout = '5s';
ALTER ROLE cpa_log_reader SET search_path = cpa_log_bridge, pg_catalog;
REVOKE cpa_log_bridge_owner FROM cpa_log_reader;

REVOKE ALL ON DATABASE "new-api" FROM cpa_log_reader;
REVOKE ALL ON SCHEMA public FROM cpa_log_reader;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM cpa_log_reader;
GRANT CONNECT ON DATABASE "new-api" TO cpa_log_reader;
GRANT USAGE ON SCHEMA cpa_log_bridge TO cpa_log_reader;
REVOKE ALL ON cpa_log_bridge.claude_logs FROM cpa_log_reader;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA cpa_log_bridge FROM cpa_log_reader;
GRANT EXECUTE ON FUNCTION cpa_log_bridge.changes(bigint, integer) TO cpa_log_reader;
GRANT EXECUTE ON FUNCTION cpa_log_bridge.search_initial(bigint, bigint, integer) TO cpa_log_reader;
GRANT EXECUTE ON FUNCTION cpa_log_bridge.search_boundary(bigint) TO cpa_log_reader;
GRANT EXECUTE ON FUNCTION cpa_log_bridge.search_before(bigint, bigint, bigint, bigint, integer) TO cpa_log_reader;
GRANT EXECUTE ON FUNCTION cpa_log_bridge.lookup_primary(text) TO cpa_log_reader;
GRANT EXECUTE ON FUNCTION cpa_log_bridge.lookup_upstream(text) TO cpa_log_reader;

DO $verification$
DECLARE
    table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY['public.logs', 'public.users', 'public.tokens', 'public.channels']
    LOOP
        IF to_regclass(table_name) IS NOT NULL
           AND has_table_privilege('cpa_log_reader', table_name, 'SELECT') THEN
            RAISE EXCEPTION 'cpa_log_reader unexpectedly has SELECT on %', table_name;
        END IF;
    END LOOP;
END;
$verification$;

DO $view_verification$
BEGIN
    IF has_table_privilege('cpa_log_reader', 'cpa_log_bridge.claude_logs', 'SELECT') THEN
        RAISE EXCEPTION 'cpa_log_reader unexpectedly has SELECT on the bridge view';
    END IF;
    IF has_any_column_privilege('cpa_log_reader', 'public.logs', 'SELECT') THEN
        RAISE EXCEPTION 'cpa_log_reader unexpectedly has column SELECT on public.logs';
    END IF;
    IF has_schema_privilege('cpa_log_reader', 'cpa_log_bridge', 'CREATE') THEN
        RAISE EXCEPTION 'cpa_log_reader unexpectedly has CREATE on the bridge schema';
    END IF;
    IF pg_has_role('cpa_log_reader', 'cpa_log_bridge_owner', 'MEMBER') THEN
        RAISE EXCEPTION 'cpa_log_reader unexpectedly belongs to cpa_log_bridge_owner';
    END IF;
END;
$view_verification$;

DO $owner_verification$
DECLARE
    column_name text;
    function_signature text;
    function_row record;
BEGIN
    IF (SELECT rolcanlogin OR rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls
        FROM pg_roles WHERE rolname = 'cpa_log_bridge_owner') THEN
        RAISE EXCEPTION 'cpa_log_bridge_owner has an unsafe role attribute';
    END IF;
    IF has_schema_privilege('cpa_log_bridge_owner', 'public', 'CREATE') THEN
        RAISE EXCEPTION 'cpa_log_bridge_owner unexpectedly has CREATE on schema public';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM pg_auth_members AS membership
        JOIN pg_roles AS owner_role ON owner_role.oid = membership.member
        WHERE owner_role.rolname = 'cpa_log_bridge_owner'
    ) THEN
        RAISE EXCEPTION 'cpa_log_bridge_owner unexpectedly belongs to another role';
    END IF;

    FOREACH column_name IN ARRAY ARRAY[
        'id', 'created_at', 'type', 'model_name', 'other', 'use_time',
        'request_id', 'upstream_request_id', 'group'
    ]
    LOOP
        IF NOT has_column_privilege('cpa_log_bridge_owner', 'public.logs', column_name, 'SELECT') THEN
            RAISE EXCEPTION 'cpa_log_bridge_owner is missing SELECT on public.logs.%', column_name;
        END IF;
    END LOOP;

    FOR column_name IN
        SELECT attribute.attname
        FROM pg_attribute AS attribute
        WHERE attribute.attrelid = 'public.logs'::regclass
          AND attribute.attnum > 0
          AND NOT attribute.attisdropped
          AND attribute.attname::text <> ALL (ARRAY[
              'id', 'created_at', 'type', 'model_name', 'other', 'use_time',
              'request_id', 'upstream_request_id', 'group'
          ])
    LOOP
        IF has_column_privilege('cpa_log_bridge_owner', 'public.logs', column_name, 'SELECT') THEN
            RAISE EXCEPTION 'cpa_log_bridge_owner unexpectedly has SELECT on public.logs.%', column_name;
        END IF;
    END LOOP;

    IF EXISTS (
        SELECT 1
        FROM pg_proc AS procedure
        JOIN pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
        CROSS JOIN LATERAL aclexplode(
            COALESCE(procedure.proacl, acldefault('f', procedure.proowner))
        ) AS privilege
        WHERE namespace.nspname = 'cpa_log_bridge'
          AND privilege.grantee = 0
          AND privilege.privilege_type = 'EXECUTE'
    ) THEN
        RAISE EXCEPTION 'PUBLIC unexpectedly has EXECUTE on a bridge function';
    END IF;

    FOREACH function_signature IN ARRAY ARRAY[
        'cpa_log_bridge.changes(bigint,integer)',
        'cpa_log_bridge.search_initial(bigint,bigint,integer)',
        'cpa_log_bridge.search_boundary(bigint)',
        'cpa_log_bridge.search_before(bigint,bigint,bigint,bigint,integer)',
        'cpa_log_bridge.lookup_primary(text)',
        'cpa_log_bridge.lookup_upstream(text)'
    ]
    LOOP
        SELECT procedure.proowner = owner_role.oid AS owned_by_bridge,
               procedure.prosecdef AS security_definer,
               procedure.proparallel = 'u' AS parallel_unsafe,
               COALESCE(procedure.proconfig, ARRAY[]::text[]) @>
                   ARRAY['search_path=pg_catalog', 'row_security=on'] AS safe_config,
               EXISTS (
                   SELECT 1
                   FROM aclexplode(COALESCE(procedure.proacl, acldefault('f', procedure.proowner))) AS privilege
                   WHERE privilege.grantee = 0
                     AND privilege.privilege_type = 'EXECUTE'
               ) AS public_execute
        INTO function_row
        FROM pg_proc AS procedure
        JOIN pg_roles AS owner_role ON owner_role.rolname = 'cpa_log_bridge_owner'
        WHERE procedure.oid = to_regprocedure(function_signature);

        IF NOT FOUND OR NOT function_row.owned_by_bridge OR NOT function_row.security_definer
           OR NOT function_row.parallel_unsafe OR NOT function_row.safe_config
           OR function_row.public_execute THEN
            RAISE EXCEPTION 'unsafe bridge function definition: %', function_signature;
        END IF;
    END LOOP;
END;
$owner_verification$;

COMMIT;

-- The reader must receive only EXECUTE on the fixed bridge functions: no
-- SELECT on the security-barrier view or any base table.
SELECT grantee, table_schema, table_name, privilege_type
FROM information_schema.role_table_grants
WHERE grantee = 'cpa_log_reader'
ORDER BY table_schema, table_name, privilege_type;

SELECT grantee, routine_schema, routine_name, privilege_type
FROM information_schema.role_routine_grants
WHERE grantee = 'cpa_log_reader'
ORDER BY routine_schema, routine_name, privilege_type;
