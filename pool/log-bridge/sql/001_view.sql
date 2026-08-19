\set ON_ERROR_STOP on

BEGIN;

SELECT 'CREATE ROLE cpa_log_bridge_owner NOLOGIN'
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cpa_log_bridge_owner')
\gexec

ALTER ROLE cpa_log_bridge_owner
    WITH NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
ALTER ROLE cpa_log_bridge_owner SET default_transaction_read_only = on;

CREATE SCHEMA IF NOT EXISTS cpa_log_bridge;

CREATE OR REPLACE FUNCTION cpa_log_bridge.safe_status_code(log_type bigint, payload text)
RETURNS integer
LANGUAGE plpgsql
IMMUTABLE
PARALLEL UNSAFE
AS $function$
DECLARE
    raw_status text;
BEGIN
    BEGIN
        raw_status := payload::jsonb ->> 'status_code';
    EXCEPTION
        WHEN invalid_text_representation THEN
            raw_status := NULL;
    END;

    IF raw_status ~ '^[1-5][0-9][0-9]$' THEN
        RETURN raw_status::integer;
    END IF;
    IF log_type = 2 THEN
        RETURN 200;
    END IF;
    RETURN 502;
END;
$function$;

CREATE OR REPLACE VIEW cpa_log_bridge.claude_logs
WITH (security_barrier = true)
AS
SELECT
    logs.id::bigint AS source_id,
    logs.created_at::bigint AS created_at,
    logs.type::integer AS type,
    logs.model_name AS model_name,
    cpa_log_bridge.safe_status_code(logs.type, logs.other) AS status,
    LEAST(GREATEST(COALESCE(logs.use_time, 0), 0), 9223372036854775)::bigint * 1000 AS latency_ms,
    logs.request_id AS request_id,
    CASE
        WHEN OCTET_LENGTH(logs.upstream_request_id) BETWEEN 1 AND 128
         AND logs.upstream_request_id !~ '[[:cntrl:]]'
        THEN logs.upstream_request_id
        ELSE NULL
    END AS upstream_request_id
FROM public.logs
WHERE logs.type IN (2, 5)
  AND logs.created_at >= 0
  AND logs.model_name LIKE 'claude-%'
  AND OCTET_LENGTH(logs.model_name) BETWEEN 8 AND 128
  AND logs.model_name !~ '[[:cntrl:]]'
  AND logs.request_id IS NOT NULL
  AND OCTET_LENGTH(logs.request_id) BETWEEN 1 AND 128
  AND logs.request_id !~ '[[:cntrl:]]';

COMMENT ON VIEW cpa_log_bridge.claude_logs IS
    'Strict CPA bridge projection of Claude consume/error logs; excludes user, token, IP, content and raw metadata.';

CREATE OR REPLACE FUNCTION cpa_log_bridge.changes(p_after_id bigint, p_limit integer)
RETURNS TABLE (
    source_id bigint, created_at bigint, type integer, model_name text,
    status integer, latency_ms bigint, request_id text, upstream_request_id text
)
LANGUAGE sql
STABLE
SECURITY DEFINER
PARALLEL UNSAFE
SET search_path = pg_catalog
SET row_security = on
AS $function$
    SELECT
        logs.id::bigint,
        logs.created_at::bigint,
        logs.type::integer,
        logs.model_name::text,
        cpa_log_bridge.safe_status_code(logs.type, logs.other),
        LEAST(GREATEST(COALESCE(logs.use_time, 0), 0), 9223372036854775)::bigint * 1000,
        logs.request_id::text,
        CASE
            WHEN OCTET_LENGTH(logs.upstream_request_id) BETWEEN 1 AND 128
             AND logs.upstream_request_id !~ '[[:cntrl:]]'
            THEN logs.upstream_request_id::text
            ELSE NULL
        END
    FROM public.logs AS logs
    WHERE logs.type IN (2, 5)
      AND logs.created_at >= 0
      AND logs.model_name LIKE 'claude-%'
      AND OCTET_LENGTH(logs.model_name) BETWEEN 8 AND 128
      AND logs.model_name !~ '[[:cntrl:]]'
      AND logs.request_id IS NOT NULL
      AND OCTET_LENGTH(logs.request_id) BETWEEN 1 AND 128
      AND logs.request_id !~ '[[:cntrl:]]'
      AND logs.id > GREATEST(COALESCE(p_after_id, 0), 0)
    ORDER BY logs.id ASC
    LIMIT LEAST(GREATEST(COALESCE(p_limit, 1), 1), 1001)
$function$;

CREATE OR REPLACE FUNCTION cpa_log_bridge.search_initial(p_from bigint, p_to bigint, p_limit integer)
RETURNS TABLE (
    source_id bigint, created_at bigint, type integer, model_name text,
    status integer, latency_ms bigint, request_id text, upstream_request_id text
)
LANGUAGE sql
STABLE
SECURITY DEFINER
PARALLEL UNSAFE
SET search_path = pg_catalog
SET row_security = on
AS $function$
    SELECT
        logs.id::bigint,
        logs.created_at::bigint,
        logs.type::integer,
        logs.model_name::text,
        cpa_log_bridge.safe_status_code(logs.type, logs.other),
        LEAST(GREATEST(COALESCE(logs.use_time, 0), 0), 9223372036854775)::bigint * 1000,
        logs.request_id::text,
        CASE
            WHEN OCTET_LENGTH(logs.upstream_request_id) BETWEEN 1 AND 128
             AND logs.upstream_request_id !~ '[[:cntrl:]]'
            THEN logs.upstream_request_id::text
            ELSE NULL
        END
    FROM public.logs AS logs
    WHERE logs.type IN (2, 5)
      AND logs.created_at >= 0
      AND logs.model_name LIKE 'claude-%'
      AND OCTET_LENGTH(logs.model_name) BETWEEN 8 AND 128
      AND logs.model_name !~ '[[:cntrl:]]'
      AND logs.request_id IS NOT NULL
      AND OCTET_LENGTH(logs.request_id) BETWEEN 1 AND 128
      AND logs.request_id !~ '[[:cntrl:]]'
      AND p_from >= 0
      AND p_to >= p_from
      AND p_to - p_from <= 7776000
      AND p_to <= EXTRACT(EPOCH FROM CURRENT_TIMESTAMP)::bigint + 60
      AND logs.created_at >= p_from
      AND logs.created_at <= p_to
    ORDER BY logs.created_at DESC, logs.id DESC
    LIMIT LEAST(GREATEST(COALESCE(p_limit, 1), 1), 1001)
$function$;

CREATE OR REPLACE FUNCTION cpa_log_bridge.search_boundary(p_source_id bigint)
RETURNS TABLE (created_at bigint, source_id bigint)
LANGUAGE sql
STABLE
SECURITY DEFINER
PARALLEL UNSAFE
SET search_path = pg_catalog
SET row_security = on
AS $function$
    SELECT logs.created_at::bigint, logs.id::bigint
    FROM public.logs AS logs
    WHERE logs.type IN (2, 5)
      AND logs.created_at >= 0
      AND logs.model_name LIKE 'claude-%'
      AND OCTET_LENGTH(logs.model_name) BETWEEN 8 AND 128
      AND logs.model_name !~ '[[:cntrl:]]'
      AND logs.request_id IS NOT NULL
      AND OCTET_LENGTH(logs.request_id) BETWEEN 1 AND 128
      AND logs.request_id !~ '[[:cntrl:]]'
      AND logs.id = GREATEST(COALESCE(p_source_id, 0), 0)
    LIMIT 1
$function$;

CREATE OR REPLACE FUNCTION cpa_log_bridge.search_before(
    p_from bigint, p_to bigint, p_before_created_at bigint,
    p_before_source_id bigint, p_limit integer
)
RETURNS TABLE (
    source_id bigint, created_at bigint, type integer, model_name text,
    status integer, latency_ms bigint, request_id text, upstream_request_id text
)
LANGUAGE sql
STABLE
SECURITY DEFINER
PARALLEL UNSAFE
SET search_path = pg_catalog
SET row_security = on
AS $function$
    SELECT
        logs.id::bigint,
        logs.created_at::bigint,
        logs.type::integer,
        logs.model_name::text,
        cpa_log_bridge.safe_status_code(logs.type, logs.other),
        LEAST(GREATEST(COALESCE(logs.use_time, 0), 0), 9223372036854775)::bigint * 1000,
        logs.request_id::text,
        CASE
            WHEN OCTET_LENGTH(logs.upstream_request_id) BETWEEN 1 AND 128
             AND logs.upstream_request_id !~ '[[:cntrl:]]'
            THEN logs.upstream_request_id::text
            ELSE NULL
        END
    FROM public.logs AS logs
    WHERE logs.type IN (2, 5)
      AND logs.created_at >= 0
      AND logs.model_name LIKE 'claude-%'
      AND OCTET_LENGTH(logs.model_name) BETWEEN 8 AND 128
      AND logs.model_name !~ '[[:cntrl:]]'
      AND logs.request_id IS NOT NULL
      AND OCTET_LENGTH(logs.request_id) BETWEEN 1 AND 128
      AND logs.request_id !~ '[[:cntrl:]]'
      AND p_from >= 0
      AND p_to >= p_from
      AND p_to - p_from <= 7776000
      AND p_to <= EXTRACT(EPOCH FROM CURRENT_TIMESTAMP)::bigint + 60
      AND p_before_created_at >= 0
      AND p_before_source_id > 0
      AND logs.created_at >= p_from
      AND logs.created_at <= p_to
      AND (logs.created_at, logs.id) < (
          p_before_created_at,
          p_before_source_id
      )
    ORDER BY logs.created_at DESC, logs.id DESC
    LIMIT LEAST(GREATEST(COALESCE(p_limit, 1), 1), 1001)
$function$;

CREATE OR REPLACE FUNCTION cpa_log_bridge.lookup_primary(p_request_id text)
RETURNS TABLE (
    source_id bigint, created_at bigint, type integer, model_name text,
    status integer, latency_ms bigint, request_id text, upstream_request_id text
)
LANGUAGE sql
STABLE
SECURITY DEFINER
PARALLEL UNSAFE
SET search_path = pg_catalog
SET row_security = on
AS $function$
    SELECT
        logs.id::bigint,
        logs.created_at::bigint,
        logs.type::integer,
        logs.model_name::text,
        cpa_log_bridge.safe_status_code(logs.type, logs.other),
        LEAST(GREATEST(COALESCE(logs.use_time, 0), 0), 9223372036854775)::bigint * 1000,
        logs.request_id::text,
        CASE
            WHEN OCTET_LENGTH(logs.upstream_request_id) BETWEEN 1 AND 128
             AND logs.upstream_request_id !~ '[[:cntrl:]]'
            THEN logs.upstream_request_id::text
            ELSE NULL
        END
    FROM public.logs AS logs
    WHERE logs.type IN (2, 5)
      AND logs.created_at >= 0
      AND logs.model_name LIKE 'claude-%'
      AND OCTET_LENGTH(logs.model_name) BETWEEN 8 AND 128
      AND logs.model_name !~ '[[:cntrl:]]'
      AND logs.request_id IS NOT NULL
      AND OCTET_LENGTH(logs.request_id) BETWEEN 1 AND 128
      AND logs.request_id !~ '[[:cntrl:]]'
      AND OCTET_LENGTH(COALESCE(p_request_id, '')) BETWEEN 1 AND 128
      AND COALESCE(p_request_id, '') !~ '[[:cntrl:]]'
      AND logs.request_id = p_request_id
    ORDER BY logs.id DESC
    LIMIT 1
$function$;

CREATE OR REPLACE FUNCTION cpa_log_bridge.lookup_upstream(p_request_id text)
RETURNS TABLE (
    source_id bigint, created_at bigint, type integer, model_name text,
    status integer, latency_ms bigint, request_id text, upstream_request_id text
)
LANGUAGE sql
STABLE
SECURITY DEFINER
PARALLEL UNSAFE
SET search_path = pg_catalog
SET row_security = on
AS $function$
    SELECT
        logs.id::bigint,
        logs.created_at::bigint,
        logs.type::integer,
        logs.model_name::text,
        cpa_log_bridge.safe_status_code(logs.type, logs.other),
        LEAST(GREATEST(COALESCE(logs.use_time, 0), 0), 9223372036854775)::bigint * 1000,
        logs.request_id::text,
        CASE
            WHEN OCTET_LENGTH(logs.upstream_request_id) BETWEEN 1 AND 128
             AND logs.upstream_request_id !~ '[[:cntrl:]]'
            THEN logs.upstream_request_id::text
            ELSE NULL
        END
    FROM public.logs AS logs
    WHERE logs.type IN (2, 5)
      AND logs.created_at >= 0
      AND logs.model_name LIKE 'claude-%'
      AND OCTET_LENGTH(logs.model_name) BETWEEN 8 AND 128
      AND logs.model_name !~ '[[:cntrl:]]'
      AND logs.request_id IS NOT NULL
      AND OCTET_LENGTH(logs.request_id) BETWEEN 1 AND 128
      AND logs.request_id !~ '[[:cntrl:]]'
      AND OCTET_LENGTH(logs.upstream_request_id) BETWEEN 1 AND 128
      AND logs.upstream_request_id !~ '[[:cntrl:]]'
      AND OCTET_LENGTH(COALESCE(p_request_id, '')) BETWEEN 1 AND 128
      AND COALESCE(p_request_id, '') !~ '[[:cntrl:]]'
      AND logs.upstream_request_id = p_request_id
    ORDER BY logs.id DESC
    LIMIT 100
$function$;

REVOKE ALL ON public.logs FROM cpa_log_bridge_owner;
SELECT format(
    'REVOKE SELECT (%I) ON TABLE public.logs FROM cpa_log_bridge_owner',
    attribute.attname
)
FROM pg_attribute AS attribute
WHERE attribute.attrelid = 'public.logs'::regclass
  AND attribute.attnum > 0
  AND NOT attribute.attisdropped
\gexec

GRANT USAGE ON SCHEMA public TO cpa_log_bridge_owner;
GRANT SELECT (
    id, created_at, type, model_name, other, use_time, request_id,
    upstream_request_id
) ON public.logs TO cpa_log_bridge_owner;

REVOKE ALL ON SCHEMA cpa_log_bridge FROM PUBLIC;
REVOKE ALL ON cpa_log_bridge.claude_logs FROM PUBLIC;
REVOKE ALL ON FUNCTION cpa_log_bridge.safe_status_code(bigint, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION cpa_log_bridge.changes(bigint, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION cpa_log_bridge.search_initial(bigint, bigint, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION cpa_log_bridge.search_boundary(bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION cpa_log_bridge.search_before(bigint, bigint, bigint, bigint, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION cpa_log_bridge.lookup_primary(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION cpa_log_bridge.lookup_upstream(text) FROM PUBLIC;

ALTER VIEW cpa_log_bridge.claude_logs OWNER TO cpa_log_bridge_owner;
ALTER FUNCTION cpa_log_bridge.safe_status_code(bigint, text) OWNER TO cpa_log_bridge_owner;
ALTER FUNCTION cpa_log_bridge.changes(bigint, integer) OWNER TO cpa_log_bridge_owner;
ALTER FUNCTION cpa_log_bridge.search_initial(bigint, bigint, integer) OWNER TO cpa_log_bridge_owner;
ALTER FUNCTION cpa_log_bridge.search_boundary(bigint) OWNER TO cpa_log_bridge_owner;
ALTER FUNCTION cpa_log_bridge.search_before(bigint, bigint, bigint, bigint, integer) OWNER TO cpa_log_bridge_owner;
ALTER FUNCTION cpa_log_bridge.lookup_primary(text) OWNER TO cpa_log_bridge_owner;
ALTER FUNCTION cpa_log_bridge.lookup_upstream(text) OWNER TO cpa_log_bridge_owner;
ALTER SCHEMA cpa_log_bridge OWNER TO cpa_log_bridge_owner;

COMMIT;
