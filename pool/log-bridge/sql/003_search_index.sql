\set ON_ERROR_STOP on

-- The existing pagination indexes include every Claude group and therefore
-- still scan unrelated rows. Together with the fixed SECURITY DEFINER search
-- functions in 001_view.sql, this narrow max-group partial index lets
-- 30-minute through 90-day bridge searches stop at the requested page instead
-- of scanning and sorting millions of log rows. CONCURRENTLY keeps New API
-- inserts available while the initial index is built.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_cpa_log_bridge_max_created_id_v3
ON public.logs (created_at DESC, id DESC)
WHERE type IN (2, 5)
  AND created_at >= 0
  AND "group" = 'max'
  AND model_name LIKE 'claude-%'
  AND OCTET_LENGTH(model_name) BETWEEN 8 AND 128
  AND model_name !~ '[[:cntrl:]]'
  AND request_id IS NOT NULL
  AND OCTET_LENGTH(request_id) BETWEEN 1 AND 128
  AND request_id !~ '[[:cntrl:]]';

COMMENT ON INDEX public.idx_cpa_log_bridge_max_created_id_v3 IS
    'Pagination index for the read-only CPA Claude max-group log bridge.';

-- Keep the former v2 and idx_cpa_log_bridge_created_id indexes until both
-- 24-hour and 90-day first/cursor-page EXPLAIN checks select this v3 index.
-- They can then be removed separately with:
-- DROP INDEX CONCURRENTLY IF EXISTS public.idx_cpa_log_bridge_safe_created_id_v2;
-- DROP INDEX CONCURRENTLY IF EXISTS public.idx_cpa_log_bridge_created_id;
