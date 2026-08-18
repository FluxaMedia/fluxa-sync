create extension if not exists pg_cron with schema extensions;

do $$
begin
    perform cron.unschedule(jobid) from cron.job where jobname = 'fluxa_sync_retention';
exception when others then
    null;
end $$;

select cron.schedule(
    'fluxa_sync_retention',
    '0 3 * * *',
    $cron$
    delete from public.sync_events where created_at < now() - interval '90 days';
    delete from public.sync_audit_log where created_at < now() - interval '30 days';
    delete from public.watch_progress_events where created_at < now() - interval '30 days';
    delete from public.watched_item_events where created_at < now() - interval '30 days';
    $cron$
);
