-- Güneş Metal: kullanıcı teklif iptalini 3 dakika içinde geri alabilsin.
alter table public.quote_requests add column if not exists cancelled_at timestamptz;
alter table public.quote_requests add column if not exists cancelled_from_status text;

create or replace function public.cancel_my_quote_request(p_quote_id bigint)
returns boolean language plpgsql security definer set search_path = public as $$
declare changed integer;
begin
  if auth.uid() is null then raise exception 'LOGIN_REQUIRED'; end if;
  update public.quote_requests
  set status='cancelled',cancelled_at=now(),cancelled_from_status=status
  where id=p_quote_id and user_id=auth.uid() and status in ('pending','contacted','quoted');
  get diagnostics changed = row_count;
  return changed = 1;
end;
$$;
revoke all on function public.cancel_my_quote_request(bigint) from public, anon;
grant execute on function public.cancel_my_quote_request(bigint) to authenticated;

create or replace function public.restore_my_quote_request(p_quote_id bigint)
returns boolean language plpgsql security definer set search_path = public as $$
declare changed integer;
begin
  if auth.uid() is null then raise exception 'LOGIN_REQUIRED'; end if;
  update public.quote_requests
  set status=coalesce(cancelled_from_status,'pending'),cancelled_at=null,cancelled_from_status=null
  where id=p_quote_id and user_id=auth.uid() and status='cancelled'
    and cancelled_at is not null and cancelled_at >= now()-interval '3 minutes';
  get diagnostics changed = row_count;
  return changed = 1;
end;
$$;
revoke all on function public.restore_my_quote_request(bigint) from public, anon;
grant execute on function public.restore_my_quote_request(bigint) to authenticated;
