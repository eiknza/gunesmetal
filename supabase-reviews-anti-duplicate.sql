-- Gunes Metal yorum sistemi: ayni isim, e-posta ve IP adresinden yalnizca bir yorum.
-- Supabase SQL Editor > New query alaninda bu dosyanin tamamini calistirin.

create extension if not exists pgcrypto with schema extensions;

alter table public.reviews add column if not exists ip_hash text;

create unique index if not exists reviews_unique_name_ci
  on public.reviews (lower(btrim(name)));

create unique index if not exists reviews_unique_email_ci
  on public.reviews (lower(btrim(email)));

create unique index if not exists reviews_unique_ip_hash
  on public.reviews (ip_hash)
  where ip_hash is not null;

create or replace function public.submit_review(
  p_name text,
  p_email text,
  p_rating integer,
  p_message text
)
returns void
language plpgsql
security definer
set search_path = public, extensions, pg_temp
as $$
declare
  v_name text := btrim(coalesce(p_name, ''));
  v_email text := lower(btrim(coalesce(p_email, '')));
  v_message text := btrim(coalesce(p_message, ''));
  v_headers jsonb;
  v_ip text;
  v_ip_hash text;
begin
  if char_length(v_name) < 2 or char_length(v_name) > 80 then
    raise exception 'INVALID_NAME';
  end if;
  if char_length(v_email) < 5 or char_length(v_email) > 254 or position('@' in v_email) = 0 then
    raise exception 'INVALID_EMAIL';
  end if;
  if p_rating < 1 or p_rating > 5 then
    raise exception 'INVALID_RATING';
  end if;
  if char_length(v_message) < 3 or char_length(v_message) > 1000 then
    raise exception 'INVALID_MESSAGE';
  end if;

  v_headers := coalesce(nullif(current_setting('request.headers', true), '')::jsonb, '{}'::jsonb);
  v_ip := coalesce(
    v_headers ->> 'cf-connecting-ip',
    split_part(coalesce(v_headers ->> 'x-forwarded-for', v_headers ->> 'x-real-ip', ''), ',', 1)
  );
  v_ip := nullif(btrim(v_ip), '');
  if v_ip is null then
    raise exception 'IP_NOT_AVAILABLE';
  end if;
  v_ip_hash := encode(digest(v_ip, 'sha256'), 'hex');

  if exists (select 1 from public.reviews where lower(btrim(name)) = lower(v_name)) then
    raise exception 'DUPLICATE_NAME';
  end if;
  if exists (select 1 from public.reviews where lower(btrim(email)) = v_email) then
    raise exception 'DUPLICATE_EMAIL';
  end if;
  if exists (select 1 from public.reviews where ip_hash = v_ip_hash) then
    raise exception 'DUPLICATE_IP';
  end if;

  insert into public.reviews (name, email, rating, message, status, ip_hash)
  values (v_name, v_email, p_rating, v_message, 'pending', v_ip_hash);
exception
  when unique_violation then
    raise exception 'DUPLICATE_REVIEW';
end;
$$;

-- Ziyaretciler tabloya dogrudan yazamasin; sadece yukaridaki kontrollu fonksiyonu cagirabilsin.
revoke insert on public.reviews from anon, authenticated;
grant execute on function public.submit_review(text, text, integer, text) to anon, authenticated;

-- E-posta ve IP hash'i herkese acik degildir; onayli yorumlar icin mevcut okuma izinleri korunur.
