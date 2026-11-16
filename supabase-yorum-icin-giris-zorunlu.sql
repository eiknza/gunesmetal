-- Yorum göndermek için oturum açma zorunluluğu ve soyadı maskeleme güncellemesi.
-- Supabase SQL Editor > New Query alanında bu dosyanın tamamını bir kez çalıştırın.

create extension if not exists pgcrypto with schema extensions;
alter table public.reviews add column if not exists ip_hash text;

-- İsim artık herkese maskeli yazıldığı için soyadına göre tekillik kontrolünü kaldır.
-- Aynı hesap ve aynı IP için tek yorum koruması devam eder.
drop index if exists public.reviews_unique_name_ci;
create unique index if not exists reviews_unique_email_ci on public.reviews (lower(btrim(email)));
create unique index if not exists reviews_unique_ip_hash on public.reviews (ip_hash) where ip_hash is not null;

-- Önceden yayımlanmış yorumlardaki adları da maskeli soyada dönüştür.
with source_names as (
  select id,
    case
      when btrim(name) ~ '^[^[:space:]]+\*{2,}$' then btrim(name)
      when position(' ' in btrim(name)) > 0 then regexp_replace(btrim(name), '^.*\s+', '')
      else 'Üye'
    end as surname
  from public.reviews
)
update public.reviews as review
set name = upper(left(source_names.surname, 1)) || repeat('*', greatest(3, char_length(source_names.surname) - 1))
from source_names
where review.id = source_names.id;

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
  v_surname text := btrim(coalesce(p_name, ''));
  v_name text;
  v_email text := lower(btrim(coalesce(p_email, '')));
  v_message text := btrim(coalesce(p_message, ''));
  v_headers jsonb;
  v_ip text;
  v_ip_hash text;
  v_user_email text;
begin
  if auth.uid() is null then raise exception 'LOGIN_REQUIRED'; end if;
  v_user_email := lower(coalesce(auth.jwt() ->> 'email', ''));
  if v_user_email = '' or v_email <> v_user_email then raise exception 'EMAIL_MISMATCH'; end if;
  if char_length(v_surname) < 2 or char_length(v_surname) > 80 then raise exception 'INVALID_NAME'; end if;
  if char_length(v_email) < 5 or char_length(v_email) > 254 or position('@' in v_email) = 0 then raise exception 'INVALID_EMAIL'; end if;
  if p_rating < 1 or p_rating > 5 then raise exception 'INVALID_RATING'; end if;
  if char_length(v_message) < 3 or char_length(v_message) > 1000 then raise exception 'INVALID_MESSAGE'; end if;

  -- Veritabanında da yalnızca maskeli soyadı sakla.
  v_name := upper(left(v_surname, 1)) || repeat('*', greatest(3, char_length(v_surname) - 1));

  v_headers := coalesce(nullif(current_setting('request.headers', true), '')::jsonb, '{}'::jsonb);
  v_ip := coalesce(v_headers ->> 'cf-connecting-ip', split_part(coalesce(v_headers ->> 'x-forwarded-for', v_headers ->> 'x-real-ip', ''), ',', 1));
  v_ip := nullif(btrim(v_ip), '');
  if v_ip is null then raise exception 'IP_NOT_AVAILABLE'; end if;
  v_ip_hash := encode(digest(v_ip, 'sha256'), 'hex');

  if exists (select 1 from public.reviews where lower(btrim(email)) = v_email) then raise exception 'DUPLICATE_EMAIL'; end if;
  if exists (select 1 from public.reviews where ip_hash = v_ip_hash) then raise exception 'DUPLICATE_IP'; end if;

  insert into public.reviews (name, email, rating, message, status, ip_hash)
  values (v_name, v_email, p_rating, v_message, 'pending', v_ip_hash);
exception when unique_violation then raise exception 'DUPLICATE_REVIEW';
end;
$$;

revoke all on function public.submit_review(text, text, integer, text) from public, anon;
grant execute on function public.submit_review(text, text, integer, text) to authenticated;

-- Ziyaretçi tarafında yalnızca onaylı yorumların name/rating/message alanları gösterilir.
-- E-posta adresi veritabanında anti-spam kontrolü için tutulur; herkese açık SELECT izni verilmez.
