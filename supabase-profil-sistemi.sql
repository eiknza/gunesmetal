-- Gunes Metal hesap profilleri ve yonetici uye listesi
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text not null default '',
  email text not null default '',
  phone text not null default '',
  created_at timestamptz not null default now(),
  last_name_change_at timestamptz
);
alter table public.profiles enable row level security;
grant select, insert, update on public.profiles to authenticated;
drop policy if exists "Users read own profile" on public.profiles;
create policy "Users read own profile" on public.profiles for select to authenticated using (id = auth.uid() or public.is_review_admin());
drop policy if exists "Users insert own profile" on public.profiles;
create policy "Users insert own profile" on public.profiles for insert to authenticated with check (id = auth.uid());
drop policy if exists "Users update own profile" on public.profiles;
create policy "Users update own profile" on public.profiles for update to authenticated using (id = auth.uid()) with check (id = auth.uid());

create or replace function public.sync_new_profile()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
 insert into public.profiles(id, full_name, email) values(new.id, coalesce(new.raw_user_meta_data->>'full_name',''), coalesce(new.email,''))
 on conflict(id) do update set email=excluded.email;
 return new;
end; $$;
drop trigger if exists on_auth_user_profile_created on auth.users;
create trigger on_auth_user_profile_created after insert or update of email on auth.users for each row execute function public.sync_new_profile();

create or replace function public.update_my_profile(p_full_name text, p_phone text)
returns void language plpgsql security definer set search_path = '' as $$
declare old_name text; changed_at timestamptz;
begin
 select full_name,last_name_change_at into old_name,changed_at from public.profiles where id=auth.uid() for update;
 if not found then raise exception 'PROFILE_NOT_FOUND'; end if;
 if coalesce(old_name,'') <> coalesce(trim(p_full_name),'') then
   if changed_at is not null and changed_at > now() - interval '15 days' then raise exception 'NAME_CHANGE_WAIT_15_DAYS'; end if;
   update public.profiles set full_name=trim(p_full_name), phone=trim(coalesce(p_phone,'')), last_name_change_at=now() where id=auth.uid();
 else
   update public.profiles set phone=trim(coalesce(p_phone,'')) where id=auth.uid();
 end if;
 update auth.users set raw_user_meta_data = coalesce(raw_user_meta_data,'{}'::jsonb) || jsonb_build_object('full_name',trim(p_full_name)) where id=auth.uid();
end; $$;
revoke all on function public.update_my_profile(text,text) from public;
grant execute on function public.update_my_profile(text,text) to authenticated;

-- Yonetici tum uye profillerini gorebilir; normal kullanicilar yalnizca kendi profilini gorebilir.

insert into public.profiles(id,full_name,email) select id,coalesce(raw_user_meta_data->>'full_name',''),coalesce(email,'') from auth.users on conflict(id) do update set email=excluded.email;
