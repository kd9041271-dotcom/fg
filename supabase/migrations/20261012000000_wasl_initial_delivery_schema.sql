-- Wasl Delivery initial schema. Safe additive migration; no existing tables are dropped.
create extension if not exists pgcrypto;
create table if not exists public.profiles (
 id uuid primary key references auth.users(id) on delete cascade,
 full_name text, phone text,
 role text not null default 'customer' check (role in ('customer','driver','store_owner','admin')),
 created_at timestamptz not null default now()
);
create table if not exists public.stores (
 id uuid primary key default gen_random_uuid(),
 owner_id uuid references public.profiles(id) on delete set null,
 name text not null, description text, address text, phone text,
 is_active boolean not null default true, created_at timestamptz not null default now()
);
create table if not exists public.products (
 id uuid primary key default gen_random_uuid(),
 store_id uuid not null references public.stores(id) on delete cascade,
 name text not null, description text, price_dzd numeric(12,2) not null check (price_dzd >= 0),
 is_available boolean not null default true, created_at timestamptz not null default now()
);
create table if not exists public.orders (
 id uuid primary key default gen_random_uuid(),
 customer_id uuid not null references public.profiles(id),
 store_id uuid not null references public.stores(id),
 driver_id uuid references public.profiles(id) on delete set null,
 status text not null default 'pending' check (status in ('pending','accepted','preparing','ready','picked_up','delivered','cancelled')),
 delivery_address text not null, customer_note text,
 total_dzd numeric(12,2) not null default 0 check (total_dzd >= 0),
 created_at timestamptz not null default now(), updated_at timestamptz not null default now()
);
create table if not exists public.order_items (
 id uuid primary key default gen_random_uuid(),
 order_id uuid not null references public.orders(id) on delete cascade,
 product_id uuid references public.products(id) on delete set null,
 product_name text not null, quantity integer not null check (quantity > 0),
 unit_price_dzd numeric(12,2) not null check (unit_price_dzd >= 0)
);
create index if not exists stores_active_idx on public.stores(is_active);
create index if not exists products_store_idx on public.products(store_id);
create index if not exists orders_customer_created_idx on public.orders(customer_id, created_at desc);
create index if not exists orders_driver_status_idx on public.orders(driver_id, status);
create index if not exists orders_store_status_idx on public.orders(store_id, status);
alter table public.profiles enable row level security;
alter table public.stores enable row level security;
alter table public.products enable row level security;
alter table public.orders enable row level security;
alter table public.order_items enable row level security;
create policy "Profiles readable by self or admins" on public.profiles for select to authenticated using (id = auth.uid() or exists (select 1 from public.profiles me where me.id = auth.uid() and me.role = 'admin'));
create policy "Users create own profile" on public.profiles for insert to authenticated with check (id = auth.uid() and role = 'customer');
create policy "Users update own profile" on public.profiles for update to authenticated using (id = auth.uid()) with check (id = auth.uid() and role = (select p.role from public.profiles p where p.id = auth.uid()));
create policy "Active stores are public" on public.stores for select to anon, authenticated using (is_active or owner_id = auth.uid());
create policy "Owners manage own stores" on public.stores for all to authenticated using (owner_id = auth.uid() or exists (select 1 from public.profiles p where p.id = auth.uid() and p.role = 'admin')) with check (owner_id = auth.uid() or exists (select 1 from public.profiles p where p.id = auth.uid() and p.role = 'admin'));
create policy "Available products are public" on public.products for select to anon, authenticated using (is_available and exists (select 1 from public.stores s where s.id = store_id and s.is_active));
create policy "Store owners manage products" on public.products for all to authenticated using (exists (select 1 from public.stores s where s.id = store_id and s.owner_id = auth.uid()) or exists (select 1 from public.profiles p where p.id = auth.uid() and p.role = 'admin')) with check (exists (select 1 from public.stores s where s.id = store_id and s.owner_id = auth.uid()) or exists (select 1 from public.profiles p where p.id = auth.uid() and p.role = 'admin'));
create policy "Relevant parties read orders" on public.orders for select to authenticated using (customer_id = auth.uid() or driver_id = auth.uid() or exists (select 1 from public.stores s where s.id = store_id and s.owner_id = auth.uid()) or exists (select 1 from public.profiles p where p.id = auth.uid() and p.role = 'admin'));
create policy "Customers create own orders" on public.orders for insert to authenticated with check (customer_id = auth.uid() and status = 'pending' and driver_id is null);
create policy "Assigned drivers update order status" on public.orders for update to authenticated using (driver_id = auth.uid() or exists (select 1 from public.stores s where s.id = store_id and s.owner_id = auth.uid()) or exists (select 1 from public.profiles p where p.id = auth.uid() and p.role = 'admin')) with check (driver_id = auth.uid() or exists (select 1 from public.stores s where s.id = store_id and s.owner_id = auth.uid()) or exists (select 1 from public.profiles p where p.id = auth.uid() and p.role = 'admin'));
create policy "Order items readable through parent order" on public.order_items for select to authenticated using (exists (select 1 from public.orders o where o.id = order_id and (o.customer_id = auth.uid() or o.driver_id = auth.uid() or exists (select 1 from public.stores s where s.id = o.store_id and s.owner_id = auth.uid()) or exists (select 1 from public.profiles p where p.id = auth.uid() and p.role = 'admin'))));
create policy "Customers add items to own pending orders" on public.order_items for insert to authenticated with check (exists (select 1 from public.orders o where o.id = order_id and o.customer_id = auth.uid() and o.status = 'pending'));
