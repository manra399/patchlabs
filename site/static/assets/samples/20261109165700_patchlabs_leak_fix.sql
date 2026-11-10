-- Fix: Replace overly permissive "everyone can read" policy with owner-only access
-- The original policy "Profiles are viewable by everyone" allowed anonymous and any signed-in user
-- to read all columns (email, phone) from all profile rows.
-- Change: Only allow users to read their own profile (where user_id = auth.uid())

DROP POLICY "Profiles are viewable by everyone" ON public.profiles;
CREATE POLICY "Users can view own profile" ON public.profiles FOR SELECT USING (auth.uid() = user_id);
