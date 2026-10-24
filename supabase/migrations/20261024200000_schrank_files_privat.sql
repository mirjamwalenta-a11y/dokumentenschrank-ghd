-- Dokumentenschrank: Dateien im Speicher „schrank-files“ nicht mehr öffentlich.
--
-- Vorher war der Bucket öffentlich: Wer die Adresse einer Datei kannte
-- (…/storage/v1/object/public/schrank-files/…), konnte sie ohne Anmeldung
-- öffnen. Die App öffnet Dateien jetzt über signierte, kurz gültige Links
-- (POST /storage/v1/object/sign/…), das braucht eine SELECT-Policy.
--
-- Dateien liegen unter <user_id>/<kategorie>/<datei>. Jede Person darf nur
-- ihren eigenen Ordner lesen, hochladen, ändern und löschen.
--
-- Einmal im Supabase-SQL-Editor ausführen. Keine GRANTs nötig: storage.objects
-- ist keine neue Tabelle in public, die Rechte dort verwaltet Supabase.

-- 1. Bucket privat machen
update storage.buckets set public = false where id = 'schrank-files';

-- 2. Erlaubt: eigener Ordner (für angemeldete Personen)
drop policy if exists "schrank-files: eigene lesen" on storage.objects;
create policy "schrank-files: eigene lesen" on storage.objects
  for select to authenticated
  using (bucket_id = 'schrank-files' and (storage.foldername(name))[1] = auth.uid()::text);

drop policy if exists "schrank-files: eigene hochladen" on storage.objects;
create policy "schrank-files: eigene hochladen" on storage.objects
  for insert to authenticated
  with check (bucket_id = 'schrank-files' and (storage.foldername(name))[1] = auth.uid()::text);

drop policy if exists "schrank-files: eigene ändern" on storage.objects;
create policy "schrank-files: eigene ändern" on storage.objects
  for update to authenticated
  using (bucket_id = 'schrank-files' and (storage.foldername(name))[1] = auth.uid()::text)
  with check (bucket_id = 'schrank-files' and (storage.foldername(name))[1] = auth.uid()::text);

drop policy if exists "schrank-files: eigene löschen" on storage.objects;
create policy "schrank-files: eigene löschen" on storage.objects
  for delete to authenticated
  using (bucket_id = 'schrank-files' and (storage.foldername(name))[1] = auth.uid()::text);

-- 3. Sicherheitsnetz: RESTRICTIVE wird mit allen anderen Policies UND-verknüpft.
--    Auch falls es noch ältere, weiter gefasste Policies für diesen Bucket gibt,
--    kommt niemand an fremde Ordner und ohne Anmeldung (auth.uid() = null) gar nicht.
--    Andere Buckets bleiben unberührt (bucket_id <> 'schrank-files' → true).
drop policy if exists "schrank-files: nur eigener Ordner" on storage.objects;
create policy "schrank-files: nur eigener Ordner" on storage.objects
  as restrictive for all to public
  using (bucket_id <> 'schrank-files' or (storage.foldername(name))[1] = auth.uid()::text)
  with check (bucket_id <> 'schrank-files' or (storage.foldername(name))[1] = auth.uid()::text);

-- 4. Kontrolle: Muss „false“ und 0 zeigen. Dateien außerhalb eines
--    Personen-Ordners wären nach dieser Änderung für niemanden mehr lesbar.
select
  (select public from storage.buckets where id = 'schrank-files') as bucket_oeffentlich,
  (select count(*) from storage.objects o
    where o.bucket_id = 'schrank-files'
      and not exists (select 1 from auth.users u where u.id::text = (storage.foldername(o.name))[1])) as dateien_ohne_personenordner;
