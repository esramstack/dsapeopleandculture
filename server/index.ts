// Supabase Edge Function entry point for the DSA People & Culture portal.
import { createHandler } from "./handler.js";

const url = Deno.env.get("SUPABASE_URL")!;
const key = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const handle = createHandler({ url, key, publicUrl: url });

Deno.serve(handle);
