// Edge Function: invite-customer
// Lets an admin invite a customer's login from inside the app, instead of
// doing it manually in Supabase. Runs server-side so the powerful
// service_role key never touches the browser.
//
// Setup: Supabase Dashboard > Edge Functions > Deploy a new function > Via Editor
// Name it: invite-customer
// Paste this whole file in as the function code, then click Deploy.
// No extra secrets to set up — SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY
// are provided automatically to every Edge Function.

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const { email, customer_id } = await req.json();
    if (!email || !customer_id) {
      return jsonResponse({ error: "email and customer_id are required" }, 400);
    }

    const authHeader = req.headers.get("Authorization") || "";
    const token = authHeader.replace("Bearer ", "");
    if (!token) return jsonResponse({ error: "Not signed in." }, 401);

    const admin = createClient(
      Deno.env.get("SUPABASE_URL"),
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")
    );

    // Confirm whoever is calling this is actually signed in...
    const { data: { user }, error: userErr } = await admin.auth.getUser(token);
    if (userErr || !user) return jsonResponse({ error: "Not signed in." }, 401);

    // ...and that they're a shop admin, not a customer trying to invite themselves access.
    const { data: callerProfile } = await admin
      .from("profiles").select("role").eq("id", user.id).single();
    if (callerProfile?.role !== "admin") {
      return jsonResponse({ error: "Admins only." }, 403);
    }

    // Send the invite email (uses whatever Site URL is set in Auth > URL Configuration)
    const { data: invited, error: inviteErr } = await admin.auth.admin.inviteUserByEmail(email);
    if (inviteErr) return jsonResponse({ error: inviteErr.message }, 400);

    // Link the brand new login straight to the chosen customer record —
    // no manual profiles-table step needed afterward.
    const { error: linkErr } = await admin
      .from("profiles").update({ customer_id }).eq("id", invited.user.id);
    if (linkErr) {
      return jsonResponse({ error: `Invited, but linking to the customer failed: ${linkErr.message}` }, 200);
    }

    return jsonResponse({ success: true });
  } catch (e) {
    return jsonResponse({ error: String(e) }, 500);
  }
});
