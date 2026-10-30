import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

function response(data: Record<string, unknown>, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      ...corsHeaders,
      "Content-Type": "application/json",
    },
  });
}

function getBearerToken(req: Request): string | null {
  const header = req.headers.get("Authorization");
  if (!header) return null;
  const match = header.match(/^Bearer\s+(.+)$/i);
  return match ? match[1] : null;
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  if (req.method !== "POST") {
    return response({ success: false, error: "Method not allowed" }, 405);
  }

  const supabaseUrl = Deno.env.get("SUPABASE_URL");
  const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  const anonKey = Deno.env.get("SUPABASE_ANON_KEY");

  if (!supabaseUrl || !serviceRoleKey || !anonKey) {
    return response({
      success: false,
      error: "Supabase environment variables are not configured",
    }, 500);
  }

  const token = getBearerToken(req);
  if (!token) {
    return response({ success: false, error: "Missing authorization token" }, 401);
  }

  const userClient = createClient(supabaseUrl, anonKey, {
    global: { headers: { Authorization: `Bearer ${token}` } },
    auth: {
      persistSession: false,
      autoRefreshToken: false,
      detectSessionInUrl: false,
    },
  });

  const adminClient = createClient(supabaseUrl, serviceRoleKey, {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
      detectSessionInUrl: false,
    },
  });

  const {
    data: { user: caller },
    error: callerError,
  } = await userClient.auth.getUser(token);

  if (callerError || !caller) {
    return response({ success: false, error: "Unauthorized" }, 401);
  }

  const { data: callerProfile, error: callerProfileError } = await adminClient
    .from("profiles")
    .select("id,role,is_active")
    .eq("id", caller.id)
    .maybeSingle();

  if (callerProfileError) {
    return response({
      success: false,
      error: "تعذر التحقق من صلاحيات المدير",
    }, 500);
  }

  if (
    !callerProfile ||
    callerProfile.role !== "admin" ||
    callerProfile.is_active !== true
  ) {
    return response({
      success: false,
      error: "غير مصرح. يجب أن يكون الحساب مديرًا نشطًا",
    }, 403);
  }

  let body: {
    name?: string;
    username?: string;
    email?: string;
    password?: string;
  };

  try {
    body = await req.json();
  } catch {
    return response({ success: false, error: "Invalid JSON request" }, 400);
  }

  const name = String(body.name || "").trim();
  const username = String(body.username || "").trim().toLowerCase();
  const email = String(body.email || "").trim().toLowerCase();
  const password = String(body.password || "");

  if (!name || !username || !email || !password) {
    return response({
      success: false,
      error: "الاسم واسم المستخدم والبريد الإلكتروني وكلمة المرور مطلوبة",
    }, 400);
  }

  if (!/^[a-z0-9_.-]{2,50}$/.test(username)) {
    return response({
      success: false,
      error: "اسم المستخدم غير صالح",
    }, 400);
  }

  if (password.length < 6) {
    return response({
      success: false,
      error: "كلمة المرور يجب ألا تقل عن 6 أحرف",
    }, 400);
  }

  const { data: existingUsername, error: usernameError } = await adminClient
    .from("profiles")
    .select("id")
    .eq("username", username)
    .maybeSingle();

  if (usernameError) {
    return response({
      success: false,
      error: "تعذر التحقق من اسم المستخدم",
    }, 500);
  }

  if (existingUsername) {
    return response({
      success: false,
      error: "اسم المستخدم مستخدم بالفعل. اختر اسم مستخدم آخر.",
    }, 409);
  }

  let createdUserId = "";

  try {
    const { data: created, error: createError } =
      await adminClient.auth.admin.createUser({
        email,
        password,
        email_confirm: true,
        user_metadata: {
          name,
          username,
          role: "admin",
        },
      });

    if (createError) throw createError;
    if (!created.user) throw new Error("تعذر إنشاء حساب المدير في Supabase Auth");

    createdUserId = created.user.id;

    const { data: profile, error: profileError } = await adminClient
      .from("profiles")
      .upsert({
        id: createdUserId,
        name,
        username,
        email,
        role: "admin",
        is_active: true,
        updated_at: new Date().toISOString(),
      }, { onConflict: "id" })
      .select("id,name,username,email,role,is_active,created_at")
      .single();

    if (profileError) throw profileError;

    return response({
      success: true,
      user: profile,
    });
  } catch (error) {
    if (createdUserId) {
      try {
        await adminClient.auth.admin.deleteUser(createdUserId);
      } catch (rollbackError) {
        console.error("Admin user rollback failed:", rollbackError);
      }
    }

    console.error("admin-create-user error:", error);
    return response({
      success: false,
      error: String(error?.message || "تعذر إنشاء حساب المدير"),
    }, 400);
  }
});
