const SUPABASE_URL = "YOUR_SUPABASE_URL";
const SUPABASE_ANON_KEY = "YOUR_SUPABASE_ANON_KEY";
const db = (!SUPABASE_URL.startsWith("YOUR_") && !SUPABASE_ANON_KEY.startsWith("YOUR_"))
  ? supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY) : null;

const $=id=>document.getElementById(id);
const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const show=(el,t,ok=false)=>el.innerHTML=`<div class="${ok?'success':'error'}">${esc(t)}</div>`;

async function requireDb(){
  if(!db) throw new Error("Add your Supabase URL and publishable/anon key to app.js.");
}

/* Users submit a report without exposing the reports table for arbitrary SELECTs.
   The SQL migration creates an RPC function that creates a report and returns only
   the generated reference. The user's authenticated identity is attached server-side. */
$("reportForm").addEventListener("submit",async e=>{
  e.preventDefault(); const out=$("reportResult");
  try{
    await requireDb();
    const {data:{user}}=await db.auth.getUser();
    if(!user){ show(out,"Please sign in with your email before submitting a report."); return; }
    const f=new FormData(e.target);
    const payload={
      p_name:f.get("name"),p_phone:f.get("phone"),p_email:user.email,
      p_scam_type:f.get("scam_type"),p_scammer_name:f.get("scammer_name"),
      p_scammer_phone:f.get("scammer_phone"),p_scammer_email:f.get("scammer_email"),
      p_website:f.get("website"),p_amount:f.get("amount")?Number(f.get("amount")):null,
      p_currency:f.get("currency"),p_incident_date:f.get("incident_date")||null,
      p_description:f.get("description")
    };
    const {data,error}=await db.rpc("create_report_secure",payload);
    if(error)throw error;
    show(out,`Report submitted. Reference number: ${data}`,true);
    e.target.reset();
  }catch(err){show(out,err.message||"Unable to submit report.");}
});

/* User lookup: the RPC checks auth.uid() and returns only the authenticated user's
   own report. The browser cannot request arbitrary reports. */
$("lookupForm").addEventListener("submit",async e=>{
  e.preventDefault(); const out=$("lookupResult");
  try{
    await requireDb();
    const {data:{user}}=await db.auth.getUser();
    if(!user){show(out,"Please sign in first.");return}
    const f=new FormData(e.target);
    const {data,error}=await db.rpc("get_my_report_secure",{p_reference:f.get("reference")});
    if(error)throw error;
    if(!data?.length){show(out,"Report not found or it does not belong to your account.");return}
    const r=data[0];
    out.innerHTML=`<div class="report"><h3>${esc(r.reference_number)} <span class="status">${esc(r.status)}</span></h3>
      <p><b>Type:</b> ${esc(r.scam_type)}</p>
      <p><b>Submitted:</b> ${new Date(r.created_at).toLocaleString()}</p>
      <p><b>Last updated:</b> ${new Date(r.updated_at).toLocaleString()}</p>
      <h3>Administrator response</h3><p>${esc(r.admin_response||"No response yet.")}</p>
      <div class="chat"><h3>Private messages</h3><div id="userMessages">Loading...</div>
      <div class="reply"><input id="userMessage" placeholder="Write a message"><button class="btn primary" onclick="sendUserMessage('${esc(r.reference_number)}')">Send</button></div></div></div>`;
    await loadUserMessages(r.reference_number);
  }catch(err){show(out,err.message||"Unable to retrieve report.");}
});

async function loadUserMessages(reference){
 const box=$("userMessages"); if(!box)return;
 const {data,error}=await db.rpc("get_my_messages_secure",{p_reference:reference});
 if(error){box.textContent="Messages unavailable.";return}
 box.innerHTML=(data||[]).map(m=>`<div class="msg ${m.sender_type==="admin"?"admin":""}"><b>${m.sender_type==="admin"?"Admin":"You"}:</b> ${esc(m.message)} <small>${new Date(m.created_at).toLocaleString()}</small></div>`).join("")||"<p>No messages yet.</p>";
}
window.sendUserMessage=async reference=>{
 const input=$("userMessage"); if(!input.value.trim())return;
 const {error}=await db.rpc("send_my_message_secure",{p_reference:reference,p_message:input.value.trim()});
 if(error){alert(error.message);return}
 input.value=""; await loadUserMessages(reference);
};

/* Email OTP/magic-link sign-in. No password is stored in this frontend. */
async function signInUser(){
  await requireDb();
  const email=prompt("Enter the email address used for your report:");
  if(!email)return;
  const {error}=await db.auth.signInWithOtp({email,options:{emailRedirectTo:location.origin+location.pathname}});
  if(error)alert(error.message);else alert("Check your email for the secure sign-in link/code.");
}

/* Admin uses Supabase Auth. The database RLS identifies authorized admin users
   from the admin_users table; frontend never contains an admin password. */
$("loginForm").addEventListener("submit",async e=>{
 e.preventDefault(); const f=new FormData(e.target),out=$("loginMsg");
 try{
  await requireDb();
  const {error}=await db.auth.signInWithPassword({email:f.get("email"),password:f.get("password")});
  if(error)throw error;
  const {data}=await db.rpc("is_admin_secure");
  if(!data){await db.auth.signOut();throw new Error("This account is not authorized as an administrator.");}
  show(out,"Administrator login successful.",true); $("loginForm").hidden=true;$("adminArea").hidden=false;await loadAdmin();
 }catch(err){show(out,"Login failed: "+(err.message||""))}
});
$("logout").addEventListener("click",async()=>{await db.auth.signOut();location.reload()});

async function loadAdmin(){
 const {data,error}=await db.rpc("admin_list_reports_secure");
 if(error){$("reports").textContent=error.message;return}
 const stats={Submitted:0,"Under Review":0,"More Information Needed":0,"Confirmed Scam":0,"Not Confirmed":0,Resolved:0,Closed:0};
 (data||[]).forEach(r=>stats[r.status]=(stats[r.status]||0)+1);
 $("stats").innerHTML=Object.entries(stats).slice(0,4).map(([k,v])=>`<div class="stat"><strong>${v}</strong>${esc(k)}</div>`).join("");
 $("reports").innerHTML=(data||[]).map(r=>`<div class="report"><h3>${esc(r.reference_number)} <span class="status">${esc(r.status)}</span></h3>
 <p><b>${esc(r.name)}</b> • ${esc(r.email)} • ${esc(r.phone)}</p><p>${esc(r.scam_type)} — ${esc(r.description).slice(0,300)}</p>
 <div class="report-actions">${["Under Review","More Information Needed","Confirmed Scam","Not Confirmed","Resolved","Closed"].map(s=>`<button class="btn" onclick="updateStatus('${r.id}','${s.replace(/'/g,"\\'")}')">${esc(s)}</button>`).join("")}</div>
 <label>Admin response<textarea id="resp-${r.id}">${esc(r.admin_response||"")}</textarea></label>
 <button class="btn primary" onclick="saveResponse('${r.id}')">Save response</button>
 <div class="chat"><b>Messages</b><div id="chat-${r.id}">Loading...</div>
 <div class="reply"><input id="reply-${r.id}" placeholder="Reply to complainant"><button class="btn" onclick="adminReply('${r.reference_number}','${r.id}')">Send</button></div></div></div>`).join("");
 for(const r of (data||[]))await loadAdminMessages(r);
}
window.updateStatus=async(id,status)=>{
 const {error}=await db.rpc("admin_update_report_secure",{p_id:id,p_status:status});
 if(error)alert(error.message);else loadAdmin();
}
window.saveResponse=async id=>{
 const response=$(`resp-${id}`).value;
 const {error}=await db.rpc("admin_update_response_secure",{p_id:id,p_response:response});
 if(error)alert(error.message);else alert("Response saved.");
}
async function loadAdminMessages(r){
 const box=$(`chat-${r.id}`);if(!box)return;
 const {data,error}=await db.rpc("admin_get_messages_secure",{p_reference:r.reference_number});
 if(error){box.textContent=error.message;return}
 box.innerHTML=(data||[]).map(m=>`<div class="msg ${m.sender_type==="admin"?"admin":""}"><b>${m.sender_type==="admin"?"Admin":"User"}:</b> ${esc(m.message)}</div>`).join("")||"<p>No messages.</p>";
}
window.adminReply=async(reference,id)=>{
 const input=$(`reply-${id}`);if(!input.value.trim())return;
 const {error}=await db.rpc("admin_send_message_secure",{p_reference:reference,p_message:input.value.trim()});
 if(error)alert(error.message);else{input.value="";await loadAdminMessages({reference_number:reference,id})}
}

/* Add a small sign-in control if desired. */
document.addEventListener("DOMContentLoaded",()=>{
 const form=$("reportForm");
 if(form){
  const b=document.createElement("button");b.type="button";b.className="btn";b.textContent="Secure email sign-in";
  b.onclick=signInUser;b.classList.add("secure-signin");form.insertBefore(b,form.firstChild);
 }
});
(async()=>{
 if(!db)return;
 const {data:{session}}=await db.auth.getSession();
 if(session){
   const {data:isAdmin}=await db.rpc("is_admin_secure");
   if(isAdmin){$("loginForm").hidden=true;$("adminArea").hidden=false;await loadAdmin()}
 }
})();