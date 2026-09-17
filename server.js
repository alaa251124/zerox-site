const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, 'data');
fs.mkdirSync(DATA_DIR, { recursive: true });
const DB_FILE = path.join(DATA_DIR, 'db.json');
const defaultDb = { users: [], orders: [], sessions: [], consultations: [] };
if (!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE, JSON.stringify(defaultDb, null, 2));

const courses = {
  basics: { title:'دورة الأساسيات', price:60, level:'مبتدئ → متوسط' },
  volume: { title:'الفوليوم العادي', price:160, level:'متوسط' },
  advanced: { title:'الفوليوم المطور', price:400, level:'متقدم / محترف' },
  modern: { title:'الفوليوم المطور الحديث', price:1000, level:'احترافي جدًا', locked:true }
};

function db(){ return JSON.parse(fs.readFileSync(DB_FILE,'utf8')); }
function save(d){ fs.writeFileSync(DB_FILE, JSON.stringify(d,null,2)); }
function id(){ return crypto.randomBytes(16).toString('hex'); }
function hash(password, salt=crypto.randomBytes(16).toString('hex')){ return {salt, hash:crypto.scryptSync(password,salt,64).toString('hex')}; }
function verify(password, salt, expected){
  const actual=crypto.scryptSync(password,salt,64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(actual,'hex'),Buffer.from(expected,'hex'));
}
function readBody(req, max=8*1024*1024){
  return new Promise((resolve,reject)=>{
    let b='';
    req.on('data',c=>{ b+=c; if(b.length>max){ req.destroy(); reject(new Error('PAYLOAD_TOO_LARGE')); }});
    req.on('end',()=>{ try{ resolve(b?JSON.parse(b):{}); }catch(e){ reject(e); } });
    req.on('error',reject);
  });
}
function headers(extra={}){ return { 'Content-Type':'application/json; charset=utf-8', 'Cache-Control':'no-store', ...extra }; }
function send(res,status,data,extra={}){ res.writeHead(status,headers(extra)); res.end(JSON.stringify(data)); }
function cookieToken(req){ const m=(req.headers.cookie||'').match(/(?:^|; )zx_session=([^;]+)/); return m?m[1]:null; }
function userFrom(req,d){ const token=cookieToken(req); if(!token)return null; const s=d.sessions.find(x=>x.token===token); return s?d.users.find(u=>u.id===s.userId)||null:null; }
function publicUser(user){ return user?{id:user.id,name:user.name,email:user.email,role:user.role,ownedCourses:user.ownedCourses||[],createdAt:user.createdAt}:null; }
function auth(res, req, d){ const user=userFrom(req,d); if(!user){send(res,401,{error:'سجل الدخول أولًا'});return null;} return user; }
function admin(res, req, d){ const user=auth(res,req,d); if(!user)return null; if(user.role!=='admin'){send(res,403,{error:'غير مصرح'});return null;} return user; }
function seedAdmin(){
  const email=process.env.ADMIN_EMAIL, password=process.env.ADMIN_PASSWORD;
  if(!email||!password)return;
  const d=db();
  let u=d.users.find(x=>x.email===email.toLowerCase());
  if(!u){ const h=hash(password); d.users.push({id:id(),name:'ZERO X Admin',email:email.toLowerCase(),salt:h.salt,passwordHash:h.hash,role:'admin',ownedCourses:[],createdAt:new Date().toISOString()}); save(d); console.log('Admin account created:',email); }
}
seedAdmin();

const server=http.createServer(async(req,res)=>{
  if(req.method==='OPTIONS'){res.writeHead(204,{'Access-Control-Allow-Origin':'*','Access-Control-Allow-Headers':'Content-Type','Access-Control-Allow-Methods':'GET,POST,PUT,OPTIONS'});return res.end();}
  const u=new URL(req.url,'http://localhost');
  try{
    const d=db();
    if(u.pathname==='/api/health') return send(res,200,{ok:true});
    if(u.pathname==='/api/courses') return send(res,200,courses);

    if(u.pathname==='/api/register'&&req.method==='POST'){
      const x=await readBody();
      if(!x.name||!x.email||!x.password||String(x.password).length<6)return send(res,400,{error:'أدخل الاسم والبريد وكلمة مرور من 6 أحرف على الأقل'});
      const email=String(x.email).trim().toLowerCase();
      if(d.users.some(v=>v.email===email))return send(res,409,{error:'البريد مستخدم مسبقًا'});
      const h=hash(String(x.password));
      const user={id:id(),name:String(x.name).trim(),email,salt:h.salt,passwordHash:h.hash,role:'student',ownedCourses:[],createdAt:new Date().toISOString()};
      d.users.push(user); const token=id(); d.sessions.push({token,userId:user.id,createdAt:Date.now()}); save(d);
      res.writeHead(201,headers({'Set-Cookie':`zx_session=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=2592000`}));
      return res.end(JSON.stringify({ok:true,user:publicUser(user)}));
    }

    if(u.pathname==='/api/login'&&req.method==='POST'){
      const x=await readBody(); const email=String(x.email||'').trim().toLowerCase(); const user=d.users.find(v=>v.email===email);
      if(!user||!verify(String(x.password||''),user.salt,user.passwordHash))return send(res,401,{error:'البريد أو كلمة المرور غير صحيحة'});
      const token=id(); d.sessions=d.sessions.filter(s=>s.userId!==user.id || Date.now()-s.createdAt<2592000000); d.sessions.push({token,userId:user.id,createdAt:Date.now()}); save(d);
      res.writeHead(200,headers({'Set-Cookie':`zx_session=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=2592000`}));
      return res.end(JSON.stringify({ok:true,user:publicUser(user)}));
    }

    if(u.pathname==='/api/logout'&&req.method==='POST'){
      const token=cookieToken(req); d.sessions=d.sessions.filter(s=>s.token!==token); save(d);
      return send(res,200,{ok:true},{'Set-Cookie':'zx_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0'});
    }

    if(u.pathname==='/api/me'){
      const user=userFrom(req,d); if(!user)return send(res,401,{error:'غير مسجل الدخول'});
      const orders=d.orders.filter(o=>o.userId===user.id).map(o=>({id:o.id,course:o.course,method:o.method,status:o.status,reference:o.reference,createdAt:o.createdAt}));
      return send(res,200,{user:publicUser(user),orders});
    }

    if(u.pathname==='/api/orders'&&req.method==='POST'){
      const user=auth(res,req,d); if(!user)return;
      const x=await readBody(); const c=courses[x.course];
      if(!c||c.locked)return send(res,400,{error:'الدورة غير متاحة'});
      if(user.ownedCourses.includes(x.course))return send(res,409,{error:'الدورة موجودة أصلًا في حسابك'});
      if(!['USDT TRC20','USDT BEP20','شام كاش'].includes(x.method))return send(res,400,{error:'طريقة الدفع غير صحيحة'});
      if(!x.reference)return send(res,400,{error:'أدخل رقم العملية أو المرجع'});
      if(x.proof && String(x.proof).length>7*1024*1024)return send(res,413,{error:'حجم إثبات الدفع كبير جدًا'});
      const pending=d.orders.find(o=>o.userId===user.id&&o.course===x.course&&o.status==='pending');
      if(pending)return send(res,409,{error:'لديك طلب دفع قيد المراجعة لهذه الدورة'});
      const order={id:id(),userId:user.id,course:x.course,method:x.method,reference:String(x.reference),proof:x.proof||'',status:'pending',createdAt:new Date().toISOString()};
      d.orders.push(order); save(d); return send(res,201,{ok:true,orderId:order.id,status:order.status});
    }

    if(u.pathname==='/api/consultations'&&req.method==='POST'){
      const user=auth(res,req,d); if(!user)return;
      const x=await readBody();
      if(!x.type||!x.problem)return send(res,400,{error:'اختر نوع الاستشارة واشرح المشكلة'});
      const consultation={id:id(),userId:user.id,name:user.name,email:user.email,type:String(x.type),problem:String(x.problem),status:'pending',createdAt:new Date().toISOString()};
      d.consultations.push(consultation); save(d); return send(res,201,{ok:true,id:consultation.id,status:'pending'});
    }

    if(u.pathname==='/api/admin/orders'&&req.method==='GET'){
      const user=admin(res,req,d); if(!user)return;
      return send(res,200,{orders:d.orders.map(o=>({...o,proof:o.proof?true:false,user:d.users.find(x=>x.id===o.userId)?.name||'—',email:d.users.find(x=>x.id===o.userId)?.email||'—',courseTitle:courses[o.course]?.title||o.course}))});
    }
    if(u.pathname==='/api/admin/orders/approve'&&req.method==='POST'){
      const user=admin(res,req,d); if(!user)return;
      const x=await readBody(); const order=d.orders.find(o=>o.id===x.orderId); if(!order)return send(res,404,{error:'الطلب غير موجود'});
      order.status='approved'; order.approvedAt=new Date().toISOString(); const student=d.users.find(v=>v.id===order.userId);
      if(student&&!student.ownedCourses.includes(order.course))student.ownedCourses.push(order.course); save(d); return send(res,200,{ok:true});
    }
    if(u.pathname==='/api/admin/orders/reject'&&req.method==='POST'){
      const user=admin(res,req,d); if(!user)return;
      const x=await readBody(); const order=d.orders.find(o=>o.id===x.orderId); if(!order)return send(res,404,{error:'الطلب غير موجود'});
      order.status='rejected'; order.rejectedAt=new Date().toISOString(); save(d); return send(res,200,{ok:true});
    }
    if(u.pathname==='/api/admin/consultations'&&req.method==='GET'){
      const user=admin(res,req,d); if(!user)return; return send(res,200,{consultations:d.consultations});
    }

    // Static files
    let file=u.pathname==='/'?'/index.html':u.pathname;
    file=path.normalize(file).replace(/^\.\.(\/|\\)/,'');
    const fp=path.join(ROOT,file);
    if(fp.startsWith(ROOT)&&fs.existsSync(fp)&&fs.statSync(fp).isFile()){
      const ext=path.extname(fp); const types={'.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'text/javascript; charset=utf-8','.png':'image/png','.jpg':'image/jpeg','.jpeg':'image/jpeg','.webp':'image/webp','.svg':'image/svg+xml','.txt':'text/plain; charset=utf-8'};
      res.writeHead(200,{'Content-Type':types[ext]||'application/octet-stream','Cache-Control':'no-cache'}); return fs.createReadStream(fp).pipe(res);
    }
    return send(res,404,{error:'Not found'});
  }catch(e){ console.error(e); if(!res.headersSent)send(res,e.message==='PAYLOAD_TOO_LARGE'?413:500,{error:e.message==='PAYLOAD_TOO_LARGE'?'حجم البيانات كبير جدًا':'حدث خطأ في الخادم'}); }
});
server.listen(process.env.PORT||3000,()=>console.log('ZERO X running on http://localhost:'+(process.env.PORT||3000)));
