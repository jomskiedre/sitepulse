import os, secrets
from datetime import datetime, timedelta
from urllib.parse import urlencode
import requests
from flask import Flask, request, jsonify, render_template, redirect, session, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app=Flask(__name__)
app.config["SECRET_KEY"]=os.environ.get("SECRET_KEY","change-me-in-production")
app.config["SQLALCHEMY_DATABASE_URI"]=os.environ.get("DATABASE_URL","sqlite:///sitepulse.db").replace("postgres://","postgresql://")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"]=False
db=SQLAlchemy(app)

class User(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    email=db.Column(db.String(255),unique=True,nullable=False)
    password_hash=db.Column(db.String(255),nullable=False)
    role=db.Column(db.String(30),default="admin")
    created_at=db.Column(db.DateTime,default=datetime.utcnow)

class Site(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    owner_id=db.Column(db.Integer,db.ForeignKey("user.id"),nullable=False)
    name=db.Column(db.String(200),nullable=False)
    url=db.Column(db.String(500),nullable=False)
    api_key=db.Column(db.String(100),unique=True,nullable=False)
    created_at=db.Column(db.DateTime,default=datetime.utcnow)

class Event(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    site_id=db.Column(db.Integer,db.ForeignKey("site.id"),nullable=False,index=True)
    event_type=db.Column(db.String(30),default="pageview",index=True)
    page=db.Column(db.String(1000)); element=db.Column(db.String(500)); referrer=db.Column(db.String(1000))
    source=db.Column(db.String(200)); medium=db.Column(db.String(200)); campaign=db.Column(db.String(200))
    visitor_id=db.Column(db.String(100),index=True); created_at=db.Column(db.DateTime,default=datetime.utcnow,index=True)

class Keyword(db.Model):
    id=db.Column(db.Integer,primary_key=True); site_id=db.Column(db.Integer,db.ForeignKey("site.id"),nullable=False,index=True)
    query=db.Column(db.String(500),nullable=False); clicks=db.Column(db.Integer,default=0); impressions=db.Column(db.Integer,default=0)
    ctr=db.Column(db.Float,default=0); position=db.Column(db.Float,default=0)

class GoogleConnection(db.Model):
    id=db.Column(db.Integer,primary_key=True); user_id=db.Column(db.Integer,db.ForeignKey("user.id"),nullable=False)
    site_id=db.Column(db.Integer,db.ForeignKey("site.id"),nullable=False); access_token=db.Column(db.Text,nullable=False)
    refresh_token=db.Column(db.Text); expires_at=db.Column(db.DateTime); property_url=db.Column(db.String(1000),nullable=False)
    created_at=db.Column(db.DateTime,default=datetime.utcnow)

def current_user():
    uid=session.get("uid")
    return User.query.get(uid) if uid else None

def require_user():
    u=current_user()
    if not u: abort(401)
    return u

def site_for_user(site_id):
    s=Site.query.filter_by(id=site_id,owner_id=require_user().id).first()
    if not s: abort(404)
    return s

GSC_CLIENT_ID=os.environ.get("GOOGLE_CLIENT_ID"); GSC_CLIENT_SECRET=os.environ.get("GOOGLE_CLIENT_SECRET"); GSC_REDIRECT_URI=os.environ.get("GOOGLE_REDIRECT_URI")
GSC_SCOPE="https://www.googleapis.com/auth/webmasters.readonly"
def gsc_ready(): return bool(GSC_CLIENT_ID and GSC_CLIENT_SECRET and GSC_REDIRECT_URI)

def refresh_gsc(conn):
    if conn.expires_at and conn.expires_at>datetime.utcnow()+timedelta(minutes=2): return conn.access_token
    if not conn.refresh_token: return None
    r=requests.post("https://oauth2.googleapis.com/token",data={"client_id":GSC_CLIENT_ID,"client_secret":GSC_CLIENT_SECRET,"refresh_token":conn.refresh_token,"grant_type":"refresh_token"},timeout=20)
    if not r.ok:return None
    d=r.json(); conn.access_token=d["access_token"]; conn.expires_at=datetime.utcnow()+timedelta(seconds=int(d.get("expires_in",3600))); db.session.commit(); return conn.access_token

def gsc_query(conn,start_date,end_date):
    token=refresh_gsc(conn)
    if not token:return []
    url="https://searchconsole.googleapis.com/webmasters/v3/sites/%s/searchAnalytics/query"%requests.utils.quote(conn.property_url,safe="")
    r=requests.post(url,headers={"Authorization":"Bearer "+token,"Content-Type":"application/json"},json={"startDate":start_date,"endDate":end_date,"dimensions":["query"],"rowLimit":25000},timeout=30)
    return r.json().get("rows",[]) if r.ok else []

@app.route("/")
def index(): return render_template("index.html",user=current_user())

@app.route("/login",methods=["GET","POST"])
def login():
    if request.method=="POST":
        u=User.query.filter_by(email=request.form.get("email","").strip().lower()).first()
        if u and check_password_hash(u.password_hash,request.form.get("password","")):
            session["uid"]=u.id; return redirect("/dashboard")
        return render_template("login.html",error="Email or password is incorrect.")
    return render_template("login.html",error=None)

@app.route("/signup",methods=["GET","POST"])
def signup():
    if current_user(): return redirect("/dashboard")
    if request.method=="POST":
        email=request.form.get("email","").strip().lower(); pw=request.form.get("password","")
        if len(pw)<8:return render_template("signup.html",error="Use at least 8 characters.")
        if User.query.filter_by(email=email).first():return render_template("login.html",error="You already have an account. Please log in instead.")
        u=User(email=email,password_hash=generate_password_hash(pw)); db.session.add(u); db.session.commit(); session["uid"]=u.id
        return redirect("/dashboard")
    return render_template("signup.html",error=None)

@app.route("/logout")
def logout(): session.clear(); return redirect("/")
@app.route("/dashboard")
def dashboard(): return render_template("dashboard.html",user=require_user())

@app.route("/api/sites",methods=["GET","POST"])
def api_sites():
    u=require_user()
    if request.method=="GET": return jsonify(sites=[{"id":s.id,"name":s.name,"url":s.url} for s in Site.query.filter_by(owner_id=u.id).order_by(Site.id.desc()).all()])
    d=request.json or {}; name=(d.get("name") or "").strip(); url=(d.get("url") or "").strip()
    if not name or not url:return jsonify(error="Website name and URL are required"),400
    if not url.startswith(("http://","https://")):url="https://"+url
    if Site.query.filter_by(owner_id=u.id,url=url).first():return jsonify(error="This website is already in your account."),409
    s=Site(owner_id=u.id,name=name,url=url,api_key=secrets.token_urlsafe(32)); db.session.add(s); db.session.commit(); return jsonify(id=s.id,name=s.name,url=s.url,api_key=s.api_key)

@app.route("/api/sites/<int:site_id>",methods=["DELETE"])
def delete_site(site_id):
    s=site_for_user(site_id)
    GoogleConnection.query.filter_by(user_id=current_user().id,site_id=s.id).delete()
    Keyword.query.filter_by(site_id=s.id).delete()
    Event.query.filter_by(site_id=s.id).delete()
    db.session.delete(s); db.session.commit(); return jsonify(ok=True)

@app.route("/api/sites/<int:site_id>/stats")
def stats(site_id):
    s=site_for_user(site_id); since=datetime.utcnow()-timedelta(days=int(request.args.get("days",30))); q=Event.query.filter(Event.site_id==s.id,Event.created_at>=since)
    views=q.filter_by(event_type="pageview").count(); clicks=q.filter_by(event_type="click").count(); visitors=len({e.visitor_id for e in q.with_entities(Event.visitor_id).all() if e.visitor_id}); pages={}; elements={}; daily={}
    for e in q.all():
        if e.event_type=="pageview":pages[e.page or "/"]=pages.get(e.page or "/",0)+1
        if e.event_type=="click":elements[e.element or "Unknown"]=elements.get(e.element or "Unknown",0)+1
        day=e.created_at.strftime("%Y-%m-%d"); daily[day]=daily.get(day,0)+1
    keys=Keyword.query.filter_by(site_id=s.id).order_by(Keyword.clicks.desc()).limit(25).all(); con=GoogleConnection.query.filter_by(user_id=current_user().id,site_id=s.id).first()
    return jsonify(site={"id":s.id,"name":s.name,"url":s.url},visitors=visitors,views=views,clicks=clicks,gsc_connected=bool(con),top_pages=sorted([{"name":k,"value":v} for k,v in pages.items()],key=lambda x:x["value"],reverse=True)[:10],top_clicks=sorted([{"name":k,"value":v} for k,v in elements.items()],key=lambda x:x["value"],reverse=True)[:10],daily=sorted([{"date":k,"value":v} for k,v in daily.items()]),keywords=[{"query":k.query,"clicks":k.clicks,"impressions":k.impressions,"ctr":k.ctr,"position":k.position} for k in keys])

@app.route("/api/sites/<int:site_id>/script")
def script(site_id):
    s=site_for_user(site_id); api=request.host_url.rstrip("/")+"/track"
    code='''<script>(function(){const API=%r,KEY=%r;let vid=localStorage.getItem("sp_vid");if(!vid){vid=crypto.randomUUID();localStorage.setItem("sp_vid",vid)}function send(type,el){const p=new URLSearchParams(location.search);fetch(API,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({api_key:KEY,event_type:type,page:location.href,element:el||"",referrer:document.referrer,source:p.get("utm_source")||"",medium:p.get("utm_medium")||"",campaign:p.get("utm_campaign")||"",visitor_id:vid})}).catch(()=>{})}send("pageview");document.addEventListener("click",e=>{const el=e.target.closest("a,button,[data-analytics]");if(el)send("click",el.getAttribute("data-analytics")||el.innerText||el.getAttribute("href")||el.tagName)})})();</script>'''%(api,s.api_key)
    return code,200,{"Content-Type":"text/plain"}

@app.route("/track",methods=["POST","OPTIONS"])
def track():
    if request.method=="OPTIONS":return ("",204,{"Access-Control-Allow-Origin":"*","Access-Control-Allow-Headers":"Content-Type"})
    d=request.json or {}; s=Site.query.filter_by(api_key=d.get("api_key")).first()
    if not s:return jsonify(error="Invalid API key"),403
    e=Event(site_id=s.id,event_type=d.get("event_type","pageview"),page=d.get("page"),element=d.get("element"),referrer=d.get("referrer"),source=d.get("source"),medium=d.get("medium"),campaign=d.get("campaign"),visitor_id=d.get("visitor_id")); db.session.add(e); db.session.commit(); return jsonify(ok=True),200,{"Access-Control-Allow-Origin":"*"}

@app.route("/api/gsc/status")
def gsc_status():
    u=require_user(); con=GoogleConnection.query.filter_by(user_id=u.id).all(); return jsonify(ready=gsc_ready(),connections=[{"site_id":c.site_id,"property_url":c.property_url} for c in con])

@app.route("/gsc/connect/<int:site_id>")
def gsc_connect(site_id):
    site_for_user(site_id)
    if not gsc_ready():return "Google Search Console OAuth is not configured yet. Add GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET and GOOGLE_REDIRECT_URI.",503
    state=secrets.token_urlsafe(24); session["gsc_state"]=state; session["gsc_site_id"]=site_id; params={"client_id":GSC_CLIENT_ID,"redirect_uri":GSC_REDIRECT_URI,"response_type":"code","scope":GSC_SCOPE,"access_type":"offline","prompt":"consent","state":state}; return redirect("https://accounts.google.com/o/oauth2/v2/auth?"+urlencode(params))

@app.route("/gsc/callback")
def gsc_callback():
    require_user()
    if request.args.get("state")!=session.get("gsc_state"):return "Invalid OAuth state.",400
    code=request.args.get("code"); site_id=session.get("gsc_site_id")
    if not code or not site_id:return "Missing authorization data.",400
    r=requests.post("https://oauth2.googleapis.com/token",data={"code":code,"client_id":GSC_CLIENT_ID,"client_secret":GSC_CLIENT_SECRET,"redirect_uri":GSC_REDIRECT_URI,"grant_type":"authorization_code"},timeout=20)
    if not r.ok:return "Google authorization failed: "+r.text,400
    d=r.json(); token=d.get("access_token")
    if not token:return "Google did not return an access token.",400
    rr=requests.get("https://www.googleapis.com/webmasters/v3/sites",headers={"Authorization":"Bearer "+token},timeout=20)
    if not rr.ok:return "Could not read Search Console properties.",400
    props=rr.json().get("siteEntry",[]); session["gsc_access_token"]=token; session["gsc_refresh_token"]=d.get("refresh_token"); session["gsc_props"]=[p.get("siteUrl") for p in props]; return render_template("gsc_select.html",site=Site.query.get_or_404(site_id),properties=session["gsc_props"])

@app.route("/gsc/save",methods=["POST"])
def gsc_save():
    u=require_user(); site_id=int(request.form["site_id"]); site_for_user(site_id); prop=request.form["property"]; token=session.get("gsc_access_token")
    if not token or prop not in session.get("gsc_props",[]):return "Invalid Google session.",400
    con=GoogleConnection.query.filter_by(user_id=u.id,site_id=site_id).first()
    if not con:db.session.add(GoogleConnection(user_id=u.id,site_id=site_id,property_url=prop,access_token=token,refresh_token=session.get("gsc_refresh_token"),expires_at=datetime.utcnow()+timedelta(hours=1)))
    else:con.property_url=prop; con.access_token=token; con.refresh_token=session.get("gsc_refresh_token") or con.refresh_token; con.expires_at=datetime.utcnow()+timedelta(hours=1)
    db.session.commit(); session.pop("gsc_access_token",None); session.pop("gsc_refresh_token",None); session.pop("gsc_props",None); return redirect("/dashboard")

@app.route("/api/gsc/sync/<int:site_id>",methods=["POST"])
def gsc_sync(site_id):
    site_for_user(site_id); con=GoogleConnection.query.filter_by(user_id=current_user().id,site_id=site_id).first()
    if not con:return jsonify(error="Connect Google Search Console first."),400
    end=datetime.utcnow().date()-timedelta(days=2); start=end-timedelta(days=28); rows=gsc_query(con,start.isoformat(),end.isoformat()); Keyword.query.filter_by(site_id=site_id).delete()
    for row in rows:db.session.add(Keyword(site_id=site_id,query=row.get("keys",[""])[0],clicks=int(row.get("clicks",0)),impressions=int(row.get("impressions",0)),ctr=float(row.get("ctr",0))*100,position=float(row.get("position",0))))
    db.session.commit(); return jsonify(synced=len(rows),period={"start":start.isoformat(),"end":end.isoformat()})

with app.app_context():
    db.create_all(); admin_email=os.environ.get("ADMIN_EMAIL"); admin_pw=os.environ.get("ADMIN_PASSWORD")
    if admin_email and admin_pw and not User.query.filter_by(email=admin_email.lower()).first():db.session.add(User(email=admin_email.lower(),password_hash=generate_password_hash(admin_pw),role="admin")); db.session.commit()

if __name__=="__main__":app.run(host="0.0.0.0",port=int(os.environ.get("PORT",5000)))
