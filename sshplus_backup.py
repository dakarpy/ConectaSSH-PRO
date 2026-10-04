#!/usr/bin/env python3
import json, os, re, secrets, subprocess, tarfile, tempfile, datetime as dt
from pathlib import Path
import urllib.request
BASE=Path('/opt/sshpanel'); ROOT=Path('/root')

def req(method,path,data=None,timeout=120):
    env={}
    for line in (BASE/'.env').read_text().splitlines():
        if '=' in line:
            k,v=line.split('=',1); env[k.strip()]=v.strip().strip('"')
    addr=env.get('ADMIN_HTTP_ADDR','127.0.0.1:9090').rsplit(':',1)[-1]
    url='http://127.0.0.1:'+addr+path
    body=None; headers={'Content-Type':'application/json','Authorization':'Bearer '+env.get('ADMIN_TOKEN','')}
    if data is not None: body=json.dumps(data).encode()
    r=urllib.request.Request(url,data=body,headers=headers,method=method)
    return json.loads(urllib.request.urlopen(r,timeout=timeout).read())

def hashpw(p):
    salt=secrets.token_urlsafe(10)[:12]
    return subprocess.check_output(['openssl','passwd','-6','-salt',salt,p],text=True).strip()

def expiry_days(x):
    if not x:return ''
    try:return str((dt.datetime.fromisoformat(x.replace('Z','+00:00')).date()-dt.date(1970,1,1)).days)
    except:return ''

def backup():
    users=req('GET','/api/users/backup',timeout=120).get('users',[])
    stamp=dt.datetime.now().strftime('%Y%m%d-%H%M%S'); out=ROOT/f'ConectaSSH-users-backup-{stamp}.vps'
    with tempfile.TemporaryDirectory() as td:
        t=Path(td); (t/'root').mkdir(); (t/'etc/SSHPlus/senha').mkdir(parents=True)
        files={n:(Path('/etc')/n).read_text(errors='replace').splitlines() for n in ['passwd','shadow','group','gshadow'] if (Path('/etc')/n).exists()}
        used=set()
        for l in files.get('passwd',[]):
            f=l.split(':')
            for i in (2,3):
                if len(f)>i and f[i].isdigit():used.add(int(f[i]))
        uid=max([1000]+list(used))+1; db=[]; valid=re.compile(r'^[A-Za-z0-9._-]{1,32}$')
        def merge(lines,u,v):
            found=False; outl=[]
            for l in lines:
                if l.startswith(u+':'):
                    if not found: outl.append(v); found=True
                else: outl.append(l)
            return outl if found else outl+[v]
        for u in users:
            name=str(u.get('username','')).strip(); pw=str(u.get('password',''))
            if not valid.fullmatch(name) or not pw:continue
            mc=max(1,int(u.get('max_connections') or 1)); db.append(f'{name} {mc}')
            old=next((l for l in files['passwd'] if l.startswith(name+':')),None)
            if old:
                f=old.split(':'); nuid=int(f[2]); ngid=int(f[3]); home=f[5] if len(f)>5 and f[5] else '/home/'+name; shell=f[6] if len(f)>6 and f[6] else '/bin/false'
            else:
                while uid in used:uid+=1
                nuid=ngid=uid; used.add(uid); uid+=1; home='/home/'+name; shell='/bin/false'
            files['passwd']=merge(files['passwd'],name,f'{name}:x:{nuid}:{ngid}::{home}:{shell}')
            files['group']=merge(files.get('group',[]),name,f'{name}:x:{ngid}:')
            files['gshadow']=merge(files.get('gshadow',[]),name,f'{name}:!::')
            d=expiry_days(u.get('expires_at')); day=(dt.date.today()-dt.date(1970,1,1)).days
            hp=hashpw(pw)
            sh=f'{name}:{hp}:{day}:0:99999:7::{d}:' if d else f'{name}:{hp}:{day}:0:99999:7:::'
            files['shadow']=merge(files['shadow'],name,sh); (t/'etc/SSHPlus/senha'/name).write_text(pw+'\n')
        (t/'root/usuarios.db').write_text('\n'.join(db)+'\n')
        for n in ['passwd','shadow','group','gshadow']:(t/'etc'/n).write_text('\n'.join(files.get(n,[]))+'\n')
        with tarfile.open(out,'w') as a:
            for p,arc in [(t/'root/usuarios.db','root/usuarios.db'),(t/'etc/passwd','etc/passwd'),(t/'etc/shadow','etc/shadow'),(t/'etc/group','etc/group'),(t/'etc/gshadow','etc/gshadow'),(t/'etc/SSHPlus','etc/SSHPlus')]:a.add(p,arcname=arc)
    os.chmod(out,0o600); print('BACKUP',out,'USERS',len(db))

def restore(path):
    with tarfile.open(path,'r:*') as a:
        def txt(n):
            try:
                f=a.extractfile(a.getmember(n)); return f.read().decode(errors='replace') if f else ''
            except KeyError:return ''
        db=txt('root/usuarios.db'); sh=txt('etc/shadow'); exp={}
        for l in sh.splitlines():
            f=l.split(':')
            if len(f)>=8 and f[7].isdigit():exp[f[0]]=(dt.datetime(1970,1,1,tzinfo=dt.timezone.utc)+dt.timedelta(days=int(f[7]))).isoformat().replace('+00:00','Z')
        users=[]
        for l in db.splitlines():
            f=l.split()
            if not f or not re.fullmatch(r'[A-Za-z0-9._-]{1,32}',f[0]):continue
            try:mc=max(1,int(f[1]))
            except:mc=1
            try:pw=txt('etc/SSHPlus/senha/'+f[0]).strip().splitlines()[0]
            except:continue
            users.append({'username':f[0],'password':pw,'max_connections':mc,'expires_at':exp.get(f[0],''),'use_pam':True})
    res=req('POST','/api/users/restore',{'version':1,'created_at':dt.datetime.now(dt.timezone.utc).isoformat(),'users':users},timeout=180); print('RESTORED',res)

if __name__=='__main__':
    import sys
    if len(sys.argv)>1 and sys.argv[1]=='restore':restore(Path(sys.argv[2]))
    else:backup()
