"""
Passive URL triage ("gf patterns", built in).

Looks only at the *shape* of a URL -- path segments, parameter names and
values -- and tags it with the vulnerability classes that shape is
classically associated with. No request is made and nothing is sent, so it
costs nothing and is safe to run on every result.

A tag is a reason to look, not a finding: `?id=42` is an IDOR/SQLi
*candidate*, nothing more. Tags feed the fused score with a small, capped
weight so they help rank a long list without ever outranking evidence
(a verified secret, an error message already present in the response).
"""

import re
from dataclasses import dataclass
from typing import Dict, List, Tuple
from urllib.parse import parse_qsl, unquote, urlsplit


@dataclass(frozen=True)
class TriageTag:
    name: str       # e.g. "open-redirect"
    kind: str       # "param" | "path" | "file" | "value"
    evidence: str   # the param name / path segment / extension that matched
    weight: int     # points contributed to the fused score (before capping)


def _names(s: str) -> frozenset:
    return frozenset(x.strip() for x in s.split(",") if x.strip())


# --- parameter-name classes (lowercased exact names) ---
_PARAM_CLASSES: Dict[str, Tuple[frozenset, int]] = {
    "open-redirect": (_names(
        "redirect,redirect_to,redirect_uri,redirect_url,redir,return,return_to,returnto,return_url,"
        "returnurl,next,continue,goto,dest,destination,rurl,forward,forward_url,callback_url,back,"
        "checkout_url,success_url,failure_url,target_url,out,jump,link"), 6),
    "ssrf": (_names(
        "url,uri,src,source,proxy,fetch,feed,host,hostname,domain,site,webhook,webhook_url,"
        "callback,image,image_url,img,img_url,load,remote,reference,endpoint,api_url,dest_url,"
        "path_url,resource,pdf_url,avatar_url"), 6),
    "lfi-path-traversal": (_names(
        "file,filename,filepath,file_path,path,page,include,inc,template,tpl,doc,document,folder,"
        "root,dir,directory,download,view,content,conf,config,layout,load,read,lang,language,locale,style,pg"), 6),
    "idor-candidate": (_names(
        "id,uid,user_id,userid,account,account_id,accountid,order,order_id,orderid,invoice,invoice_id,"
        "doc_id,docid,profile,profile_id,customer,customer_id,member,member_id,uuid,ticket,ticket_id,"
        "report,report_id,project,project_id,org,org_id,employee,employee_id,booking,booking_id"), 5),
    "sqli-candidate": (_names(
        "id,cat,category,category_id,item,item_id,product,product_id,pid,cid,sid,sort,sortby,sort_by,"
        "orderby,order_by,dir,column,col,field,where,filter,select,limit,offset,table,row,year,month,news,article,article_id"), 4),
    "xss-reflection": (_names(
        "q,s,search,query,keyword,keywords,term,lang,name,message,msg,comment,text,title,desc,description,"
        "error,err,errmsg,subject,body,value,input,html,data,label,preview"), 3),
    "command-injection": (_names(
        "cmd,command,exec,execute,run,shell,system,eval,ping,process,daemon,jump,code,payload,module,func,function,do,action_cmd"), 6),
    "debug-toggle": (_names("debug,test,testing,dev,verbose,trace,admin,is_admin,isadmin,role,internal,staging,env,mode,show_errors"), 5),
}

# Credentials passed in the query string end up in logs, history, Referer
# headers and search indexes -- and the fact this URL was *indexed* means they
# are already public. Worth more than a mere shape match.
_SECRET_PARAMS = _names(
    "access_token,accesstoken,token,auth_token,authtoken,id_token,refresh_token,api_key,apikey,api-key,key,"
    "secret,client_secret,password,passwd,pwd,pass,session,sessionid,session_id,sid,jwt,auth,authorization,"
    "signature,sig,x-amz-signature,x-amz-security-token,sas,sv")
_SECRET_MIN_LEN = 12

# --- path segments ---
_PATH_RULES: List[Tuple[str, re.Pattern, int]] = [
    ("admin-panel", re.compile(r"(?:^|/)(?:admin|administrator|wp-admin|manage|manager|management|backoffice|cpanel|"
                                r"phpmyadmin|adminer|console|dashboard|panel|siteadmin|webadmin|controlpanel)(?:/|$|\.)", re.I), 8),
    ("login-portal", re.compile(r"(?:^|/)(?:login|signin|sign-in|sso|auth|oauth|saml|logon)(?:/|$|\.)", re.I), 3),
    ("debug-endpoint", re.compile(r"(?:^|/)(?:debug|trace|phpinfo(?:\.php)?|server-status|server-info|actuator|"
                                   r"heapdump|jolokia|metrics|health|status|_profiler|_debug|elmah\.axd|telescope|horizon)(?:/|$|\.)", re.I), 10),
    ("api-docs", re.compile(r"(?:^|/)(?:swagger(?:-ui)?|api-docs|openapi(?:\.json|\.yaml)?|graphql|graphiql|"
                             r"playground|redoc|v[0-9]/api-docs)(?:/|$|\.)", re.I), 7),
    ("dev-staging", re.compile(r"(?:^|/)(?:dev|test|tests|staging|stage|uat|qa|sandbox|internal|private|old|backup|beta)(?:/|$)", re.I), 4),
    ("vcs-or-config-dir", re.compile(r"(?:^|/)\.(?:git|svn|hg|env|aws|ssh|docker|npmrc|htpasswd|htaccess|DS_Store)(?:/|$|\b)", re.I), 12),
    ("upload-endpoint", re.compile(r"(?:^|/)(?:upload|uploads|file-upload|fileupload|uploader|import)(?:/|$|\.)", re.I), 5),
    ("cgi-script", re.compile(r"(?:^|/)cgi-bin(?:/|$)", re.I), 4),
]

# --- file extensions that are rarely meant to be public ---
_SENSITIVE_EXT = {
    "bak": 10, "old": 8, "orig": 8, "backup": 10, "swp": 9, "sql": 12, "dump": 10, "db": 9, "sqlite": 10,
    "sqlite3": 10, "mdb": 9, "env": 12, "ini": 6, "conf": 7, "cfg": 7, "config": 7, "yml": 4, "yaml": 4,
    "log": 7, "pem": 12, "key": 12, "p12": 12, "pfx": 12, "kdbx": 12, "ppk": 12, "crt": 3, "tfstate": 12,
    "tfvars": 11, "zip": 6, "tar": 6, "gz": 5, "tgz": 6, "rar": 6, "7z": 6, "war": 6, "jar": 3,
    "csv": 3, "xls": 3, "xlsx": 3, "htpasswd": 12, "passwd": 12, "properties": 6,
}
_DOUBLE_EXT = re.compile(r"\.(?:tar\.gz|tar\.bz2|sql\.gz|sql\.zip|bak\.zip)$", re.I)

_TRAVERSAL_VALUE = re.compile(r"(?:\.\./|\.\.\\|/etc/(?:passwd|shadow|hosts)|c:\\windows|boot\.ini|file://|php://|WEB-INF)", re.I)
_URLISH_VALUE = re.compile(r"^(?:https?:)?//|^[a-z0-9.-]+\.[a-z]{2,}(?:[/:?]|$)", re.I)
_NUMERIC = re.compile(r"^\d{1,12}$")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)

MAX_TRIAGE_POINTS = 15


def triage_url(url: str) -> List[TriageTag]:
    """Return tags for one URL, strongest first. Never raises on bad input."""
    try:
        parts = urlsplit(url)
        params = parse_qsl(parts.query, keep_blank_values=True)
    except ValueError:
        return []
    path = unquote(parts.path or "")
    tags: List[TriageTag] = []
    seen = set()

    def add(name, kind, evidence, weight):
        key = (name, evidence.lower())
        if key not in seen:
            seen.add(key)
            tags.append(TriageTag(name, kind, evidence, weight))

    # Parameters ---------------------------------------------------------
    for pname, pvalue in params:
        lname = pname.lower()
        for tag, (names, weight) in _PARAM_CLASSES.items():
            if lname not in names:
                continue
            # Value-aware tightening: shape alone is weak, shape + a plausible value is better.
            if tag == "idor-candidate" and not (_NUMERIC.match(pvalue) or _UUID.match(pvalue)):
                continue
            if tag == "sqli-candidate" and lname in ("id", "cat", "category", "category_id", "item", "item_id",
                                                      "product", "product_id", "pid", "cid", "sid", "news",
                                                      "article", "article_id", "year", "month") and not _NUMERIC.match(pvalue):
                continue
            if tag in ("xss-reflection", "debug-toggle") and pvalue == "":
                weight = max(1, weight - 2)
            if tag == "open-redirect" and _URLISH_VALUE.match(pvalue):
                weight += 3   # already carries a destination: the classic exploitable shape
            if tag == "ssrf" and _URLISH_VALUE.match(pvalue):
                weight += 3
            add(tag, "param", lname, weight)
        if lname in _SECRET_PARAMS and len(pvalue) >= _SECRET_MIN_LEN and not _looks_templated(pvalue):
            add("secret-in-url", "param", lname, 15)
        if _TRAVERSAL_VALUE.search(unquote(pvalue)):
            add("traversal-payload-present", "value", lname, 8)

    # Path segments --------------------------------------------------------
    for name, rx, weight in _PATH_RULES:
        m = rx.search(path)
        if m:
            add(name, "path", m.group(0).strip("/."), weight)

    # Extensions -----------------------------------------------------------
    last = path.rsplit("/", 1)[-1]
    if _DOUBLE_EXT.search(last):
        add("sensitive-file", "file", _DOUBLE_EXT.search(last).group(0).lower(), 10)
    elif "." in last:
        ext = last.rsplit(".", 1)[1].lower()
        if ext in _SENSITIVE_EXT:
            add("sensitive-file", "file", "." + ext, _SENSITIVE_EXT[ext])
    if last.lower() in ("web.config", "wp-config.php", "config.php", "settings.py", "database.yml", "credentials",
                        "id_rsa", "id_dsa", "docker-compose.yml", ".env", "phpinfo.php", "composer.lock", "package-lock.json"):
        add("sensitive-file", "file", last.lower(), 10)
    if re.search(r"(?:^|/)wp-config\.php(?:\.|~|$)", path, re.I) and last.lower() != "wp-config.php":
        add("sensitive-file", "file", last.lower(), 12)  # wp-config.php.bak / .txt / ~

    tags.sort(key=lambda t: (-t.weight, t.name, t.evidence))
    return tags


def _looks_templated(value: str) -> bool:
    return any(t in value for t in ("${", "{{", "<", "%s")) or value.lower() in ("undefined", "null", "none", "redacted")


def triage_points(tags: List[TriageTag]) -> int:
    """Score contribution: strongest tag in full, each extra distinct tag name
    adds a little, hard-capped so triage can rank but never outrank evidence."""
    if not tags:
        return 0
    first, *rest = tags
    distinct_rest = {t.name for t in rest} - {first.name}
    return min(first.weight + 2 * len(distinct_rest), MAX_TRIAGE_POINTS)
