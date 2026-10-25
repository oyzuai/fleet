package poolserver

import (
 "crypto/ed25519"
 "crypto/subtle"
 "net/http"
 "net/url"
 "sort"
 "strconv"
 "strings"
 "time"

 "github.com/oyzuai/fleet/assertion"
 "github.com/oyzuai/fleet/runnerclient"
)
func(s *Server)runner(w http.ResponseWriter,r *http.Request){
 if r.Method!="POST"{problem(w,405,"REQUEST_INVALID","Use POST.");return}
 route:=strings.TrimPrefix(r.URL.Path,"/runner/v1/")
 switch route{case "job/id-token","job/egress","job/secrets","job/write-token":problem(w,404,"REQUEST_INVALID","Route not implemented by this pool.");return}
 if strings.HasPrefix(route,"job/kind/")||(strings.HasPrefix(route,"readiness/")&&route!="readiness/session"){problem(w,404,"REQUEST_INVALID","Route not implemented by this pool.");return}
 if route=="enroll"{s.enroll(w,r);return};if route=="token"||route=="keys"{s.assertionRoute(w,r,route);return}
 s.mu.Lock();defer s.mu.Unlock();if s.expire()!=nil{problem(w,503,"SERVICE_UNAVAILABLE","State storage is unavailable.");return}
 tok:=bearer(r);if tok==""{problem(w,401,"UNAUTHENTICATED","Credential refused.");return};digest:=hash([]byte(tok))
 if strings.HasPrefix(route,"job/"){s.jobRoute(w,r,route,digest);return}
 access,ok:=s.state.Meta.Access[digest];if !ok||!s.now().Before(access.Expires){problem(w,401,"UNAUTHENTICATED","Manager credential refused.");return}
 d:=s.state.clone();m:=d.Meta.Managers[access.Manager];if m==nil{problem(w,401,"UNAUTHENTICATED","Manager credential refused.");return}
 switch route{
 case "readiness/session":respond(w,200,map[string]any{"session":"","enabled":false})
 case "report":var report runnerclient.Report;if !parseBody(w,r,&report){return};if len(report.Facts)>32||report.Slots.Max<0||report.Slots.Max>100000||report.Slots.Running<0||report.Slots.Ready<0||report.Slots.Provisioning<0{problem(w,400,"REQUEST_INVALID","Invalid manager report.");return};m.Report=report;if s.persist(w,d){respond(w,200,map[string]bool{"ok":true})}
 case "demand":n:=0;for _,j:=range d.Jobs{if j.State=="queued"{n++}};respond(w,200,runnerclient.Demand{Eligible:n,Ready:n})
 case "claim":
  jobs:=[]*jobRecord{};for _,j:=range d.Jobs{if j.State=="queued"{jobs=append(jobs,j)}};sort.Slice(jobs,func(i,j int)bool{return jobs[i].Job.ID<jobs[j].Job.ID});if len(jobs)==0{w.WriteHeader(204);return};j:=jobs[0];j.Job.Attempt++;j.State="claimed";j.Manager=m.ID;startup:=randomToken();j.StartupHash=hash([]byte(startup));j.StartupExpires=s.now().Add(5*time.Minute);rr:=d.Runs[jobRunID(d,j)];rr.Run.Attempt=j.Job.Attempt
  allow:=append([]runnerclient.EgressAllow{},s.cfg.EgressAllow...);u,_:=url.Parse(s.cfg.PublicURL);port:=443;if u.Port()!=""{port,_=strconv.Atoi(u.Port())};allow=append(allow,runnerclient.EgressAllow{Host:u.Hostname(),Port:port})
  if s.persist(w,d){respond(w,200,runnerclient.Claim{JobID:j.Job.ID,Attempt:j.Job.Attempt,StartupToken:startup,StartupExpires:j.StartupExpires,Egress:runnerclient.ClaimEgress{Allow:allow}})}
 case "release":var in runnerclient.Release;if !parseBody(w,r,&in){return};j:=d.Jobs[in.JobID];released:=j!=nil&&j.Manager==m.ID&&j.State=="claimed"&&j.Job.Attempt==in.Attempt;if released{j.State="queued";j.Manager=0;j.StartupHash="";j.Job.Attempt--;d.Runs[jobRunID(d,j)].Run.Attempt=j.Job.Attempt;if !s.persist(w,d){return}};respond(w,200,map[string]bool{"released":released})
 default:problem(w,404,"REQUEST_INVALID","Route not found.")
 }
}
func(s *Server)enroll(w http.ResponseWriter,r *http.Request){
 var in struct{Token string `json:"token"`;Name string `json:"name"`;PublicKey string `json:"public_key"`};if !parseBody(w,r,&in){return};pub,e:=assertion.DecodeKey(in.PublicKey);if e!=nil||in.Name==""||len(in.Name)>100{problem(w,400,"REQUEST_INVALID","Invalid enrollment.");return}
 s.mu.Lock();defer s.mu.Unlock();h:=hash([]byte(in.Token));if s.state.Meta.EnrollmentSpent||subtle.ConstantTimeCompare([]byte(h),[]byte(s.cfg.EnrollmentTokenSHA256))!=1{problem(w,401,"UNAUTHENTICATED","Enrollment credential refused.");return}
 d:=s.state.clone();d.Meta.NextID++;d.Meta.NextKey++;id,kid:=d.Meta.NextID,d.Meta.NextKey;d.Meta.EnrollmentSpent=true;d.Meta.Managers[id]=&managerRecord{ID:id,Name:in.Name,Keys:map[int64]ed25519.PublicKey{kid:pub}}
 if s.persist(w,d){respond(w,200,runnerclient.Enrolled{ManagerID:id,KeyID:kid,Pool:s.cfg.Account,Name:in.Name})}
}
func(s *Server)assertionRoute(w http.ResponseWriter,r *http.Request,route string){
 var token string
 if route=="token"{r.Body=http.MaxBytesReader(w,r.Body,16<<10);if r.ParseForm()!=nil||r.PostForm.Get("grant_type")!="client_credentials"||r.PostForm.Get("client_assertion_type")!="urn:ietf:params:oauth:client-assertion-type:jwt-bearer"{problem(w,400,"REQUEST_INVALID","Invalid private_key_jwt request.");return};token=r.PostForm.Get("client_assertion")}else{var in struct{Assertion string `json:"assertion"`};if !parseBody(w,r,&in){return};token=in.Assertion}
 p,e:=assertion.Parse(token);if e!=nil{problem(w,401,"UNAUTHENTICATED","Assertion refused.");return};id,e:=p.Manager();if e!=nil{problem(w,401,"UNAUTHENTICATED","Assertion refused.");return}
 s.mu.Lock();defer s.mu.Unlock();if s.expire()!=nil{problem(w,503,"SERVICE_UNAVAILABLE","State storage is unavailable.");return};m:=s.state.Meta.Managers[id];typ:=assertion.TypeLogin;if route=="keys"{typ=assertion.TypeRotation};jti:=strconv.FormatInt(id,10)+":"+p.Claims.ID
 if m==nil||p.Verify(m.Keys[p.KeyID],typ,s.cfg.Audience,s.now())!=nil{problem(w,401,"UNAUTHENTICATED","Assertion refused.");return};if _,used:=s.state.Meta.Assertions[jti];used{problem(w,401,"UNAUTHENTICATED","Assertion already used.");return}
 d:=s.state.clone();d.Meta.Assertions[jti]=p.Expires();m=d.Meta.Managers[id]
 if route=="keys"{pub,e:=assertion.DecodeKey(p.Claims.NewKey);if e!=nil{problem(w,400,"REQUEST_INVALID","Invalid new public key.");return};if len(m.Keys)>=2{problem(w,409,"KEY_LIMIT","Two keys are already active.");return};d.Meta.NextKey++;m.Keys[d.Meta.NextKey]=pub;if s.persist(w,d){respond(w,200,map[string]int64{"key_id":d.Meta.NextKey})};return}
 // The new key's first login retires its predecessor; already-issued access
 // tokens keep their original bounded lifetime.
 for keyID:=range m.Keys{if keyID<p.KeyID{delete(m.Keys,keyID)}}
 access:=randomToken();d.Meta.Access[hash([]byte(access))]=accessRecord{Manager:id,Expires:s.now().Add(10*time.Minute)};if s.persist(w,d){respond(w,200,map[string]any{"access_token":access,"token_type":"Bearer","expires_in":600})}
}
func(s *Server)jobRoute(w http.ResponseWriter,r *http.Request,route,digest string){
 d:=s.state.clone();var j *jobRecord;for _,candidate:=range d.Jobs{if (route=="job/start"&&candidate.StartupHash==digest)||(route!="job/start"&&candidate.TokenHash==digest){j=candidate;break}}
 if j==nil{problem(w,401,"UNAUTHENTICATED","Job credential refused.");return};rr:=d.Runs[jobRunID(d,j)];now:=s.now()
 if route=="job/start"{
  if j.State!="claimed"||!now.Before(j.StartupExpires)||rr.Run.State!="queued"{problem(w,401,"UNAUTHENTICATED","Startup credential refused.");return};var assignment runnerclient.StartupAssignment;if !parseBody(w,r,&assignment){return};if assignment.Readiness!=nil||assignment.ExecutionTrustDecision!=""{problem(w,400,"REQUEST_INVALID","Unexpected assignment metadata.");return}
  token:=randomToken();j.TokenHash=hash([]byte(token));j.StartupHash="";j.State="running";j.Lease=now.Add(2*time.Minute);rr.Run.State="running";rr.Run.StartedAt=&now
  if s.persist(w,d){respond(w,200,runnerclient.Started{JobToken:token,Expires:j.Lease,HeartbeatSeconds:30,Job:j.Job})};return
 }
 logs:=route=="job/logs"||route=="job/logs/finish";live:=j.State=="running"&&now.Before(j.Lease);draining:=finished(rr.Run)&&now.Before(j.DrainUntil)
 if !live&&!(logs&&draining){problem(w,401,"UNAUTHENTICATED","Job credential expired.");return}
 switch route{
 case "job/heartbeat":j.Lease=now.Add(2*time.Minute);if s.persist(w,d){respond(w,200,map[string]any{"expires_at":j.Lease,"cancel":rr.Run.CancelRequestedAt!=nil})}
 case "job/source":
  // Release the state lock while reaching GitHub, then re-check the lease.
  s.mu.Unlock();source,e:=s.source.Source(r.Context(),j.Job.Repository);s.mu.Lock()
  current:=s.state.Jobs[j.Job.ID];if current==nil||current.TokenHash!=digest||current.State!="running"||!s.now().Before(current.Lease){problem(w,401,"UNAUTHENTICATED","Job credential expired.");return};if e!=nil{problem(w,503,"SERVICE_UNAVAILABLE","Source credential unavailable.");return};respond(w,200,source)
 case "job/finish":var outcome runnerclient.Outcome;if !parseBody(w,r,&outcome){return};if !contains([]string{"succeeded","failed","cancelled","timed_out"},outcome.State)||len(outcome.Plan)>0||len(outcome.Outputs)>1000||len(outcome.Summary)>64<<10{problem(w,400,"REQUEST_INVALID","Invalid job outcome.");return}
  if rr.Run.CancelRequestedAt!=nil&&outcome.State!="cancelled"{problem(w,409,"CANCEL_REQUESTED","Cancellation must be confirmed by the executor.");return}
  for _,o:=range outcome.Outputs{if !validOutput(o){problem(w,400,"REQUEST_INVALID","Invalid output metadata.");return}}
  j.State=outcome.State;j.DrainUntil=now.Add(15*time.Minute);j.Outputs=outcome.Outputs;rr.Run.State=outcome.State;rr.Run.ExitCode=outcome.ExitCode;rr.Run.FinishedAt=&now
  if outcome.ReasonCode!=""{rr.Run.Reason=&Reason{Code:outcome.ReasonCode,Message:outcome.Summary}}else if outcome.State=="cancelled"{rr.Run.Reason=&Reason{Code:"CANCELLED_BY_USER",Message:"Cancelled by the caller."}}
  if s.persist(w,d){respond(w,200,map[string]bool{"ok":true})}
 case "job/logs":s.uploadLogs(w,r,d,j)
 case "job/logs/finish":s.finishLogs(w,r,d,j)
 default:problem(w,404,"REQUEST_INVALID","Route not found.")
 }
}
func validOutput(o runnerclient.Output)bool{return o.Path!=""&&len(o.Path)<=1024&&!strings.HasPrefix(o.Path,"/")&&!strings.Contains(o.Path,"\\")&&!contains(strings.Split(o.Path,"/"),"..")&&contains([]string{"manifest","report","artifact"},o.Kind)&&o.Size>=0&&strings.HasPrefix(o.Digest,"sha256:")&&hashRE.MatchString(strings.TrimPrefix(o.Digest,"sha256:"))&&len(o.MediaType)<=255}
