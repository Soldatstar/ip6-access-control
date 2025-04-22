# DEALER (Supervisor) zu ROUTER (UserTool)

## Startup Request vom Supervisor an User Tool
```json
{
    "type": "read_db",
    "body": {
    	"program": "/home/user/file-access"
    }
}
```

## Request für abgefangene Syscalls ohne bestehende Policy
```json
{
   "type":"req_decision",
   "body":{
      "program":"/home/user/file-access",
      "syscall_id":123,
      "parameter":"some_parameter"
   }
}
```

## Reply vom ROUTER an DEALER
Reply enthält entweder ALLOW/DENY oder die bestehende Policy für `read_db`.

```json
{
    "status": "success",  // für Fehlerbehandlung, falls Request nicht verstanden wurde sollte "error" gesendet werden, evtl. im data eine Message?
    "data": { "decision" : "ALLOW" }            // Response data (if any)
}
```
policy reply
```json
{
   "status":"success",
   "data":{
      "rules":{
         "allowed_syscalls":[
            [
               123,
               "some_parameter"
            ]
         ],
         "denied_syscalls":[
            
         ]
      }
   }
}
```