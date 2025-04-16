# DEALER (Supervisor) zu ROUTER (UserTool)

## Startup Request vom Supervisor an User Tool
```json
{
    "type": "read_db",
    "body": {}
}
```

## Request für abgefangene Syscalls ohne bestehende Policy
```json
{
    "type": "req_decision",
    "body": {
        "syscall_id": 123,
        "parameter": "some_parameter"
    }
}
```

## Reply vom ROUTER an DEALER
Reply enthält entweder ALLOW/DENY oder die bestehende Policy für `read_db`.

```json
{
    "status": "success",  // für Fehlerbehandlung, falls Request nicht verstanden wurde sollte "error" gesendet werden, evtl. im data eine Message?
    "data": {}            // Response data (if any)
}
```

