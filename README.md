# Smallstep RADIUS Authentication Webhook Example

> This feature is available to [Smallstep Enterprise RADIUS](https://smallstep.com/product/wifi/) customers.

A minimal Go implementation and reference for building webhook endpoints that participate in Smallstep Enterprise RADIUS EAP‑TLS authentication flows.

This is an example implementation and is not intended for production use.
For reference, see [our RADIUS webhook documentation](https://smallstep.com/docs/tutorials/wifi-authentication-webhooks/).

With RADIUS authentication webhooks, you can integrate Smallstep’s RADIUS workflow with your own device posture or authorization checks during EAP‑TLS connection requests. Your webhook evaluates the presented client certificate and returns an allow/deny decision.

## How it works

1. A client attempts EAP‑TLS authentication to Smallstep RADIUS.
2. After certificate verification, Smallstep invokes your configured webhook(s) with a JSON payload that includes the client certificate and metadata.
3. Your webhook server returns an allow/deny decision.
4. Smallstep enforces the decision. Timeouts or non‑200 responses are treated as deny.

Multiple webhooks are supported and are called sequentially with no guaranteed order.

