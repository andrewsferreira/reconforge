# HTTP Collection Pipeline (Burp Provider)

## Overview

ReconForge now includes a structured HTTP collection pipeline that consumes Burp provider outputs and emits normalized internal observations.

Pipeline components:

1. `reconforge.collectors.http_collector.HttpCollector`
2. `reconforge.normalizers.http.HttpObservationNormalizer`
3. `reconforge.normalizers.http.HTTPObservation`

This design keeps provider transport/details isolated while exposing stable internal data for analytics/reporting.

## Model structure

`HTTPObservation` fields:

- `target_url`, `scheme`, `host`, `port`
- `method`, `path`, `query`
- `request_headers`, `request_body`
- `response_status`, `response_headers`, `response_body`, `response_length`
- `timestamp`
- `source_tool`, `source_provider`
- `evidence_id`
- `raw_reference`

## Collection flows

### Request collection

`collect_request(target_url, http_version="http1")`:

- calls Burp `send_http1_request` or `send_http2_request`
- relies on provider-level scope validation (deny-first, malformed blocked)
- normalizes first returned record into `HTTPObservation`
- emits structured logs for start/success/empty results

### Proxy history collection

`collect_proxy_history(regex=None)`:

- calls `get_proxy_http_history` or `get_proxy_http_history_regex`
- normalizes each returned record
- skips malformed entries safely with warning logs
- returns `list[HTTPObservation]`

## Evidence handling

Each normalized observation gets an `evidence_id` (`<provider>:<tool>:<uuid>`), enabling traceable linkage into future evidence pipelines.

## Summary output

`HttpCollector.summarize(observations)` returns:

- total observations
- unique hosts
- status code distribution
- response size stats (min/max/avg)

## Scope and safety

Request-capable operations are still enforced by Burp provider scope controls before execution. The collector does not bypass or duplicate that enforcement.

## Example usage

See `examples/http_collection.py`.

## Extending to other providers

To support another provider, map provider records into `HttpObservationNormalizer.normalize(...)` input format and reuse `HTTPObservation` as the shared internal schema.

## Limitations

- Body normalization currently stores bytes as base64-prefixed text (`base64:<...>`).
- Timestamp extraction uses provider timestamp if present, otherwise UTC now.
- Current collector is Burp-backed; future providers can reuse the same normalizer and observation schema.
