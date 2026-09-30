## relgate — ✅ **PASS**

Target: `http://localhost:8000`

### Load

| metric | value |
|---|---|
| requests | 1493 |
| error rate | 0.00% |
| throughput | 299 req/s |
| p50 | 2ms |
| p95 | 4ms |
| p99 | 6ms |

### Security

| severity | finding | path |
|---|---|---|
| medium | missing Content-Security-Policy | `/` |
| medium | missing Content-Security-Policy | `/health` |
| medium | missing Content-Security-Policy | `/docs` |
| low | missing Referrer-Policy | `/` |
| low | missing Referrer-Policy | `/health` |
| low | missing Referrer-Policy | `/docs` |
| low | missing X-Content-Type-Options | `/` |
| low | missing X-Content-Type-Options | `/health` |
| low | missing X-Content-Type-Options | `/docs` |
| low | missing X-Frame-Options | `/` |
| low | missing X-Frame-Options | `/health` |
| low | missing X-Frame-Options | `/docs` |

<sub>relgate runs only against hosts listed in its config.</sub>
