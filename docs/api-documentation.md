# API documentation

Interactive documentation is served by FastAPI at:

- http://127.0.0.1:8000/docs
- http://127.0.0.1:8000/redoc

The base path is `/api/v1`. Errors use `{"detail": "..."}`. Validation errors from FastAPI use status 422. The service does not return stack traces.

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/health` | Database and TShark status. HTTP 200 when the database is up. `status` is `degraded` if TShark is missing. |
| POST | `/uploads` | Multipart field `file`. Returns 201 and a queued analysis. Rejects bad extensions (400), bad magic (400), empty files (400), and oversized files (413). |
| GET | `/analyses` | Paginated analyses. Optional `status` and `q`. |
| GET | `/analyses/{id}` | One analysis, including summary and rule snapshot when present. |
| POST | `/analyses/{id}/run` | Clears previous results and queues the capture again. 409 if it is already processing. |
| GET | `/analyses/{id}/summary` | Summary for a completed analysis. 409 otherwise. |
| GET | `/analyses/{id}/hosts` | Host, pair, and port rankings from the summary. |
| GET | `/analyses/{id}/packets` | Paginated packet metadata. Filters: `protocol`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `q`, `numbers`. |
| GET | `/analyses/{id}/alerts` | Alerts for one analysis. 404 if the analysis does not exist. |
| GET | `/alerts` | Alerts across analyses. Filters: `analysis_id`, `severity`, `rule_key`, `q`. Sort: `severity`, `id`, `rule_name`, `window_start`. |
| GET | `/alerts/{id}` | One alert plus up to 100 supporting packets. |
| GET | `/rules` | Current rules and their parameter schema. |
| PATCH | `/rules/{id}` | Update `enabled`, `severity`, and/or `parameters`. Unknown or out-of-range parameters return 422. |
| GET | `/analyses/{id}/report?format=json` | JSON attachment for a completed analysis. |
| GET | `/analyses/{id}/report?format=csv` | CSV attachment for a completed analysis. |
| GET | `/overview` | Dashboard aggregate. Optional `analysis_id`. |

Pagination uses `page` (starting at 1) and `page_size` (1–100). Responses include `total`, `page`, `page_size`, and `pages`.

## Report contents

Both formats include the capture metadata, protocol and host statistics, the rule snapshot with thresholds, and each alert's observed value, threshold, explanation, and packet numbers. They also include the disclaimer that an empty alert list is not a safety certification.

Reports return 409 until status is `completed`, and 404 when the analysis id does not exist.

## Status values

`queued`, `processing`, `completed`, `failed`.

Uploading a valid file returns `queued` immediately. The background task is responsible for the later transition. Clients must read the analysis again before showing results.
