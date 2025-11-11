# Search Manager

Minimal wrapper for Elasticsearch/OpenSearch queries.

## Setup

Create `~/.search-manager/config.json` with your cluster details:

```json
{
  "servers": [
    {
      "name": "local-es",
      "host": "localhost:9200",
      "protocol": "http"
    },
    {
      "name": "prod-os",
      "host": "opensearch.example.com:9200",
      "protocol": "https"
    }
  ]
}
```

Install:

```bash
pip install -e .
```

## Usage

```bash
search cluster health              # uses first server (default)
search --target prod-os cat indices
```
