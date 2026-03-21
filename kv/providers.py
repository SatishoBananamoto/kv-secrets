"""API provider registry for kv.

Maps provider names to base URLs, auth patterns, and required secret keys.
Used by the kv agent daemon to inject credentials into HTTP requests
without exposing them to the AI agent.
"""


# Auth types:
#   "bearer"  → Authorization: Bearer <key>
#   "x-api-key" → x-api-key: <key>  (Anthropic's pattern)
#   "query"   → ?key=<key> appended to URL
#   "basic"   → Authorization: Basic base64(user:key)

PROVIDERS = {
    "openai": {
        "base_url": "https://api.openai.com",
        "secret_name": "OPENAI_API_KEY",
        "auth_type": "bearer",
        "default_headers": {
            "Content-Type": "application/json",
        },
    },
    "anthropic": {
        "base_url": "https://api.anthropic.com",
        "secret_name": "ANTHROPIC_API_KEY",
        "auth_type": "x-api-key",
        "default_headers": {
            "Content-Type": "application/json",
            "anthropic-version": "2023-06-01",
        },
    },
    "google": {
        "base_url": "https://generativelanguage.googleapis.com",
        "secret_name": "GOOGLE_API_KEY",
        "auth_type": "query",
        "auth_query_param": "key",
        "default_headers": {
            "Content-Type": "application/json",
        },
    },
    "github": {
        "base_url": "https://api.github.com",
        "secret_name": "GITHUB_TOKEN",
        "auth_type": "bearer",
        "default_headers": {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    },
    "google-cloud": {
        "base_url": "https://www.googleapis.com",
        "secret_name": "GOOGLE_CLOUD_API_KEY",
        "auth_type": "query",
        "auth_query_param": "key",
        "default_headers": {
            "Content-Type": "application/json",
        },
    },
}


def get_provider(name):
    """Get provider config by name. Returns None if unknown."""
    return PROVIDERS.get(name)


def list_providers():
    """List all registered provider names."""
    return sorted(PROVIDERS.keys())


def build_auth(provider_config, secret_value):
    """Build auth headers and query params for a provider.

    Returns (headers_dict, query_params_dict).
    """
    headers = dict(provider_config.get("default_headers", {}))
    query_params = {}

    auth_type = provider_config["auth_type"]

    if auth_type == "bearer":
        headers["Authorization"] = f"Bearer {secret_value}"
    elif auth_type == "x-api-key":
        headers["x-api-key"] = secret_value
    elif auth_type == "query":
        param_name = provider_config.get("auth_query_param", "key")
        query_params[param_name] = secret_value
    elif auth_type == "basic":
        import base64
        encoded = base64.b64encode(f":{secret_value}".encode()).decode()
        headers["Authorization"] = f"Basic {encoded}"

    return headers, query_params


def build_url(provider_config, path, query_params=None):
    """Build the full URL for an API call.

    Combines base_url + path + any query parameters.
    """
    url = provider_config["base_url"].rstrip("/") + "/" + path.lstrip("/")

    if query_params:
        from urllib.parse import urlencode
        separator = "&" if "?" in url else "?"
        url = url + separator + urlencode(query_params)

    return url
