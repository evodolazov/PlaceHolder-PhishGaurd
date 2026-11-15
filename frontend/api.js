const API_BASE_URL = "";

const ANALYSIS_PATH = "/api/v1/analyze/url";

async function requestJSON(path, options = {}) {
  let response;
  try {
    response = await fetch(`${API_BASE_URL}${path}`, {
      ...options,
      headers: {
        Accept: "application/json",
        ...options.headers
      }
    });
  } catch {
    throw new Error(
      "Cannot connect to Flask. Check that the backend is running."
    );
  }

  const contentType = response.headers.get("content-type") || "";
  let data = null;

  if (contentType.includes("application/json")) {
    data = await response.json();
  } else {
    const body = await response.text();
    data = body ? { message: body } : {};
  }

  if (!response.ok) {
    throw new Error(
      data.message ||
      data.error ||
      `API request failed with status ${response.status}`
    );
  }

  return data;
}

export async function analyzeURL(url) {
  return requestJSON(ANALYSIS_PATH, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ url })
  });
}

export async function checkAPIHealth() {
  return requestJSON("/api/v1/health");
}
