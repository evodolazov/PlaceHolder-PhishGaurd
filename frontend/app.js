import { analyzeURL } from "./api.js";

const form = document.getElementById("scan-form");
const input = document.getElementById("url-input");
const button = document.getElementById("scan-button");
const message = document.getElementById("message");
const results = document.getElementById("results");

form.addEventListener("submit", async (event) => {
  event.preventDefault();

  const url = input.value.trim();

  if (!url) {
    message.textContent = "Enter a URL to analyze.";
    return;
  }

  button.disabled = true;
  button.textContent = "Analyzing...";
  message.textContent = "Sending URL to PhishGuard...";
  results.classList.add("hidden");

  try {
    const data = await analyzeURL(url);
    // Temporary view:
    results.classList.remove("hidden");

    let output = document.getElementById("api-response");

    if (!output) {
      output = document.createElement("pre");
      output.id = "api-response";
      output.style.whiteSpace = "pre-wrap";
      output.style.overflowWrap = "anywhere";
      results.appendChild(output);
    }

    output.textContent = JSON.stringify(data, null, 2);
    message.textContent = "Analysis completed successfully.";

    results.scrollIntoView({
      behavior: "smooth",
      block: "start"
    });
  } catch (error) {
    message.textContent = error.message;
  } finally {
    button.disabled = false;
    button.textContent = "Analyze URL";
  }
});
