// Detect login forms and autofill
document.addEventListener("DOMContentLoaded", () => {
    const usernameField = document.querySelector("input[type='text'], input[type='email']");
    const passwordField = document.querySelector("input[type='password']");
  
    if (usernameField && passwordField) {
      // Fetch saved credentials from the Flask API
      fetch("https://your-flask-api-domain/get_credentials", {
        method: "GET",
        headers: {
          "Authorization": `Bearer ${localStorage.getItem("authToken")}`
        }
      })
        .then(response => response.json())
        .then(data => {
          usernameField.value = data.username;
          passwordField.value = data.password;
        })
        .catch(err => console.error("Failed to fetch credentials:", err));
    }
  });
  