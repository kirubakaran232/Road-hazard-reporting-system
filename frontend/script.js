document.addEventListener("DOMContentLoaded", async () => {
    let userEmail = localStorage.getItem("userEmail");

    if (!userEmail) {
        alert("You need to log in first.");
        window.location.href = "login.html";
        return;
    }

    userEmail = userEmail.toLowerCase();  // Convert to lowercase

    try {
        const response = await fetch(`http://localhost:5000/profile/${encodeURIComponent(userEmail)}`);
        const user = await response.json();

        if (response.ok) {
            document.getElementById("userName").innerText = user.full_name;
            document.getElementById("userEmail").innerText = user.email;
            document.getElementById("userPhone").innerText = user.phone_number;
        } else {
            alert(user.error || "Error fetching profile");
            window.location.href = "login.html";
        }
    } catch (error) {
        alert("An error occurred while fetching the profile.");
        console.error(error);
    }
});
