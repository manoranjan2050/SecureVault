document.addEventListener("click", async (event) => {
    const sidebarToggle = event.target.closest("[data-sidebar-toggle]");
    if (sidebarToggle) {
        document.querySelector("#sidebar")?.classList.toggle("open");
    }

    const copyButton = event.target.closest("[data-copy]");
    if (copyButton) {
        await navigator.clipboard.writeText(copyButton.dataset.copy || "");
        const oldText = copyButton.textContent;
        copyButton.textContent = "Copied";
        setTimeout(() => {
            copyButton.textContent = oldText;
        }, 1200);
    }

    const revealButton = event.target.closest("[data-reveal]");
    if (revealButton) {
        const input = revealButton.parentElement.querySelector(".secret-input");
        input.type = input.type === "password" ? "text" : "password";
        revealButton.textContent = input.type === "password" ? "Show" : "Hide";
    }

    const generator = event.target.closest("[data-generate-password]");
    if (generator) {
        const field = document.querySelector("#passwordField");
        field.value = generatePassword(22);
        field.focus();
        updateStrength(field);
    }
});

document.querySelectorAll("form[data-confirm]").forEach((form) => {
    form.addEventListener("submit", (event) => {
        if (!confirm(form.dataset.confirm)) {
            event.preventDefault();
        }
    });
});

setTimeout(() => {
    document.querySelectorAll(".flash").forEach((flash) => {
        flash.style.opacity = "0";
        flash.style.transform = "translateY(-8px)";
        setTimeout(() => flash.remove(), 220);
    });
}, 3200);

function generatePassword(length) {
    const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*_-+=";
    const values = new Uint32Array(length);
    crypto.getRandomValues(values);
    return Array.from(values, (value) => chars[value % chars.length]).join("");
}

document.querySelectorAll("[data-strength-input]").forEach((input) => {
    input.addEventListener("input", () => updateStrength(input));
    updateStrength(input);
});

function updateStrength(input) {
    const meter = document.querySelector("[data-strength-meter] span");
    const label = document.querySelector("[data-strength-label]");
    if (!meter || !label) {
        return;
    }
    const password = input.value || "";
    let score = 0;
    if (password.length >= 12) score += 1;
    if (/[a-z]/.test(password)) score += 1;
    if (/[A-Z]/.test(password)) score += 1;
    if (/[0-9]/.test(password)) score += 1;
    if (/[^A-Za-z0-9]/.test(password)) score += 1;

    const states = [
        ["0%", "#ff6b7a", "Password strength will appear here."],
        ["25%", "#ff6b7a", "Weak password"],
        ["45%", "#f6c85f", "Fair password"],
        ["65%", "#f6c85f", "Good password"],
        ["82%", "#26d9b5", "Strong password"],
        ["100%", "#26d9b5", "Excellent password"],
    ];
    const [width, color, text] = states[score];
    meter.style.width = width;
    meter.style.background = color;
    label.textContent = text;
}

if (document.querySelector(".otp-card")) {
    setTimeout(() => {
        window.location.reload();
    }, 30000);
}
