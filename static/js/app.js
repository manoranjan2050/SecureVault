document.addEventListener("click", async (event) => {
    // Copy to clipboard with toast feedback
    const copyButton = event.target.closest("[data-copy]");
    if (copyButton) {
        const text = copyButton.dataset.copy || "";
        await navigator.clipboard.writeText(text);
        
        // Visual feedback on the button
        const originalIcon = copyButton.innerHTML;
        copyButton.innerHTML = '<i class="fa-solid fa-check text-green-500"></i>';
        setTimeout(() => {
            copyButton.innerHTML = originalIcon;
        }, 1500);
    }

    // Reveal/Hide Secret Logic
    const revealButton = event.target.closest("[data-reveal]");
    if (revealButton) {
        const container = revealButton.closest("div, .secret-line");
        const input = container.querySelector("input[type='password'], input[type='text']");
        const icon = revealButton.querySelector("i");
        
        if (input.type === "password") {
            input.type = "text";
            if(icon) icon.className = "fa-solid fa-eye-slash text-sm";
        } else {
            input.type = "password";
            if(icon) icon.className = "fa-solid fa-eye text-sm";
        }
    }

    // Password Generation
    const generator = event.target.closest("[data-generate-password]");
    if (generator) {
        const field = document.querySelector("#passwordField");
        if(field) {
            field.value = generatePassword(24);
            field.focus();
            updateStrength(field);
        }
    }
});

// Confirmation Dialogs
document.querySelectorAll("form[data-confirm]").forEach((form) => {
    form.addEventListener("submit", (event) => {
        if (!confirm(form.dataset.confirm)) {
            event.preventDefault();
        }
    });
});

// Password Strength Logic
function updateStrength(input) {
    const meter = document.querySelector("[data-strength-meter] div");
    const label = document.querySelector("[data-strength-label]");
    const icon = document.querySelector("[data-strength-icon]");
    if (!meter || !label) return;

    const password = input.value || "";
    let score = 0;
    if (password.length >= 12) score += 1;
    if (/[a-z]/.test(password)) score += 1;
    if (/[A-Z]/.test(password)) score += 1;
    if (/[0-9]/.test(password)) score += 1;
    if (/[^A-Za-z0-9]/.test(password)) score += 1;

    const states = [
        ["0%", "bg-slate-800", "Critical Vulnerability", "fa-shield-xmark", "text-red-500"],
        ["25%", "bg-red-500", "Weak Encryption", "fa-shield-slash", "text-red-400"],
        ["45%", "bg-orange-500", "Fair Protection", "fa-shield-halved", "text-orange-400"],
        ["65%", "bg-yellow-500", "Secure Key", "fa-shield", "text-yellow-400"],
        ["82%", "bg-blue-500", "High Security", "fa-shield-heart", "text-blue-400"],
        ["100%", "bg-green-500", "Elite Protection", "fa-shield-check", "text-green-500"],
    ];
    
    const [width, color, text, iconClass, textColor] = states[score];
    meter.style.width = width;
    meter.className = `h-full transition-all duration-500 ${color}`;
    label.textContent = text;
    label.className = `text-[10px] font-black uppercase tracking-tighter ${textColor}`;
    if(icon) icon.className = `fa-solid ${iconClass} ${textColor}`;
}

document.querySelectorAll("[data-strength-input]").forEach((input) => {
    input.addEventListener("input", () => updateStrength(input));
    updateStrength(input);
});

function generatePassword(length) {
    const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*_-+=";
    const values = new Uint32Array(length);
    crypto.getRandomValues(values);
    return Array.from(values, (value) => chars[value % chars.length]).join("");
}

// Real-time TOTP Countdown Logic
function initTotpTimers() {
    const timers = document.querySelectorAll("[data-totp-timer]");
    if (timers.length === 0) return;

    setInterval(() => {
        let needsReload = false;
        timers.forEach(timer => {
            let seconds = parseInt(timer.dataset.seconds);
            const period = parseInt(timer.dataset.period);
            const circle = timer.querySelector("circle[id^='progress-']");
            const label = timer.querySelector(".countdown-label");

            seconds--;

            if (seconds < 0) {
                needsReload = true;
                seconds = period;
            }

            // Update data attribute
            timer.dataset.seconds = seconds;

            // Update Label
            if (label) label.textContent = `${seconds}s`;

            // Update SVG Circle (Dashoffset math)
            if (circle) {
                const circumference = 113.1;
                const offset = circumference * (1 - seconds / period);
                circle.style.strokeDashoffset = offset;
                
                // Color transition for urgency
                if (seconds <= 5) circle.classList.replace("text-purple-500", "text-red-500");
                else circle.classList.replace("text-red-500", "text-purple-500");
            }
        });

        // If any timer reaches 0, reload to get fresh cryptographic codes
        if (needsReload) {
            window.location.reload();
        }
    }, 1000);
}

// Initialize on load
initTotpTimers();


