document.addEventListener("DOMContentLoaded", function () {
    const cards = document.querySelectorAll(".service-card");

    cards.forEach((card, index) => {
        setTimeout(() => {
            card.style.opacity = "1";
            card.style.transform = "translateY(0)";
        }, index * 300); // Delay for staggered animation
    });
});