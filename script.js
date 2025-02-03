document.addEventListener("DOMContentLoaded", function () {
    gsap.registerPlugin(ScrollTrigger);
  
    // Animate sections when they appear in viewport
    gsap.from(".cyber-security-section .image-container img", {
      opacity: 0,
      x: -100,
      duration: 1,
      scrollTrigger: {
        trigger: ".cyber-security-section",
        start: "top 80%",
        toggleActions: "play none none none",
      },
    });
  
    gsap.from(".cyber-security-section .text-container", {
      opacity: 0,
      x: 100,
      duration: 2,
      scrollTrigger: {
        trigger: ".cyber-security-section",
        start: "top 80%",
        toggleActions: "play none none none",
      },
    });
  
    gsap.from(".okk .text-container", {
      opacity: 0,
      x: -100,
      duration: 2,
      scrollTrigger: {
        trigger: ".okk",
        start: "top 80%",
        toggleActions: "play none none none",
      },
    });
  
    gsap.from(".okk .image-container img", {
      opacity: 0,
      x: 100,
      duration: 1,
      scrollTrigger: {
        trigger: ".okk",
        start: "top 80%",
        toggleActions: "play none none none",
      },
    });
  });

  function filterSearch() {
    let input = document.getElementById("search").value.toLowerCase();
    let resultsDiv = document.getElementById("results");
    let items = document.querySelectorAll("#searchItems li");

    resultsDiv.innerHTML = "";
    let count = 0;

    items.forEach(item => {
        if (item.innerText.toLowerCase().includes(input) && input.length > 0) {
            let div = document.createElement("div");
            div.innerText = item.innerText;
            div.onclick = () => {
                document.getElementById("search").value = item.innerText;
                resultsDiv.style.display = "none";
            };
            resultsDiv.appendChild(div);
            count++;
        }
    });

    resultsDiv.style.display = count > 0 ? "block" : "none";
}