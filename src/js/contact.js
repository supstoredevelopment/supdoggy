window.sendMail = function () {
    const params = {
        name: document.getElementById("name").value,
        email: document.getElementById("email").value,
        subject: document.getElementById("subject").value,
        title: document.getElementById("subject").value,
        message: document.getElementById("message").value,
    };

    return emailjs.send(
        "service_0vbieb1",
        "template_jcj4ako",
        params
    );
};
