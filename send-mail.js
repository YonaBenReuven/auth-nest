"use strict";
const nodemailer = require("nodemailer");


let transporter = nodemailer.createTransport({
    service: 'gmail',
    host: 'smtp.gmail.com',
    port: 465,
    secure: true, // true for 465, false for other ports
    "auth": {
        "user": "lalala",
        "pass": "lalal"
    }
});

transporter.send = transporter.sendMail;
module.exports.mailer = transporter;
