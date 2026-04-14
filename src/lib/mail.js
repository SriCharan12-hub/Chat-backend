import nodemailer from "nodemailer";
import dotenv from "dotenv";
console.log("hello")
dotenv.config();

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS ? process.env.EMAIL_PASS.replace(/\s+/g, "") : "", // Remove spaces from App Password
  },
});
console.log(transporter)

transporter.verify(function (error, success) {
  if (error) {
    console.log("Transporter verification error:", error);
  } else {
    console.log("Server is ready to take our messages");
  }
});

export const sendVerificationEmail = async (email, otp) => {
  try {
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Verify your email",
      html: `
                <h1>Email Verification</h1>
                <p>Your verification code is:</p>
                <h2>${otp}</h2>
                <p>This code will expire in 10 minutes.</p>
            `,
    };

    await transporter.sendMail(mailOptions);
    console.log(`Verification email sent to ${email}`);
  } catch (error) {
    console.log("Error sending email", error);
    throw new Error("Error sending verification email");
  }
};
export const sendMFAMail = async (email, otp) => {
  try {
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: "MFA Verification Code",
      html: `
                <h1>MFA Verification</h1>
                <p>Your login verification code is:</p>
                <h2>${otp}</h2>
                <p>This code will expire in 10 minutes.</p>
            `,
    };

    await transporter.sendMail(mailOptions);
    console.log(`MFA email sent to ${email}`);
  } catch (error) {
    console.log("Error sending MFA email", error);
    throw new Error("Error sending MFA email");
  }
};
