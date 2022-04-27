const nodemailer = require('nodemailer')
const bcrypt = require('bcrypt')
const UserOtp = require('../models/userOtp')
require('dotenv').config({ path: '../.env' })

const sendOTPEmail = async(_id, email, res)=>{
    try{
        const otp = `${Math.floor(Math.random()*9000 + 1000)}`
        // const testAccount = await nodemailer.createTestAccount()
        
        let transporter = nodemailer.createTransport({
            host: process.env.NODEMAILER_HOST,
            port: 587,
            secure: false,
            auth: {
                user: process.env.NODEMAILER_EMAIL, 
                pass: process.env.NODEMAILER_PASSWORD
            },
        })
        

        const mailOptions = {
            from: process.env.NODEMAILER_EMAIL,
            to: email,
            subject: "Secure Vault OTP",
            html: `<p>Your Secure Vault OTP is <b>${otp}</b></p><p>Valid for <b>10 mins</b></p>`
        }
        const hashedOTP = await bcrypt.hash(otp, 10)

        const userOtp = new UserOtp({
            otp: hashedOTP,
            createdAt: Date.now(),
            expiresAt: Date.now() + 600000,
            owner: _id
        })

        await userOtp.save()
        await transporter.sendMail(mailOptions)
        
        res.status(200).send({
            message: "OTP sent",
            data:{
                email,
            }
        })
    } catch(e){
        console.log(e.message)
        res.status(500).send(e)
    }
}

module.exports = sendOTPEmail