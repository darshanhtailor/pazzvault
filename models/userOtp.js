const mongoose = require('mongoose')

const userOtpSchema = new mongoose.Schema({
    otp: String,
    createdAt: Date,
    expiresAt: Date,
    owner:{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    }
})

const UserOtp = mongoose.model('UserOtp', userOtpSchema)
module.exports = UserOtp