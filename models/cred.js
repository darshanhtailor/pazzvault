const mongoose = require('mongoose')

const Cred = mongoose.model('Cred', {
    website:{
        type: String,
    },
    username:{
        type: String,
        required: true
    },
    password:{
        type: String,
        required: true
    },
    owner:{
        type: mongoose.Schema.Types.ObjectId,
        required: true,
        ref: 'User'
    }
})

module.exports = Cred