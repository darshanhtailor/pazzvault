// if (process.env.NODE_ENV !== 'production') {
// 	require('dotenv').config()
// }
const express = require('express')
const app = express()
const bcrypt = require('bcrypt')
const cryptojs = require('crypto-js')
const passport = require('passport')
const flash = require('express-flash')
const session = require('express-session')
const methodOverride = require('method-override')
const path = require('path')
const cookieParser = require('cookie-parser') //--> added
const mongoose = require('mongoose')
const User = require('./models/user')
const Cred = require('./models/cred')
const sendOTPEmail = require('./src/sendOtp')
const UserOtp = require('./models/userOtp')
require('dotenv').config({ path: './.env' })

const mongoURI = process.env.DB_URL
mongoose.connect(mongoURI)

const initializePassport = require('./passport-config')
// initializePassport(passport, email => users.find(user => user.email === email), id => users.find(user => user.id === id))
initializePassport(passport, email => User.findOne({ email }), user_id => User.findOne({ user_id }))
// const users = []

app.set('view-engine', 'ejs')

app.use(express.json()) //-->added
app.use(express.urlencoded({ extended: false }))
app.use(flash())

app.use(session({
	secret: process.env.SESSION_KEY,
	resave: false,
	saveUninitialized: false
}))
app.use(passport.initialize())
app.use(passport.session())
app.use(methodOverride('_method'))

const publicDir = path.join(__dirname, '/public')
app.use(express.static(publicDir))

app.get('/', checkAuthenticated, (req, res) => {
	res.render('index.ejs', { name: req.user.name })
})

app.get('/login', checkNotAuthenticated, (req, res) => {
	res.render('login.ejs')
})

app.post('/login', checkNotAuthenticated, passport.authenticate('local', {
	successRedirect: '/',
	failureRedirect: '/login',
	failureFlash: true
}))

app.get('/register', checkNotAuthenticated, (req, res) => {
	res.render('register.ejs')
})

app.post('/register', checkNotAuthenticated, async (req, res) => {
	try {
		const hashedPassword = await bcrypt.hash(req.body.password, 10)
		const user = new User({ 
			user_id: Date.now().toString(),
			name: req.body.name, 
			email: req.body.email, 
			password: hashedPassword
		})
		await user.save()
		res.redirect('/login')
	} catch {
		res.redirect('/register')
	}
})

app.delete('/logout', (req, res) => {
	res.setHeader('Set-Cookie', `[vault=${null}; expires=Thu, 01 Jan 1970 00:00:00 GMT]`)
	req.logOut()
	res.redirect('/login')
})

app.get('/profile', checkAuthenticated, (req, res)=>{
	res.render('profile.ejs', {name: req.user.name})
})

app.get('/profile/addcred', checkAuthenticated, (req, res)=>{
	res.render('addcredpage.ejs', {name: req.user.name})
})

app.post('/addcred', checkAuthenticated, async(req, res)=>{
	console.log()
	try{
		const cred = new Cred({
			website: req.body.website,
			username: req.body.username,
			password: cryptojs.AES.encrypt(req.body.password, process.env.PASS_PHRASE).toString(),
			owner: req.user._id
		})
		await cred.save()
		res.redirect('/profile')
	} catch(e){
		res.status(500).send(e)
	}
})

app.get('/profile/getcreds', checkAuthenticated, async(req, res)=>{
	try{
		let userCreds = await Cred.find({ owner: req.user._id })
		userCreds.forEach(userCred => { userCred.password = cryptojs.AES.decrypt(userCred.password, process.env.PASS_PHRASE).toString(cryptojs.enc.Utf8) })
		res.send(userCreds)
	} catch(e){
		res.status(500).send(e)
	}
})

app.get('/generatepass', checkAuthenticated, async(req, res)=>{
	res.render('generatePass.ejs', { name:req.user.name })
})

app.get('/vault', checkAuthenticated, async(req, res)=>{
	res.render('vault.ejs', {name: req.user.name})
})

app.get('/vault/access', checkAuthenticated, async(req, res)=>{
	res.render('vaultAccess.ejs', {name: req.user.name})
})

app.post('/sendmail', checkAuthenticated, async(req, res)=>{
	sendOTPEmail(req.user._id, req.user.email, res)
})

app.post('/verifyotp', checkAuthenticated, async(req, res)=>{
	try{
		const otps = await UserOtp.find({ owner: req.user._id })
		let hashedotp
		otps.forEach(async(otp)=>{
			if((Date.now() > otp.expiresAt) || hashedotp){
				await UserOtp.deleteOne({ _id: otp._id })
			} else{
				hashedotp = otp
			}
		})
		if(!hashedotp){
			res.status(404).send('Please request OTP again.')
		}
		const match = await bcrypt.compare(req.body.otp, hashedotp.otp)

		if(!match){
			res.send('Wrong OTP. Please try again.')
		} else{
			await UserOtp.deleteOne({ _id: hashedotp._id})
			res.setHeader('Set-Cookie', [`vault=accessgiven.${Date.now().toString()}`])
			res.redirect('/vault/access')
		}
		
	} catch(e){
		console.log(e.message)
		res.status(500).send(e)
	}
})

app.get('/breach', checkAuthenticated, async(req, res)=>{
	res.render('breach.ejs', { name: req.user.name })
})

function checkAuthenticated(req, res, next) {
	if (req.isAuthenticated()) {
		return next()
	}
	res.redirect('/login')
}

function checkNotAuthenticated(req, res, next) {
	if (req.isAuthenticated()) {
		return res.redirect('/')
	}
	next()
}

app.listen(3000, () => {
	console.log('server started at port 3000')
})